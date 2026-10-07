"""Custom Slither detectors for recurring audit-contest bug classes.

Titles, explanations and recommendations live in ``meta.py``.

All analysis here is intra-procedural over SlithIR, with a few one-level
caller/callee look-ups. The detectors favour precision on the common shapes of
each bug over completeness.
"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Any, Iterable

from slither.core.declarations import Contract, Function
from slither.core.expressions import Literal
from slither.core.declarations.solidity_variables import (
    SolidityVariable,
    SolidityVariableComposed,
)
from slither.core.solidity_types import ElementaryType, MappingType, UserDefinedType
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.slithir.operations import (
    Assignment,
    Binary,
    BinaryType,
    HighLevelCall,
    Index,
    InternalCall,
    LibraryCall,
    Member,
    NewStructure,
    Return,
    SolidityCall,
    TypeConversion,
    Unary,
    Unpack,
)
from slither.slithir.variables import Constant

from .meta import CUSTOM_DETECTORS

_LEVEL = {
    "high": DetectorClassification.HIGH,
    "medium": DetectorClassification.MEDIUM,
    "low": DetectorClassification.LOW,
}

_COMPARISONS = {
    BinaryType.LESS,
    BinaryType.GREATER,
    BinaryType.LESS_EQUAL,
    BinaryType.GREATER_EQUAL,
    BinaryType.EQUAL,
    BinaryType.NOT_EQUAL,
}
_PROPAGATING = (Assignment, Binary, TypeConversion, Unary, Unpack, Index, Member)
_UINT256_MAX = 2**256 - 1


# --------------------------------------------------------------------------- helpers


def _irs(function: Function) -> Iterable[tuple[Any, Any]]:
    for node in function.nodes:
        for ir in node.irs:
            yield node, ir


def _is_external_call(ir: Any) -> bool:
    return isinstance(ir, HighLevelCall) and not isinstance(ir, LibraryCall)


class _Flow:
    """Def-use edges of one function (lvalue <-> operands of propagating ops)."""

    def __init__(self, function: Function) -> None:
        self.back: dict[Any, set] = defaultdict(set)
        self.fwd: dict[Any, set] = defaultdict(set)
        for _, ir in _irs(function):
            if isinstance(ir, _PROPAGATING) and getattr(ir, "lvalue", None) is not None:
                if isinstance(ir, Unpack):
                    reads = [ir.tuple]
                elif isinstance(ir, (Index, Member)):
                    # m[k] / s.f carries the value stored in m / s: the key k (or the field
                    # name) selects a slot but is not part of the value
                    reads = [ir.variable_left]
                else:
                    reads = list(ir.read)
                for r in reads:
                    self.back[ir.lvalue].add(r)
                    self.fwd[r].add(ir.lvalue)

    @staticmethod
    def _closure(start: Any, edges: dict[Any, set]) -> set:
        seen = {start}
        stack = [start]
        while stack:
            cur = stack.pop()
            for nxt in edges.get(cur, ()):
                if nxt not in seen:
                    seen.add(nxt)
                    stack.append(nxt)
        return seen

    def origins(self, var: Any) -> set:
        """Root values ``var`` is computed from (variables with no incoming edge)."""
        closure = self._closure(var, self.back)
        return {v for v in closure if not self.back.get(v)} or {var}

    def derived(self, var: Any) -> set:
        """``var`` plus every value computed from it."""
        return self._closure(var, self.fwd)


def _const_value(v: Any) -> Any:
    """Value of a literal or of a ``constant`` variable initialised with a literal, else None."""
    if isinstance(v, Constant):
        return v.value
    if getattr(v, "is_constant", False) and isinstance(getattr(v, "expression", None), Literal):
        lit = v.expression
        try:
            return Constant(str(lit.value), lit.type, lit.subdenomination).value
        except Exception:  # noqa: BLE001 - unusual literal: treat as unknown
            return None
    return None


def _is_zero(value: Any, flow: _Flow) -> bool:
    origins = flow.origins(value)
    return all(isinstance(o, Constant) and o.value == 0 for o in origins)


def _derives_from_timestamp(value: Any, flow: _Flow) -> bool:
    for o in flow.origins(value):
        if isinstance(o, SolidityVariable) and o.name in ("block.timestamp", "now"):
            return True
    return False


def _is_max_uint(value: Any, flow: _Flow) -> bool:
    origins = flow.origins(value)
    return bool(origins) and all(isinstance(o, Constant) and o.value == _UINT256_MAX for o in origins)


def _compared(var: Any, function: Function, flow: _Flow) -> bool:
    """True if ``var`` (or a value derived from it) is an operand of a comparison."""
    derived = flow.derived(var)
    for _, ir in _irs(function):
        if isinstance(ir, Binary) and ir.type in _COMPARISONS:
            if ir.variable_left in derived or ir.variable_right in derived:
                return True
    return False


def _passed_to_internal_call(var: Any, function: Function, flow: _Flow) -> bool:
    derived = flow.derived(var)
    for _, ir in _irs(function):
        if isinstance(ir, InternalCall) and any(a in derived for a in ir.arguments):
            return True
    return False


def _param_names(ir: HighLevelCall) -> list[str] | None:
    fn = ir.function
    if isinstance(fn, Function) and len(fn.parameters) == len(ir.arguments):
        return [p.name or "" for p in fn.parameters]
    return None


def _norm(name: str) -> str:
    return (name or "").lower().replace("_", "")


def _called_functions(function: Function) -> list[Function]:
    """``function`` plus every function it reaches through internal and library calls."""
    out: list[Function] = [function]
    for call in list(function.all_internal_calls()) + list(function.all_library_calls()):
        target = getattr(call, "function", call)
        if isinstance(target, Function) and target not in out:
            out.append(target)
    return out


def _call_args_by_name(function: Function) -> Iterable[tuple[Any, Any, str, Any]]:
    """Yield (node, ir, parameter_name, argument) for external calls and for struct
    literals that are passed to an external call in the same function."""
    struct_to_call: set = set()
    for _, ir in _irs(function):
        if _is_external_call(ir):
            struct_to_call.update(ir.arguments)
    for node, ir in _irs(function):
        if _is_external_call(ir):
            names = _param_names(ir)
            if names:
                for name, arg in zip(names, ir.arguments):
                    yield node, ir, name, arg
        elif isinstance(ir, NewStructure) and ir.lvalue in struct_to_call:
            fields = [e.name for e in ir.structure.elems_ordered]
            if len(fields) == len(ir.arguments):
                for name, arg in zip(fields, ir.arguments):
                    yield node, ir, name, arg


def _skip_contract(contract: Contract) -> bool:
    return contract.is_interface


class _CustomDetector(AbstractDetector):
    """Fills Slither's required class attributes from ``meta.CUSTOM_DETECTORS``."""

    KEY = ""

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        m = CUSTOM_DETECTORS[cls.KEY]
        cls.ARGUMENT = cls.KEY
        cls.HELP = m["title"]
        cls.IMPACT = _LEVEL[m["impact"]]
        cls.CONFIDENCE = _LEVEL[m["confidence"]]
        cls.WIKI = "https://github.com/tanod-labs/slither-detectors#" + cls.KEY
        cls.WIKI_TITLE = m["title"]
        cls.WIKI_DESCRIPTION = m["explanation"]
        cls.WIKI_EXPLOIT_SCENARIO = m["explanation"]
        cls.WIKI_RECOMMENDATION = m["recommendation"]

    def _functions(self) -> Iterable[tuple[Contract, Function]]:
        for contract in self.compilation_unit.contracts:
            if _skip_contract(contract):
                continue
            for function in contract.functions_and_modifiers_declared:
                if function.nodes:
                    yield contract, function


# --------------------------------------------------------------------------- detectors

_SAFE_LIB = re.compile(r"(safe|transferhelper|transferlib)", re.I)
_ERC20_ARGC = {"transfer": 2, "transferFrom": 3, "approve": 2}
# Tokens whose transfer/transferFrom/approve revert on failure and return true otherwise, so a
# raw call is safe whether or not the bool is checked: WETH9 (and its interfaces), MakerDAO DAI,
# Lido stETH, and Uniswap V2-style LP tokens. Matched on the (normalised) interface/contract type
# of the call target, or on the name of the variable the target is read from.
_KNOWN_TOKEN_TYPES = re.compile(
    r"^i?(weth\d*|wrappedether|dai|daitoken|dailike|daiabstract|steth|stethtoken|lido"
    r"|uniswapv2pair|uniswapv2erc20|pancakepair|sushiswappair)$")
_KNOWN_TOKEN_VARS = re.compile(r"^(weth\d*|wrappedether|dai|steth)$")


def _known_reverting_token(ir: HighLevelCall, function: Function) -> str | None:
    names = []
    dest_type = getattr(ir.destination, "type", None)
    if isinstance(dest_type, UserDefinedType):
        names.append(("type", str(dest_type.type.name)))
    for origin in _Flow(function).origins(ir.destination) | {ir.destination}:
        t = getattr(origin, "type", None)
        if isinstance(t, UserDefinedType):
            names.append(("type", str(t.type.name)))
        # a variable name is only trusted for a constant/immutable (set once by the deployer);
        # a settable `IERC20 weth` could point anywhere
        if getattr(origin, "name", None) and (getattr(origin, "is_constant", False)
                                              or getattr(origin, "is_immutable", False)):
            names.append(("var", str(origin.name)))
    for kind, name in names:
        pattern = _KNOWN_TOKEN_TYPES if kind == "type" else _KNOWN_TOKEN_VARS
        if pattern.match(_norm(name)):
            return name
    return None


class ERC20UnsafeTransfer(_CustomDetector):
    KEY = "erc20-unsafe-transfer"

    def _detect(self) -> list:
        results = []
        for contract, function in self._functions():
            if contract.is_library and _SAFE_LIB.search(contract.name):
                continue
            for node, ir in _irs(function):
                if not _is_external_call(ir):
                    continue
                name = ir.function_name
                if _ERC20_ARGC.get(str(name)) != len(ir.arguments):
                    continue
                fn = ir.function
                if not isinstance(fn, Function):
                    continue
                if [str(t) for t in fn.return_type or []] != ["bool"]:
                    continue
                # a concrete token implemented in scope (known to revert) is not "arbitrary"
                dest_type = getattr(ir.destination, "type", None)
                if (
                    isinstance(dest_type, UserDefinedType)
                    and isinstance(dest_type.type, Contract)
                    and not dest_type.type.is_interface
                    and fn.is_implemented
                ):
                    continue
                used = ir.lvalue is not None and any(
                    ir.lvalue in other.read for _, other in _irs(function) if other is not ir
                )
                known = _known_reverting_token(ir, function)
                if known:
                    # reported as info (hidden by default) so that it still claims the location
                    # and the stock unchecked-transfer/unused-return result there is dropped
                    severity = "info"
                    info = [function, f" calls raw ERC20 `{name}` on `{known}`, a token known to revert on "
                            "failure (acceptable): ", node, "\n"]
                elif used:
                    severity = "medium"
                    info = [function, f" checks the return value of a raw ERC20 `{name}` "
                            "(reverts for tokens that return nothing, e.g. USDT): ", node, "\n"]
                else:
                    severity = "high"
                    info = [function, f" ignores the return value of ERC20 `{name}`: ", node, "\n"]
                results.append(self.generate_result(info, additional_fields={"severity": severity}))
        return results


_QUOTE_FUNCS = {"getamountout", "getamountsout", "getamountin", "getamountsin", "quote"}
_TWAP_CALLS = {"observe", "observations", "consult", "gettimepoints", "getblockstartingtickandliquidity"}
_MIN_BOUND = re.compile(r"(^min|min$|minimum|^max|max$|limit)")


def _copy_reads(ir: Any) -> list:
    if isinstance(ir, Unpack):
        return [ir.tuple]
    if isinstance(ir, Assignment):
        return [ir.rvalue]
    if isinstance(ir, TypeConversion):
        return [ir.variable]
    return []


def _only_zero_checked(var: Any, function: Function, flow: _Flow) -> bool:
    """True if ``var`` (or a plain copy of it) is only ever compared with 0, i.e. the spot state
    is read just to test whether the pool is initialised, never used as a value."""
    copies = {var}
    changed = True
    while changed:
        changed = False
        for _, ir in _irs(function):
            lv = getattr(ir, "lvalue", None)
            if lv is not None and lv not in copies and any(r in copies for r in _copy_reads(ir)):
                copies.add(lv)
                changed = True
    for _, ir in _irs(function):
        if not any(r in copies for r in getattr(ir, "read", [])):
            continue
        if any(r in copies for r in _copy_reads(ir)):
            continue
        if isinstance(ir, Binary) and ir.type in (BinaryType.EQUAL, BinaryType.NOT_EQUAL):
            other = ir.variable_right if ir.variable_left in copies else ir.variable_left
            if _is_zero(other, flow):
                continue
        return False
    return True


def _spot_derived(var: Any, function: Function) -> set:
    """Values computed from ``var``, also through calls that take such a value as an argument
    (`liquidity = getLiquidityForAmounts(sqrtPrice, ...)`, `(a0, a1) = pool.mint(.., liquidity, ..)`)."""
    derived = {var}
    changed = True
    while changed:
        changed = False
        for _, ir in _irs(function):
            lv = getattr(ir, "lvalue", None)
            if lv is None or lv in derived:
                continue
            if isinstance(ir, Unpack):
                reads = [ir.tuple]
            elif isinstance(ir, (Index, Member)):
                reads = [ir.variable_left]
            elif isinstance(ir, (HighLevelCall, InternalCall, LibraryCall)):
                reads = list(ir.arguments)
            else:
                reads = list(getattr(ir, "read", []))
            if any(r in derived for r in reads):
                derived.add(lv)
                changed = True
    return derived


def _min_bounded(function: Function, flow: _Flow, spot: Any = None) -> bool:
    """True if the function compares a value computed from the spot read with a caller-supplied
    bound (amount0Min, minAmountOut, sqrtPriceLimitX96...): the outcome is then
    slippage-protected by the caller."""
    derived = _spot_derived(spot, function) if spot is not None else None
    bounds = {p for p in function.parameters if _MIN_BOUND.search(_norm(p.name))}
    for _, ir in _irs(function):
        if isinstance(ir, Member) and _MIN_BOUND.search(_norm(str(ir.variable_right))):
            bounds.add(ir.lvalue)
    if not bounds:
        return False
    for _, ir in _irs(function):
        if isinstance(ir, Binary) and ir.type in _COMPARISONS - {BinaryType.EQUAL, BinaryType.NOT_EQUAL}:
            pair = (ir.variable_left, ir.variable_right)
            for bound, value in (pair, pair[::-1]):
                if flow._closure(bound, flow.back) & bounds and (derived is None or value in derived):
                    return True
    return False


def _reads_twap(function: Function) -> bool:
    """The same function also reads a TWAP/observation (to compare the spot state with it)."""
    for _, ir in _irs(function):
        if isinstance(ir, (HighLevelCall, InternalCall)):
            name = ir.function_name if isinstance(ir, HighLevelCall) else getattr(ir.function, "name", "")
            if _norm(str(name)) in _TWAP_CALLS:
                return True
    return False


class AMMSpotPrice(_CustomDetector):
    KEY = "amm-spot-price"

    def _detect(self) -> list:
        results = []
        for contract, function in self._functions():
            if contract.is_library or _norm(function.name) in _QUOTE_FUNCS:
                continue
            # quoter/lens contracts simulate swaps for off-chain callers; they hold no value
            if re.search(r"quoter|lens", contract.name, re.I):
                continue
            own = {f.name for f in contract.functions}
            # reserves read to execute a swap on the same pool (router math) are not a valuation
            if any(_is_external_call(ir) and str(ir.function_name) == "swap" for _, ir in _irs(function)):
                continue
            flow = _Flow(function)
            for node, ir in _irs(function):
                if not _is_external_call(ir):
                    continue
                name = str(ir.function_name)
                if name in ("getReserves", "slot0") and len(ir.arguments) == 0 and name not in own:
                    if ir.lvalue is not None and _only_zero_checked(ir.lvalue, function, flow):
                        continue  # "is the pool initialised?" check, not a price
                    if _reads_twap(function):
                        continue  # compared with a TWAP/observation: a manipulation guard
                    if ir.lvalue is not None and _min_bounded(function, flow, ir.lvalue):
                        continue  # caller-supplied min/limit bounds the outcome
                    info = [function, f" reads the AMM spot state `{name}()`: ", node, "\n"]
                    results.append(self.generate_result(info))
        return results


_MIN_OUT = re.compile(
    r"^(?:(?:min|minimum)(?:amount|amounts)?(?:out|output|return|returnamount|received?|toreceive|dy|buyamount|tokensout)"
    r"|amount[a-z]{0,5}min(?:imum)?"
    r"|minamount)$"
)


class SwapZeroMinOut(_CustomDetector):
    KEY = "swap-zero-min-out"

    def _detect(self) -> list:
        results = []
        for _, function in self._functions():
            flow = _Flow(function)
            for node, ir, pname, arg in _call_args_by_name(function):
                if _MIN_OUT.match(_norm(pname)) and _is_zero(arg, flow):
                    info = [function, f" passes 0 as `{pname}` (no slippage protection): ", node, "\n"]
                    results.append(self.generate_result(info))
        return results


class SwapDeadline(_CustomDetector):
    KEY = "swap-deadline"

    def _detect(self) -> list:
        results = []
        for _, function in self._functions():
            flow = _Flow(function)
            for node, ir, pname, arg in _call_args_by_name(function):
                if "deadline" not in _norm(pname):
                    continue
                if _derives_from_timestamp(arg, flow):
                    what = "block.timestamp"
                elif _is_max_uint(arg, flow):
                    what = "type(uint256).max"
                else:
                    continue
                info = [function, f" passes {what} as `{pname}` (deadline is always met): ", node, "\n"]
                results.append(self.generate_result(info))
        return results


def _int_bits(t: Any) -> int | None:
    if isinstance(t, ElementaryType) and (t.name.startswith("uint") or t.name.startswith("int")):
        try:
            return t.size
        except ValueError:
            return 256
    return None


class UnsafeDowncast(_CustomDetector):
    KEY = "unsafe-downcast"

    def _detect(self) -> list:
        results = []
        for contract, function in self._functions():
            if contract.is_library and "safecast" in contract.name.lower():
                continue
            if function.view or function.pure:
                continue
            flow = _Flow(function)
            params = set(function.parameters)
            for node, ir in _irs(function):
                if not isinstance(ir, TypeConversion) or isinstance(ir.variable, Constant):
                    continue
                to_bits = _int_bits(ir.type)
                from_bits = _int_bits(getattr(ir.variable, "type", None))
                if to_bits is None or from_bits is None or to_bits >= from_bits:
                    continue
                sources = [
                    o for o in flow.origins(ir.variable)
                    if o in params or (isinstance(o, SolidityVariableComposed) and o.name == "msg.value")
                ]
                if not sources or self._range_checked(function, flow, ir.variable, sources, to_bits):
                    continue
                info = [function, f" downcasts a user-influenced value to {ir.type} without a range check: ",
                        node, "\n"]
                results.append(self.generate_result(info))
        return results

    @staticmethod
    def _range_checked(function: Function, flow: _Flow, var: Any, sources: list, bits: int) -> bool:
        tainted: set = set()
        for s in sources:
            tainted |= flow.derived(s)
        tainted |= flow.origins(var) | {var}
        for _, ir in _irs(function):
            if isinstance(ir, Binary) and ir.type in _COMPARISONS - {BinaryType.EQUAL, BinaryType.NOT_EQUAL}:
                left, right = ir.variable_left, ir.variable_right
                for a, b in ((left, right), (right, left)):
                    if a in tainted:
                        bounds = [_const_value(o) for o in flow.origins(b)]
                        if bounds and all(isinstance(c, int) and c <= 2**bits for c in bounds):
                            return True
        return False


_CONVERT_FUNCS = ("convertToShares", "previewDeposit", "_convertToShares")


class ERC4626Inflation(_CustomDetector):
    KEY = "erc4626-inflation"

    def _detect(self) -> list:
        results = []
        for contract in self.compilation_unit.contracts_derived:
            if contract.is_interface or contract.is_library:
                continue
            by_name: dict[str, list[Function]] = defaultdict(list)
            for f in contract.functions:
                if f.nodes:
                    by_name[f.name].append(f)
            if "_decimalsOffset" in by_name:
                continue
            if "totalAssets" not in by_name or not ({"deposit", "mint"} & by_name.keys()):
                continue
            converters = [f for n in _CONVERT_FUNCS for f in by_name.get(n, [])]
            if not converters:
                continue
            if not self._balance_based(by_name["totalAssets"]):
                continue
            if any(self._has_virtual_offset(f) for f in converters):
                continue
            target = converters[0]
            info = [target, " converts assets to shares without virtual shares/offset (vault ", contract,
                    ") while totalAssets() uses the token balance\n"]
            results.append(self.generate_result(info))
        return results

    @staticmethod
    def _balance_based(funcs: list[Function]) -> bool:
        for f in funcs:
            for g in _called_functions(f):
                for _, ir in _irs(g):
                    if _is_external_call(ir) and str(ir.function_name) == "balanceOf":
                        return True
        return False

    @staticmethod
    def _has_virtual_offset(function: Function) -> bool:
        for g in _called_functions(function):
            for _, ir in _irs(g):
                if isinstance(ir, Binary) and ir.type == BinaryType.ADDITION:
                    for operand in (ir.variable_left, ir.variable_right):
                        if isinstance(operand, Constant) and operand.value:
                            return True
                        if getattr(operand, "is_constant", False) or getattr(operand, "is_immutable", False):
                            return True
        return False


def _is_ecrecover(ir: Any) -> bool:
    return isinstance(ir, SolidityCall) and ir.function.name.startswith("ecrecover(")


def _zero_checked(var: Any, function: Function, flow: _Flow) -> bool:
    direct = flow.derived(var)
    # a registry lookup keyed by the recovered address and compared with zero
    # (`owners[recovered] != address(0)`) is a membership check, which covers address(0)
    # as long as address(0) is never registered
    compared = set(direct)
    for _, ir in _irs(function):
        if isinstance(ir, Index) and ir.variable_right in direct and ir.lvalue is not None:
            compared |= flow.derived(ir.lvalue)
    for _, ir in _irs(function):
        if isinstance(ir, Binary) and ir.type in (BinaryType.EQUAL, BinaryType.NOT_EQUAL):
            l, r = ir.variable_left, ir.variable_right
            if (l in compared and _is_zero(r, flow)) or (r in compared and _is_zero(l, flow)):
                return True
        # `recovered > x` (or `x < recovered`) implies recovered != 0 for any x, e.g. Safe's
        # strictly increasing owner order `currentOwner > lastOwner` starting at address(0)
        if isinstance(ir, Binary) and ir.type == BinaryType.GREATER and ir.variable_left in direct:
            return True
        if isinstance(ir, Binary) and ir.type == BinaryType.LESS and ir.variable_right in direct:
            return True
    return False


def _callers(function: Function, all_functions: list[Function]) -> list[tuple[Function, Any]]:
    out = []
    for caller in all_functions:
        for _, ir in _irs(caller):
            if isinstance(ir, InternalCall) and ir.function == function:
                out.append((caller, ir))
    return out


def _param_zero_checked_by_callers(function: Function, param: Any, all_functions: list[Function]) -> bool:
    """True if every internal caller checks the argument it passes for ``param`` against 0."""
    try:
        idx = function.parameters.index(param)
    except ValueError:
        return False
    callers = _callers(function, all_functions)
    if not callers:
        return False
    for caller, ir in callers:
        if idx >= len(ir.arguments):
            return False
        cflow = _Flow(caller)
        arg = ir.arguments[idx]
        if not any(_zero_checked(o, caller, cflow) for o in cflow.origins(arg) | {arg}):
            return False
    return True


def _expected_signer_nonzero(var: Any, function: Function, flow: _Flow, all_functions: list[Function]) -> bool:
    """``recovered == expected`` is safe when ``expected`` is known to be non-zero: checked
    against 0 in this function, or a parameter that every caller checks."""
    derived = flow.derived(var)
    for _, ir in _irs(function):
        if isinstance(ir, Binary) and ir.type in (BinaryType.EQUAL, BinaryType.NOT_EQUAL):
            l, r = ir.variable_left, ir.variable_right
            other = r if l in derived else l if r in derived else None
            if other is None or _is_zero(other, flow):
                continue
            for o in flow.origins(other) | {other}:
                if _zero_checked(o, function, flow):
                    return True
                if o in function.parameters and _param_zero_checked_by_callers(function, o, all_functions):
                    return True
    return False


class EcrecoverZeroAddress(_CustomDetector):
    KEY = "ecrecover-zero-address"

    def _detect(self) -> list:
        results = []
        all_functions = [f for c in self.compilation_unit.contracts for f in c.functions_and_modifiers_declared]
        for _, function in self._functions():
            flow = _Flow(function)
            for node, ir in _irs(function):
                if not _is_ecrecover(ir) or ir.lvalue is None:
                    continue
                if _zero_checked(ir.lvalue, function, flow):
                    continue
                if _expected_signer_nonzero(ir.lvalue, function, flow, all_functions):
                    continue
                if self._returned(ir.lvalue, function, flow) and self._all_callers_check(function, all_functions):
                    continue
                info = [function, " uses the result of ecrecover without checking for address(0): ", node, "\n"]
                results.append(self.generate_result(info))
        return results

    @staticmethod
    def _returned(var: Any, function: Function, flow: _Flow) -> bool:
        derived = flow.derived(var)
        if any(r in derived for r in function.returns):
            return True
        return any(isinstance(ir, Return) and any(v in derived for v in ir.values) for _, ir in _irs(function))

    @staticmethod
    def _all_callers_check(function: Function, all_functions: list[Function]) -> bool:
        callers = _callers(function, all_functions)
        for caller, ir in callers:
            cflow = _Flow(caller)
            if ir.lvalue is None:
                return False
            if not (_zero_checked(ir.lvalue, caller, cflow)
                    or _expected_signer_nonzero(ir.lvalue, caller, cflow, all_functions)):
                return False
        return bool(callers)


_SIG_LIB_CALLS = {"recover", "tryrecover", "isvalidsignaturenow", "isvalidsignaturenowcalldata"}
_USED_MARKERS = ("nonce", "used", "executed", "claimed", "consumed", "processed", "spent", "redeemed",
                 "invalidated", "cancelled", "canceled", "filled", "seen", "replay")
_CHAIN_MARKERS = ("domainseparator", "hashtypeddata", "chainid", "eip712")


def _bool_mapping(t: Any) -> bool:
    if isinstance(t, MappingType):
        inner = t.type_to
        return _bool_mapping(inner) if isinstance(inner, MappingType) else str(inner) == "bool"
    return False


class SignatureReplay(_CustomDetector):
    KEY = "signature-replay"

    def _detect(self) -> list:
        results = []
        for contract in self.compilation_unit.contracts_derived:
            if contract.is_interface or contract.is_library:
                continue
            for entry in contract.functions_entry_points:
                if entry.view or entry.pure or not entry.nodes:
                    continue
                reach = _called_functions(entry)
                site = self._signature_site(reach)
                if site is None:
                    continue
                missing = []
                if not self._has_nonce(reach):
                    missing.append("a nonce / used-signature record")
                if not self._has_chain_binding(reach):
                    missing.append("the chain id / EIP-712 domain separator")
                if missing:
                    info = [entry, " verifies a signature without " + " or ".join(missing) + ": ", site, "\n"]
                    results.append(self.generate_result(info))
        return results

    @staticmethod
    def _signature_site(reach: list[Function]) -> Any:
        for f in reach:
            if f.contract_declarer is not None and f.contract_declarer.is_library:
                continue
            for node, ir in _irs(f):
                if _is_ecrecover(ir):
                    return node
                if isinstance(ir, HighLevelCall) and _norm(str(ir.function_name)) in _SIG_LIB_CALLS:
                    return node
        return None

    @staticmethod
    def _has_nonce(reach: list[Function]) -> bool:
        for f in reach:
            names = [_norm(v.name) for v in f.state_variables_written] + [_norm(f.name)]
            names += [_norm(v.name) for v in f.state_variables_read if "nonce" in _norm(v.name)]
            if any(m in n for n in names for m in _USED_MARKERS):
                return True
            # a written mapping(... => bool) is the usual "digest/nonce already used" record
            if any(_bool_mapping(v.type) for v in f.state_variables_written):
                return True
        return False

    @staticmethod
    def _has_chain_binding(reach: list[Function]) -> bool:
        for f in reach:
            if any(v.name == "block.chainid" for v in f.solidity_variables_read):
                return True
            names = [_norm(v.name) for v in f.state_variables_read] + [_norm(f.name)]
            if any(m in n for n in names for m in _CHAIN_MARKERS):
                return True
            for node in f.nodes:
                asm = node.inline_asm
                if isinstance(asm, str) and "chainid" in asm:
                    return True
                if isinstance(asm, dict) and "chainid" in str(asm):
                    return True
        return False


class ChainlinkStalePrice(_CustomDetector):
    KEY = "chainlink-stale-price"

    def _detect(self) -> list:
        results = []
        for _, function in self._functions():
            flow = _Flow(function)
            for node, ir in _irs(function):
                if not _is_external_call(ir) or str(ir.function_name) != "latestRoundData":
                    continue
                unpacked = {
                    u.index: u.lvalue for _, u in _irs(function)
                    if isinstance(u, Unpack) and ir.lvalue is not None and u.tuple == ir.lvalue
                }
                if ir.lvalue is not None and not unpacked:
                    continue  # tuple forwarded as-is (wrapper); the caller is responsible
                missing = []
                if not self._checked(unpacked.get(3), function, flow):
                    missing.append("staleness (updatedAt)")
                if not self._checked(unpacked.get(1), function, flow):
                    missing.append("answer > 0")
                if missing:
                    info = [function, " calls latestRoundData without checking " + " and ".join(missing) + ": ",
                            node, "\n"]
                    results.append(self.generate_result(info))
        return results

    @staticmethod
    def _checked(var: Any, function: Function, flow: _Flow) -> bool:
        if var is None:
            return False
        return _compared(var, function, flow) or _passed_to_internal_call(var, function, flow)


ALL_CUSTOM_DETECTORS = [
    ERC20UnsafeTransfer,
    AMMSpotPrice,
    SwapZeroMinOut,
    SwapDeadline,
    UnsafeDowncast,
    ERC4626Inflation,
    EcrecoverZeroAddress,
    SignatureReplay,
    ChainlinkStalePrice,
]
