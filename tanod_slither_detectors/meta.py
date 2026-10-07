"""Static metadata for the custom detectors (no Slither import).

``impact`` and ``confidence`` use Slither's vocabulary (high/medium/low); the
report maps them to a report severity with ``scanner.report.map_severity``.
"""

from __future__ import annotations

CUSTOM_DETECTORS: dict[str, dict[str, str]] = {
    "erc20-unsafe-transfer": {
        "title": "ERC20 transfer/transferFrom/approve called without SafeERC20",
        "impact": "high",
        "confidence": "medium",
        "explanation": (
            "The contract calls transfer, transferFrom or approve directly on an ERC20 token "
            "instead of going through SafeERC20 (or an equivalent low-level wrapper). When the "
            "boolean return value is ignored, a token that signals failure by returning false "
            "(rather than reverting) lets the call 'succeed' silently, so balances are credited "
            "for tokens that never moved. When the return value is checked through the "
            "interface, tokens that return nothing at all (USDT, BNB, OMG and others) make the "
            "ABI decoder revert, so every call fails and funds can be locked. Severity is high "
            "when the return value is ignored and medium when it is checked."
        ),
        "recommendation": (
            "Use OpenZeppelin SafeERC20 (safeTransfer, safeTransferFrom, forceApprove) or "
            "Solady SafeTransferLib for every interaction with an arbitrary ERC20 token."
        ),
    },
    "amm-spot-price": {
        "title": "Spot price read from AMM reserves or slot0",
        "impact": "high",
        "confidence": "low",
        "explanation": (
            "The contract reads the instantaneous state of an AMM pool (Uniswap V2 style "
            "getReserves() or Uniswap V3 style slot0()) and can use it as a price. The spot "
            "price of a pool can be moved arbitrarily within a single transaction using a "
            "flash loan or a large swap, so any valuation, collateral check, mint/redeem ratio "
            "or liquidation threshold derived from it can be manipulated and the protocol "
            "drained. This is one of the most frequent root causes of DeFi exploits and of "
            "high-severity audit-contest findings. Confidence is low because reading reserves "
            "is legitimate for quoting swaps that are themselves slippage-protected."
        ),
        "recommendation": (
            "Price assets with a manipulation-resistant source: a Chainlink (or similar) "
            "oracle with staleness checks, or a Uniswap V3 TWAP over a sufficiently long "
            "window. Never use getReserves()/slot0() for valuation."
        ),
    },
    "swap-zero-min-out": {
        "title": "Swap or liquidation call with minimum output hard-coded to 0",
        "impact": "high",
        "confidence": "medium",
        "explanation": (
            "A call into a DEX router or pool passes the literal 0 as its minimum-output "
            "(slippage) argument, for example amountOutMin, amountOutMinimum, minAmountOut or "
            "min_dy. Without a slippage bound the swap accepts any price, so an MEV searcher "
            "can sandwich the transaction: move the price before it, let the contract swap at a "
            "terrible rate, and move it back afterwards, extracting most of the value. Calls "
            "that run automatically (harvests, compounding, liquidations, rebalances) are "
            "particularly exposed because anyone can trigger them at a chosen moment."
        ),
        "recommendation": (
            "Accept a caller-supplied minimum output, or derive one from a trusted oracle "
            "price minus a bounded slippage tolerance, and pass it to the swap."
        ),
    },
    "swap-deadline": {
        "title": "Swap deadline set to block.timestamp (no effective deadline)",
        "impact": "low",
        "confidence": "high",
        "explanation": (
            "A router call receives block.timestamp (or a value derived from it, or "
            "type(uint256).max) as its deadline parameter. The deadline is checked against "
            "block.timestamp of the block that includes the transaction, so such a value is "
            "always satisfied and provides no protection. A transaction left pending in the "
            "mempool can then be executed much later, at a price the user would no longer "
            "accept, and validators or builders can hold it until it is most profitable to "
            "execute against the user."
        ),
        "recommendation": (
            "Let the caller supply the deadline as a function argument computed off-chain, and "
            "pass it through to the router unchanged."
        ),
    },
    "unsafe-downcast": {
        "title": "Unchecked downcast of a user-influenced value",
        "impact": "medium",
        "confidence": "medium",
        "explanation": (
            "An integer derived from a function argument (or msg.value) is converted to a "
            "smaller integer type, such as uint256 to uint128 or uint64, with an explicit cast "
            "and no prior range check. Explicit conversions are never checked, not even with "
            "Solidity 0.8's checked arithmetic: values that do not fit are silently truncated "
            "to their low-order bits. An attacker who controls the input can make stored "
            "amounts, timestamps or accounting values wrap to small numbers, breaking "
            "invariants such as 'shares minted match assets deposited'."
        ),
        "recommendation": (
            "Use OpenZeppelin SafeCast (toUint128, toUint64, ...) or require that the value "
            "is at most type(uintN).max before casting."
        ),
    },
    "erc4626-inflation": {
        "title": "ERC4626-style vault without virtual shares (first-depositor inflation)",
        "impact": "high",
        "confidence": "medium",
        "explanation": (
            "The vault converts assets to shares with a plain ratio of totalSupply to "
            "totalAssets(), where totalAssets() comes from the vault's token balance, and has "
            "no virtual shares, virtual assets or decimals offset. The first depositor can mint "
            "1 wei of shares and then donate a large amount of the asset directly to the vault, "
            "inflating the share price so that later deposits round down to zero (or very few) "
            "shares; the attacker then redeems and captures the victims' deposits. This is the "
            "classic ERC4626 inflation (donation) attack."
        ),
        "recommendation": (
            "Use OpenZeppelin ERC4626 v4.9+ (virtual shares and assets via _decimalsOffset), "
            "add a virtual offset to the conversion math, track deposited assets internally "
            "instead of using balanceOf, or seed the vault with dead shares at deployment."
        ),
    },
    "ecrecover-zero-address": {
        "title": "ecrecover result not checked against address(0)",
        "impact": "medium",
        "confidence": "medium",
        "explanation": (
            "The address returned by ecrecover is used without checking that it is non-zero. "
            "ecrecover returns address(0) for an invalid signature instead of reverting. If the "
            "recovered address is compared with a signer, owner or mapping entry that is unset "
            "or can be zero (an uninitialised signer, a deleted role, an unregistered user), an "
            "arbitrary invalid signature passes verification. The raw precompile also accepts "
            "malleable (high-s) signatures."
        ),
        "recommendation": (
            "Use OpenZeppelin ECDSA.recover (which rejects zero addresses and malleable "
            "signatures), or explicitly require(recovered != address(0))."
        ),
    },
    "signature-replay": {
        "title": "Signature verification without nonce or chain id (replay)",
        "impact": "high",
        "confidence": "low",
        "explanation": (
            "A public function verifies a signature, but the code path neither consumes a nonce "
            "or marks the signature/digest as used, nor binds the signed message to the chain "
            "(block.chainid or an EIP-712 domain separator). Without a nonce the same "
            "signature can be submitted again to repeat the authorised action (claims, "
            "withdrawals, mints); without a chain id a signature produced for one network is "
            "valid on every other network or fork where the contract is deployed at the same "
            "address. The detector reports which of the two protections it could not find."
        ),
        "recommendation": (
            "Sign EIP-712 typed data with a domain separator that includes chainId and "
            "verifyingContract, and include a per-signer nonce (or record used digests) that is "
            "consumed on every successful verification."
        ),
    },
    "chainlink-stale-price": {
        "title": "Chainlink latestRoundData without staleness or answer validation",
        "impact": "medium",
        "confidence": "medium",
        "explanation": (
            "The contract calls latestRoundData() on a Chainlink-style aggregator but does not "
            "check that updatedAt is recent (against block.timestamp and the feed's heartbeat), "
            "and/or does not check that the returned answer is positive. During oracle outages, "
            "network congestion or feed deprecation the call keeps returning the last (stale) "
            "price or zero, and the protocol then values collateral, mints or liquidates at a "
            "wrong price."
        ),
        "recommendation": (
            "Require answer > 0 and block.timestamp - updatedAt <= heartbeat for that feed; on "
            "L2s also check the sequencer uptime feed. Revert or fall back to a secondary "
            "oracle when the checks fail."
        ),
    },
}

# Stock Slither detectors that report the same root cause at the same location as a
# custom detector. When both fire on the same file:line, only the custom one is kept.
ALIASES: dict[str, frozenset[str]] = {
    "erc20-unsafe-transfer": frozenset({"unchecked-transfer", "unused-return"}),
    "chainlink-stale-price": frozenset({"unused-return"}),
    "swap-zero-min-out": frozenset({"unused-return"}),
    "swap-deadline": frozenset({"unused-return"}),
    "amm-spot-price": frozenset({"unused-return"}),
    "ecrecover-zero-address": frozenset(),
    "signature-replay": frozenset(),
    "unsafe-downcast": frozenset(),
    "erc4626-inflation": frozenset(),
}
