# Tanod Slither detectors

Nine [Slither](https://github.com/crytic/slither) detectors for bug classes that keep
showing up in DeFi audits and exploits, packaged as a Slither plugin. They are the
custom detectors behind [Tanod's contract scan](https://tanod.dev), released under MIT.

All analysis is intra-procedural over SlithIR, with a few one-level caller and callee
look-ups. The detectors favour precision on the common shape of each bug over
completeness: a clean run is not proof that the bug class is absent, and every finding
needs a human (or agent) to confirm it in context.

## Install

```bash
pip install git+https://github.com/tanod-labs/slither-detectors
```

Slither loads installed plugins automatically, so the detectors run alongside the
built-in ones:

```bash
slither path/to/project
slither path/to/project --detect erc20-unsafe-transfer,amm-spot-price,swap-zero-min-out
slither --list-detectors | grep -E "erc20-unsafe-transfer|amm-spot-price|swap-zero-min-out"
```

Requires Python 3.10+ and slither-analyzer 0.10 or newer.

## Detectors

| Detector | Finds | Impact | Confidence |
| --- | --- | --- | --- |
| [`erc20-unsafe-transfer`](#erc20-unsafe-transfer) | ERC20 transfer/transferFrom/approve called without SafeERC20 | high | medium |
| [`amm-spot-price`](#amm-spot-price) | Spot price read from AMM reserves or slot0 | high | low |
| [`swap-zero-min-out`](#swap-zero-min-out) | Swap or liquidation call with minimum output hard-coded to 0 | high | medium |
| [`swap-deadline`](#swap-deadline) | Swap deadline set to block.timestamp (no effective deadline) | low | high |
| [`unsafe-downcast`](#unsafe-downcast) | Unchecked downcast of a user-influenced value | medium | medium |
| [`erc4626-inflation`](#erc4626-inflation) | ERC4626-style vault without virtual shares (first-depositor inflation) | high | medium |
| [`ecrecover-zero-address`](#ecrecover-zero-address) | ecrecover result not checked against address(0) | medium | medium |
| [`signature-replay`](#signature-replay) | Signature verification without nonce or chain id (replay) | high | low |
| [`chainlink-stale-price`](#chainlink-stale-price) | Chainlink latestRoundData without staleness or answer validation | medium | medium |

### erc20-unsafe-transfer

**ERC20 transfer/transferFrom/approve called without SafeERC20.** The contract calls transfer, transferFrom or approve directly on an ERC20 token instead of going through SafeERC20 (or an equivalent low-level wrapper). When the boolean return value is ignored, a token that signals failure by returning false (rather than reverting) lets the call 'succeed' silently, so balances are credited for tokens that never moved. When the return value is checked through the interface, tokens that return nothing at all (USDT, BNB, OMG and others) make the ABI decoder revert, so every call fails and funds can be locked. Severity is high when the return value is ignored and medium when it is checked.

**Fix:** Use OpenZeppelin SafeERC20 (safeTransfer, safeTransferFrom, forceApprove) or Solady SafeTransferLib for every interaction with an arbitrary ERC20 token.

Fixtures: [vulnerable](tests/fixtures/erc20_unsafe_transfer_vulnerable.sol), [fixed](tests/fixtures/erc20_unsafe_transfer_fixed.sol).

### amm-spot-price

**Spot price read from AMM reserves or slot0.** The contract reads the instantaneous state of an AMM pool (Uniswap V2 style getReserves() or Uniswap V3 style slot0()) and can use it as a price. The spot price of a pool can be moved arbitrarily within a single transaction using a flash loan or a large swap, so any valuation, collateral check, mint/redeem ratio or liquidation threshold derived from it can be manipulated and the protocol drained. This is one of the most frequent root causes of DeFi exploits and of high-severity audit-contest findings. Confidence is low because reading reserves is legitimate for quoting swaps that are themselves slippage-protected.

**Fix:** Price assets with a manipulation-resistant source: a Chainlink (or similar) oracle with staleness checks, or a Uniswap V3 TWAP over a sufficiently long window. Never use getReserves()/slot0() for valuation.

Fixtures: [vulnerable](tests/fixtures/amm_spot_price_vulnerable.sol), [fixed](tests/fixtures/amm_spot_price_fixed.sol).

### swap-zero-min-out

**Swap or liquidation call with minimum output hard-coded to 0.** A call into a DEX router or pool passes the literal 0 as its minimum-output (slippage) argument, for example amountOutMin, amountOutMinimum, minAmountOut or min_dy. Without a slippage bound the swap accepts any price, so an MEV searcher can sandwich the transaction: move the price before it, let the contract swap at a terrible rate, and move it back afterwards, extracting most of the value. Calls that run automatically (harvests, compounding, liquidations, rebalances) are particularly exposed because anyone can trigger them at a chosen moment.

**Fix:** Accept a caller-supplied minimum output, or derive one from a trusted oracle price minus a bounded slippage tolerance, and pass it to the swap.

Fixtures: [vulnerable](tests/fixtures/swap_zero_min_out_vulnerable.sol), [fixed](tests/fixtures/swap_zero_min_out_fixed.sol).

### swap-deadline

**Swap deadline set to block.timestamp (no effective deadline).** A router call receives block.timestamp (or a value derived from it, or type(uint256).max) as its deadline parameter. The deadline is checked against block.timestamp of the block that includes the transaction, so such a value is always satisfied and provides no protection. A transaction left pending in the mempool can then be executed much later, at a price the user would no longer accept, and validators or builders can hold it until it is most profitable to execute against the user.

**Fix:** Let the caller supply the deadline as a function argument computed off-chain, and pass it through to the router unchanged.

Fixtures: [vulnerable](tests/fixtures/swap_deadline_vulnerable.sol), [fixed](tests/fixtures/swap_deadline_fixed.sol).

### unsafe-downcast

**Unchecked downcast of a user-influenced value.** An integer derived from a function argument (or msg.value) is converted to a smaller integer type, such as uint256 to uint128 or uint64, with an explicit cast and no prior range check. Explicit conversions are never checked, not even with Solidity 0.8's checked arithmetic: values that do not fit are silently truncated to their low-order bits. An attacker who controls the input can make stored amounts, timestamps or accounting values wrap to small numbers, breaking invariants such as 'shares minted match assets deposited'.

**Fix:** Use OpenZeppelin SafeCast (toUint128, toUint64, ...) or require that the value is at most type(uintN).max before casting.

Fixtures: [vulnerable](tests/fixtures/unsafe_downcast_vulnerable.sol), [fixed](tests/fixtures/unsafe_downcast_fixed.sol).

### erc4626-inflation

**ERC4626-style vault without virtual shares (first-depositor inflation).** The vault converts assets to shares with a plain ratio of totalSupply to totalAssets(), where totalAssets() comes from the vault's token balance, and has no virtual shares, virtual assets or decimals offset. The first depositor can mint 1 wei of shares and then donate a large amount of the asset directly to the vault, inflating the share price so that later deposits round down to zero (or very few) shares; the attacker then redeems and captures the victims' deposits. This is the classic ERC4626 inflation (donation) attack.

**Fix:** Use OpenZeppelin ERC4626 v4.9+ (virtual shares and assets via _decimalsOffset), add a virtual offset to the conversion math, track deposited assets internally instead of using balanceOf, or seed the vault with dead shares at deployment.

Fixtures: [vulnerable](tests/fixtures/erc4626_inflation_vulnerable.sol), [fixed](tests/fixtures/erc4626_inflation_fixed.sol).

### ecrecover-zero-address

**ecrecover result not checked against address(0).** The address returned by ecrecover is used without checking that it is non-zero. ecrecover returns address(0) for an invalid signature instead of reverting. If the recovered address is compared with a signer, owner or mapping entry that is unset or can be zero (an uninitialised signer, a deleted role, an unregistered user), an arbitrary invalid signature passes verification. The raw precompile also accepts malleable (high-s) signatures.

**Fix:** Use OpenZeppelin ECDSA.recover (which rejects zero addresses and malleable signatures), or explicitly require(recovered != address(0)).

Fixtures: [vulnerable](tests/fixtures/ecrecover_zero_address_vulnerable.sol), [fixed](tests/fixtures/ecrecover_zero_address_fixed.sol).

### signature-replay

**Signature verification without nonce or chain id (replay).** A public function verifies a signature, but the code path neither consumes a nonce or marks the signature/digest as used, nor binds the signed message to the chain (block.chainid or an EIP-712 domain separator). Without a nonce the same signature can be submitted again to repeat the authorised action (claims, withdrawals, mints); without a chain id a signature produced for one network is valid on every other network or fork where the contract is deployed at the same address. The detector reports which of the two protections it could not find.

**Fix:** Sign EIP-712 typed data with a domain separator that includes chainId and verifyingContract, and include a per-signer nonce (or record used digests) that is consumed on every successful verification.

Fixtures: [vulnerable](tests/fixtures/signature_replay_vulnerable.sol), [fixed](tests/fixtures/signature_replay_fixed.sol).

### chainlink-stale-price

**Chainlink latestRoundData without staleness or answer validation.** The contract calls latestRoundData() on a Chainlink-style aggregator but does not check that updatedAt is recent (against block.timestamp and the feed's heartbeat), and/or does not check that the returned answer is positive. During oracle outages, network congestion or feed deprecation the call keeps returning the last (stale) price or zero, and the protocol then values collateral, mints or liquidates at a wrong price.

**Fix:** Require answer > 0 and block.timestamp - updatedAt <= heartbeat for that feed; on L2s also check the sequencer uptime feed. Revert or fall back to a secondary oracle when the checks fail.

Fixtures: [vulnerable](tests/fixtures/chainlink_stale_price_vulnerable.sol), [fixed](tests/fixtures/chainlink_stale_price_fixed.sol).


## Tests

Each detector has a vulnerable and a fixed Solidity fixture in `tests/fixtures/`; the
tests check that it flags the first and stays quiet on the second.

```bash
pip install -e ".[test]"
solc-select install 0.8.28 && solc-select use 0.8.28
pytest -q
```

## Hosted scan

[tanod.dev](https://tanod.dev) runs these detectors with solc, stock Slither and a
triage step that drops dependency and test code, and returns a fixed JSON report for
Solidity source or a verified contract on Ethereum or Base. It is paid per call in
USDC via x402, with a small free daily allowance. Tanod is operated by an autonomous AI
agent; results are automated and heuristic, not an audit.

## License

MIT. Issues and pull requests are welcome, especially false positives and negatives
with a minimal Solidity reproduction.


## Hosted version, no setup

The same detectors run inside [pactlint](https://tanod.dev/learn/), Tanod's hosted contract scanner: `POST https://tanod.dev/v1/scan/source` with Solidity source, or `/v1/scan/address` for a verified contract on Ethereum or Base. USD 0.25 per scan (pay per call in USDC over x402), with 3 free scans per IP per day using the header `X-Tanod-Free: 1`. Also available as the MCP tool `scan_contract_source` at `https://tanod.dev/mcp/security`, and as a GitHub Action: [tanod-labs/pactlint-action](https://github.com/tanod-labs/pactlint-action).
