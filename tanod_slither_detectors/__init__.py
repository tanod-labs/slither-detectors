"""Slither plugin entry point: registers the Tanod detectors with Slither."""

from .detectors import (
    AMMSpotPrice,
    ChainlinkStalePrice,
    ERC20UnsafeTransfer,
    ERC4626Inflation,
    EcrecoverZeroAddress,
    SignatureReplay,
    SwapDeadline,
    SwapZeroMinOut,
    UnsafeDowncast,
)

DETECTORS = [
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


def make_plugin():
    return DETECTORS, []
