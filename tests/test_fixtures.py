"""Each detector fires on its vulnerable fixture and stays quiet on the fixed one."""

from pathlib import Path

import pytest
from slither import Slither

from tanod_slither_detectors import DETECTORS

FIXTURES = Path(__file__).parent / "fixtures"


def _hits(path: Path, detector) -> int:
    sl = Slither(str(path))
    sl.register_detector(detector)
    return sum(len(r) for r in sl.run_detectors())


@pytest.mark.parametrize("detector", DETECTORS, ids=lambda d: d.ARGUMENT)
def test_vulnerable_fixture_is_flagged(detector):
    base = detector.ARGUMENT.replace("-", "_")
    assert _hits(FIXTURES / f"{base}_vulnerable.sol", detector) > 0


@pytest.mark.parametrize("detector", DETECTORS, ids=lambda d: d.ARGUMENT)
def test_fixed_fixture_is_clean(detector):
    base = detector.ARGUMENT.replace("-", "_")
    assert _hits(FIXTURES / f"{base}_fixed.sol", detector) == 0


def test_plugin_entry_point():
    from tanod_slither_detectors import make_plugin

    detectors, printers = make_plugin()
    assert len(detectors) == 9 and printers == []
