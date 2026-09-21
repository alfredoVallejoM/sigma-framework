from pathlib import Path

import pytest

from experiments.reproduce_all import _campaign_configs


def test_pilot_orchestrator_discovers_only_current_validated_configs() -> None:
    configs = _campaign_configs(Path("experiments/configs"), "pilot")
    assert len(configs) == 20
    assert all(path.parent.name == "pilots" for path in configs)


def test_confirmatory_orchestrator_requires_a_verified_freeze(tmp_path: Path) -> None:
    (tmp_path / "confirmatory-frozen").mkdir()
    with pytest.raises((FileNotFoundError, ValueError)):
        _campaign_configs(tmp_path, "confirmatory")
