import argparse
import json
import sys
from pathlib import Path

from .common import sha256_file
from .figures import generate
from .runner import execute


def reproduce_all(
    config_dir: Path, output_root: Path, figure_output: Path, campaign: str = "smoke"
) -> dict[str, object]:
    if campaign == "smoke":
        configs = [config_dir / f"exp{index:02d}-smoke.json" for index in range(1, 11)]
    elif campaign == "confirmatory":
        configs = [config_dir / "confirmatory" / f"exp{index:02d}.json" for index in range(1, 11)]
    else:
        raise ValueError("campaign must be smoke or confirmatory")
    missing = [str(path) for path in configs if not path.is_file()]
    if missing:
        raise ValueError(f"missing EXP-01..10 smoke configs: {missing}")
    output_root.mkdir(parents=True, exist_ok=True)
    selections: dict[str, str] = {}
    summaries: dict[str, dict[str, object]] = {}
    for config_path in configs:
        config = json.loads(config_path.read_text(encoding="utf-8"))
        experiment = str(config["experiment"])
        run_name = f"{experiment.lower().replace('-', '')}-{campaign}-reproduced"
        output = output_root / run_name
        summary = execute(config_path, output, [*sys.argv, "--experiment", experiment])
        selections[experiment] = run_name
        summaries[experiment] = summary
    figures = generate(output_root, figure_output, selections)
    manifest: dict[str, object] = {
        "figures": {path.name: sha256_file(path) for path in figures},
        "runs": selections,
        "schema": "sigma-reproduction-manifest-v1",
        "summaries": summaries,
    }
    manifest_path = output_root / "reproduction-manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description="Run EXP-01..10 and regenerate all figures")
    parser.add_argument("--config-dir", type=Path, default=Path("experiments/configs"))
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--figure-output", type=Path, required=True)
    parser.add_argument("--campaign", choices=("smoke", "confirmatory"), default="smoke")
    args = parser.parse_args()
    try:
        manifest = reproduce_all(
            args.config_dir, args.output_root, args.figure_output, args.campaign
        )
    except (OSError, RuntimeError, TypeError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    print(json.dumps({"runs": manifest["runs"]}, sort_keys=True))
    summaries = manifest["summaries"]
    assert isinstance(summaries, dict)
    return 0 if all(summary["passed"] for summary in summaries.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
