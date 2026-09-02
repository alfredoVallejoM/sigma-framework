import hashlib
import statistics
from typing import Any

from sigma.experimental import PsiKernel

from .common import derived_random


def _distance(left: bytes, right: bytes) -> int:
    return sum((a ^ b).bit_count() for a, b in zip(left, right, strict=True))


def _psi(parts: tuple[bytes, bytes, bytes, bytes]) -> bytes:
    return PsiKernel.compute_anchor(*parts)


def run(config: dict[str, Any]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    master_seed = str(config["master_seed"])
    for width_value in config.get("collision_widths", [8, 12, 16]):
        width = int(width_value)
        rng = derived_random(master_seed, f"EXP-15/collision/{width}")
        seen: dict[int, int] = {}
        for candidate in range(1, int(config.get("max_candidates", 100_000)) + 1):
            output = _psi(tuple(rng.randbytes(64) for _ in range(4)))  # type: ignore[arg-type]
            prefix = int.from_bytes(output, "big") >> (512 - width)
            if prefix in seen:
                records.append(
                    {
                        "candidates": candidate,
                        "kind": "reduced-collision",
                        "metric": candidate,
                        "state_bits": width,
                    }
                )
                break
            seen[prefix] = candidate
        else:
            records.append(
                {
                    "candidates": int(config.get("max_candidates", 100_000)),
                    "kind": "reduced-collision-censored",
                    "metric": int(config.get("max_candidates", 100_000)),
                    "state_bits": width,
                }
            )

    rng = derived_random(master_seed, "EXP-15/differential")
    for trial in range(int(config.get("differential_trials", 256))):
        parts = tuple(rng.randbytes(64) for _ in range(4))
        changed = list(parts)
        bit = rng.randrange(2048)
        branch, within = divmod(bit, 512)
        mutable = bytearray(changed[branch])
        mutable[within // 8] ^= 1 << (within % 8)
        changed[branch] = bytes(mutable)
        changed_parts = tuple(changed)
        psi_distance = _distance(_psi(parts), _psi(changed_parts))  # type: ignore[arg-type]
        sha_distance = _distance(
            hashlib.sha512(b"".join(parts)).digest(),
            hashlib.sha512(b"".join(changed_parts)).digest(),
        )
        records.extend(
            (
                {
                    "candidates": 0,
                    "kind": "psi-differential",
                    "metric": psi_distance,
                    "state_bits": 512,
                    "trial": trial,
                },
                {
                    "candidates": 0,
                    "kind": "sha512-differential",
                    "metric": sha_distance,
                    "state_bits": 512,
                    "trial": trial,
                },
            )
        )
    return records


def summarize(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[tuple[str, int], list[dict[str, Any]]] = {}
    for record in records:
        groups.setdefault((str(record["kind"]), int(record["state_bits"])), []).append(record)
    summaries: list[dict[str, Any]] = [
        {
            "input_bits": 2048,
            "kind": "dimension-audit",
            "non_bijective_by_pigeonhole": True,
            "output_bits": 512,
        }
    ]
    for (kind, width), group in sorted(groups.items()):
        summaries.append(
            {
                "kind": kind,
                "mean_metric": statistics.mean(float(row["metric"]) for row in group),
                "observations": len(group),
                "state_bits": width,
            }
        )
    return summaries
