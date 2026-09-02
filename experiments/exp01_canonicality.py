import hashlib
import io
import tempfile
from pathlib import Path
from typing import Any, Iterable

from reference.independent_v22 import (
    ALGORITHMS,
    LIGHT_ALGORITHMS,
    deep_vector,
    sequential_suite,
    tree_suite,
)
from sigma.backends import SERIAL_BACKEND, MultiprocessingTreeBackend
from sigma.incremental import IncrementalSigmaV2
from sigma.presets import get_preset
from sigma.spec.ids import AnchorProfileId, SuiteId
from sigma.v2 import _anchor_engine, _round_engine, hash_file, hash_reader, hash_text

from .common import derived_random


def _parts(data: bytes, sizes: Iterable[int]) -> list[bytes]:
    chunks = []
    offset = 0
    for size in sizes:
        if offset >= len(data):
            break
        chunk = data[offset : offset + size]
        chunks.append(chunk)
        offset += len(chunk)
    if offset < len(data):
        chunks.append(data[offset:])
    return chunks


def _evaluate_chunks(context, chunks: Iterable[bytes]) -> tuple[str, str, str]:
    engine = _anchor_engine(context)
    for chunk in chunks:
        engine.update(chunk)
    anchor = engine.finalize()
    digest, transcript = _round_engine(context).evaluate(anchor)
    transcript_bytes = b"".join(transcript.states) + b"".join(
        item for level in transcript.branch_outputs for item in level
    )
    return (
        anchor.to_bytes().hex(),
        digest.hex(),
        hashlib.sha256(transcript_bytes).hexdigest(),
    )


def _independent_result(message: bytes, context) -> tuple[str, str, str] | None:
    common = {
        "target_round": context.target_round,
        "state_count": context.state_count,
        "salt": context.salt,
        "challenge": context.challenge,
        "application_context": context.application_context,
    }
    if context.suite_id is SuiteId.SIMULTANEOUS_TREE_WIDE_V2_2:
        result = tree_suite(message, chunk_size=context.chunk_size, **common)
        states = result["states"]
        outputs: list[list[bytes]] = []
    elif context.suite_id is SuiteId.PARANOID_DEEP_VECTOR_V2_2:
        result = deep_vector(message, **common)
        states = result["vectors"]
        outputs = result["components"]
    else:
        parameters = {
            SuiteId.REFERENCE_STREAM_WIDE_V2_2: (1, 1, ALGORITHMS),
            SuiteId.LIGHTWEIGHT_STREAM_WIDE_V2_2: (1, 1, LIGHT_ALGORITHMS),
            SuiteId.PARANOID_CROSS_WIDE_V2_2: (3, 1, ALGORITHMS),
            SuiteId.PARANOID_DEEP_V2_2: (3, 2, ALGORITHMS),
        }.get(context.suite_id)
        if parameters is None:
            return None
        anchor_profile, round_profile, algorithms = parameters
        result = sequential_suite(
            message,
            int(context.suite_id),
            anchor_profile,
            round_profile,
            algorithms=algorithms,
            **common,
        )
        states = result["states"]
        outputs = result["branch_outputs"]
    transcript = b"".join(states) + b"".join(value for row in outputs for value in row)
    return (
        result["evidence"].hex(),
        result["digest"].hex(),
        hashlib.sha256(transcript).hexdigest(),
    )


def _file_chunks(path: Path, read_size: int) -> Iterable[bytes]:
    with path.open("rb") as source:
        while chunk := source.read(read_size):
            yield chunk


def _large_file_records(
    context, preset_name: str, size: int, rng, workers: list[int]
) -> list[dict[str, Any]]:
    """Exercise large inputs without ever materializing the complete message."""

    records: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="sigma-exp01-large-") as temporary:
        path = Path(temporary) / "message.bin"
        message_hash = hashlib.sha256()
        remaining = size
        with path.open("wb") as target:
            while remaining:
                chunk = rng.randbytes(min(1024 * 1024, remaining))
                target.write(chunk)
                message_hash.update(chunk)
                remaining -= len(chunk)
        reference = _evaluate_chunks(context, _file_chunks(path, 1024 * 1024))
        adapters = [("streaming-file-reference", reference)]
        for read_size in (65521, 1024 * 1024):
            result = _evaluate_chunks(context, _file_chunks(path, read_size))
            adapters.append((f"reader-{read_size}", result))
        if context.anchor_profile is AnchorProfileId.TREE_WIDE:
            for worker_count in workers:
                evidence = MultiprocessingTreeBackend(worker_count).compute_anchor_file(
                    path, context
                )
                digest, transcript = _round_engine(context).evaluate(evidence)
                adapters.append(
                    (
                        f"mmap-workers-{worker_count}",
                        (
                            evidence.to_bytes().hex(),
                            digest.hex(),
                            hashlib.sha256(b"".join(transcript.states)).hexdigest(),
                        ),
                    )
                )
        else:
            incremental = IncrementalSigmaV2(context)
            for chunk in _file_chunks(path, 65521):
                incremental.update(chunk)
            adapters.append(
                ("incremental-file", (reference[0], incremental.finalize().hex(), reference[2]))
            )
        for adapter, result in adapters:
            records.append(
                {
                    "adapter": adapter,
                    "anchor_hex": result[0],
                    "anchor_match": result[0] == reference[0],
                    "context_hex": context.to_bytes().hex(),
                    "digest_hex": result[1],
                    "digest_match": result[1] == reference[1],
                    "message_sha256": message_hash.hexdigest(),
                    "preset": preset_name,
                    "size": size,
                    "transcript_match": result[2] == reference[2],
                    "transcript_sha256": result[2],
                }
            )
    return records


def run(config: dict[str, Any]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    master_seed = str(config["master_seed"])
    workers = [int(value) for value in config.get("workers", [1, 2, 3, 4, 8])]
    max_in_memory = int(config.get("max_in_memory_bytes", 256 * 1024 * 1024))
    sizes = [int(value) for value in config["sizes"]]
    for start, end in config.get("size_ranges", []):
        sizes.extend(range(int(start), int(end) + 1))
    sizes = sorted(set(sizes))
    for preset_name in config["presets"]:
        context = get_preset(
            preset_name,
            target_round=int(config.get("target_round", 2)),
            state_count=int(config.get("state_count", 3)),
        )
        text = "Σigma/ñ/🔒"
        text_bytes = text.encode("utf-8")
        text_reference = _evaluate_chunks(context, (text_bytes,))
        text_digest = hash_text(text, context).hex()
        records.append(
            {
                "adapter": "text-explicit-utf8",
                "anchor_hex": text_reference[0],
                "anchor_match": True,
                "context_hex": context.to_bytes().hex(),
                "digest_hex": text_digest,
                "digest_match": text_digest == text_reference[1],
                "message_sha256": hashlib.sha256(text_bytes).hexdigest(),
                "preset": preset_name,
                "size": len(text_bytes),
                "transcript_match": True,
                "transcript_sha256": text_reference[2],
            }
        )
        independent_text = _independent_result(text_bytes, context)
        if independent_text is not None:
            records.append(
                {
                    "adapter": "independent-consumer-text",
                    "anchor_hex": independent_text[0],
                    "anchor_match": independent_text[0] == text_reference[0],
                    "context_hex": context.to_bytes().hex(),
                    "digest_hex": independent_text[1],
                    "digest_match": independent_text[1] == text_digest,
                    "message_sha256": hashlib.sha256(text_bytes).hexdigest(),
                    "preset": preset_name,
                    "size": len(text_bytes),
                    "transcript_match": independent_text[2] == text_reference[2],
                    "transcript_sha256": independent_text[2],
                }
            )
        for size in sizes:
            rng = derived_random(master_seed, f"EXP-01/{preset_name}/{size}")
            if size > max_in_memory:
                records.extend(_large_file_records(context, preset_name, size, rng, workers))
                continue
            message = rng.randbytes(size)
            reference = _evaluate_chunks(context, [message])
            adapters: list[tuple[str, tuple[str, str, str]]] = [("bytes", reference)]
            independent_limit = int(config.get("independent_max_bytes", 1024 * 1024))
            if size <= independent_limit:
                independent = _independent_result(message, context)
                if independent is not None:
                    adapters.append(("independent-consumer", independent))

            random_sizes = [rng.randint(1, 131071) for _ in range(max(1, size // 32768 + 2))]
            adapters.append(
                ("random-chunks", _evaluate_chunks(context, _parts(message, random_sizes)))
            )
            reader_result = _evaluate_chunks(context, _parts(message, iter(lambda: 65521, 0)))
            reader_digest = hash_reader(io.BytesIO(message), context, read_size=65521).hex()
            adapters.append(("reader-65521", (reader_result[0], reader_digest, reader_result[2])))

            with tempfile.TemporaryDirectory(prefix="sigma-exp01-") as temporary:
                path = Path(temporary) / "message.bin"
                path.write_bytes(message)
                evidence = SERIAL_BACKEND.compute_anchor_file(path, context)
                file_reference, file_transcript = _round_engine(context).evaluate(evidence)
                file_digest = hash_file(path, context).hex()
                file_transcript_bytes = b"".join(file_transcript.states) + b"".join(
                    item for level in file_transcript.branch_outputs for item in level
                )
                if file_digest != file_reference.hex():
                    raise RuntimeError("public file adapter diverged from serial backend")
                adapters.append(
                    (
                        "file",
                        (
                            evidence.to_bytes().hex(),
                            file_digest,
                            hashlib.sha256(file_transcript_bytes).hexdigest(),
                        ),
                    )
                )
                if context.anchor_profile is AnchorProfileId.TREE_WIDE:
                    for worker_count in workers:
                        backend = MultiprocessingTreeBackend(worker_count)
                        evidence = backend.compute_anchor_file(path, context)
                        digest, transcript = _round_engine(context).evaluate(evidence)
                        transcript_bytes = b"".join(transcript.states)
                        adapters.append(
                            (
                                f"mmap-workers-{worker_count}",
                                (
                                    evidence.to_bytes().hex(),
                                    digest.hex(),
                                    hashlib.sha256(transcript_bytes).hexdigest(),
                                ),
                            )
                        )

            if context.anchor_profile is not AnchorProfileId.TREE_WIDE:
                incremental = IncrementalSigmaV2(context)
                incremental_chunks = _parts(message, random_sizes)
                for chunk in incremental_chunks:
                    incremental.update(chunk)
                incremental_reference = _evaluate_chunks(context, incremental_chunks)
                adapters.append(
                    (
                        "incremental",
                        (
                            incremental_reference[0],
                            incremental.finalize().hex(),
                            incremental_reference[2],
                        ),
                    )
                )

            for adapter, result in adapters:
                records.append(
                    {
                        "adapter": adapter,
                        "anchor_hex": result[0],
                        "anchor_match": result[0] == reference[0],
                        "context_hex": context.to_bytes().hex(),
                        "digest_hex": result[1],
                        "digest_match": result[1] == reference[1],
                        "message_sha256": hashlib.sha256(message).hexdigest(),
                        "preset": preset_name,
                        "size": size,
                        "transcript_match": result[2] == reference[2],
                        "transcript_sha256": result[2],
                    }
                )
    return records
