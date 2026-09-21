from __future__ import annotations

import hashlib
import tempfile
from pathlib import Path

from experiments.r141_protocol import R141_FREEZE_ID
from experiments.r15_stat_adapters import StreamIdentityV3, derive_stream_seed_v3
from experiments.r15_stat_shadow import run_stat_shadow_suite_v3
from experiments.r15_stat_streams import (
    STAT_CONSTRUCTIONS,
    STAT_CORPORA,
    StatStreamGeneratorV3,
    hash_stat_stream_v3,
    stat_message_v3,
)
from scripts.check_r15_stat_shadow import check_r15_stat_shadow


def _identity(construction: str = "SHA512", corpus: str = "counter") -> StreamIdentityV3:
    seed = derive_stream_seed_v3(R141_FREEZE_ID, construction, corpus, 0)
    return StreamIdentityV3(
        R141_FREEZE_ID,
        construction,
        corpus,
        0,
        seed.hex(),
        1024,
        128,
    )


def test_stat_messages_have_fixed_width_and_distinct_corpora() -> None:
    seed = hashlib.sha256(b"fixture").digest()
    messages = [stat_message_v3(seed, corpus, 7) for corpus in STAT_CORPORA]
    assert all(len(message) == 128 for message in messages)
    assert len(set(messages)) == 3


def test_standard_stream_is_chunking_invariant() -> None:
    identity = _identity()
    left = hash_stat_stream_v3(identity, emit_chunk_bytes=137)
    right = hash_stat_stream_v3(identity, emit_chunk_bytes=509)
    assert left == right
    assert left["total_bytes"] == 1024


def test_broken_control_repeats_digest_half() -> None:
    identity = _identity("broken-control", "alternating")
    block = StatStreamGeneratorV3(identity).output_block(0)
    assert len(block) == 64
    assert block[:32] == block[32:]


def test_r15_f_shadow_covers_all_24_cells() -> None:
    report = check_r15_stat_shadow()
    assert report["passed"] is True
    assert report["confirmatory"] is False
    assert report["cells"] == len(STAT_CONSTRUCTIONS) * len(STAT_CORPORA)


def test_stat_shadow_writes_ledger() -> None:
    with tempfile.TemporaryDirectory(prefix="r15f-test-") as temporary:
        report = run_stat_shadow_suite_v3(Path(temporary))
    assert report["cells"] == 24
    assert isinstance(report["ledger_root"], str)
    assert len(report["ledger_root"]) == 64
