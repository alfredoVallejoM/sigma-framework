from __future__ import annotations

import os
from dataclasses import replace
from pathlib import Path

import pytest

from sigma.tree import (
    DEFAULT_PROFILE,
    TreeBuilder,
    TreeResumeCheckpointV1,
    TreeSourceHintV1,
    build_tree,
    checkpoint_builder,
    checkpoint_bytes,
    read_checkpoint,
    restore_builder,
    resume_tree,
    source_hint_from_path,
    source_hint_matches_path,
    write_checkpoint_atomic,
)


@pytest.mark.parametrize("size", [0, 1, 65_535, 65_536, 65_537, 3 * 65_536 + 19])
def test_checkpoint_roundtrip_and_resume(size):
    data = bytes((i * 17 + 3) % 251 for i in range(size))
    split = size // 2
    checkpoint = checkpoint_bytes(data[:split])
    decoded = TreeResumeCheckpointV1.from_bytes(checkpoint.to_bytes())
    assert decoded == checkpoint
    assert resume_tree(decoded, data[split:]) == build_tree(data)


def test_checkpoint_exact_chunk_boundary_has_empty_tail():
    data = b"x" * (2 * 65_536)
    checkpoint = checkpoint_bytes(data)
    assert checkpoint.completed_leaf_count == 2
    assert checkpoint.completed_bytes == len(data)
    assert checkpoint.tail == b""
    assert checkpoint.frontier.byte_length == len(data)


def test_checkpoint_mid_tail_keeps_only_unhashed_tail():
    data = b"x" * (2 * 65_536 + 123)
    checkpoint = checkpoint_bytes(data)
    assert checkpoint.completed_leaf_count == 2
    assert checkpoint.frontier.byte_length == 2 * 65_536
    assert checkpoint.tail == b"x" * 123
    assert checkpoint.completed_bytes == 2 * 65_536 + 123


def test_checkpoint_rejects_tail_at_chunk_size():
    checkpoint = checkpoint_bytes(b"")
    with pytest.raises(ValueError, match="shorter than chunk size"):
        replace(checkpoint, tail=b"x" * DEFAULT_PROFILE.chunk_size)


def test_checkpoint_rejects_offset_accounting_drift():
    checkpoint = checkpoint_bytes(b"abc")
    with pytest.raises(ValueError, match="byte count"):
        replace(checkpoint, completed_bytes=checkpoint.completed_bytes + 1)


def test_checkpoint_frontier_must_contain_only_complete_leaves():
    builder = TreeBuilder()
    builder.update(b"x" * 17)
    # Builder frontier excludes the tail, so the normal checkpoint is valid.
    checkpoint = checkpoint_builder(builder)
    assert checkpoint.frontier.nodes == ()

    # A TreeFrontier with a short rightmost leaf is structurally legal in ST0
    # but is not legal checkpoint frontier state.
    from sigma.tree import TreeFrontier, leaf_node

    short = leaf_node(DEFAULT_PROFILE, 0, 0, b"x")
    frontier = TreeFrontier((short,))
    with pytest.raises(ValueError, match="complete leaves"):
        TreeResumeCheckpointV1(DEFAULT_PROFILE, 1, 1, frontier, b"")


def test_checkpoint_from_finalized_builder_rejected():
    builder = TreeBuilder()
    builder.update(b"abc")
    builder.finalize()
    with pytest.raises(RuntimeError, match="finalized"):
        checkpoint_builder(builder)


def test_repeated_resume_checkpoint_cycles_equal_direct():
    data = bytes((i * 31 + 9) % 251 for i in range(4 * 65_536 + 313))
    cuts = [65_535, 65_536, 2 * 65_536 + 7, 4 * 65_536, len(data)]

    builder = TreeBuilder()
    previous = 0
    checkpoint = checkpoint_builder(builder)
    for cut in cuts:
        builder = restore_builder(checkpoint)
        builder.update(data[previous:cut])
        checkpoint = checkpoint_builder(builder)
        previous = cut

    assert resume_tree(checkpoint, data[previous:]) == build_tree(data)


def test_source_hint_roundtrip_does_not_affect_resume_root(tmp_path: Path):
    source = tmp_path / "source.bin"
    source.write_bytes(b"payload")
    hint = source_hint_from_path(source)
    assert source_hint_matches_path(hint, source)

    checkpoint = checkpoint_bytes(b"abc", source_hint=hint)
    changed_hint = TreeSourceHintV1(
        hint.size + 1,
        hint.mtime_ns,
        hint.inode,
        hint.device,
    )
    changed = replace(checkpoint, source_hint=changed_hint)
    assert resume_tree(checkpoint, b"def") == resume_tree(changed, b"def")

    source.write_bytes(b"changed")
    assert not source_hint_matches_path(hint, source)


def test_checkpoint_wrong_profile_wire_rejected():
    checkpoint = checkpoint_bytes(b"abc").to_bytes()
    # Nested profile begins in field 1; mutate its profile id payload while
    # retaining outer framing. Strict nested parsing must reject it.
    marker = b"SIGTPRF1"
    offset = checkpoint.index(marker)
    mutated = bytearray(checkpoint)
    # profile record: 14-byte header, tag1 header 6 bytes, then u16 profile id
    mutated[offset + 14 + 6 + 1] ^= 1
    with pytest.raises(ValueError):
        TreeResumeCheckpointV1.from_bytes(bytes(mutated))


def test_checkpoint_corrupted_frontier_wire_rejected():
    checkpoint = checkpoint_bytes(b"x" * (3 * 65_536 + 7)).to_bytes()
    marker = b"SIGTFRNT"
    offset = checkpoint.index(marker)
    mutated = bytearray(checkpoint)
    mutated[offset] ^= 1
    with pytest.raises(ValueError):
        TreeResumeCheckpointV1.from_bytes(bytes(mutated))


def test_atomic_checkpoint_persistence_success(tmp_path: Path):
    path = tmp_path / "state.chk"
    checkpoint = checkpoint_bytes(b"abc")
    write_checkpoint_atomic(path, checkpoint)
    assert read_checkpoint(path) == checkpoint
    assert not list(tmp_path.glob(".state.chk.*.tmp"))


def test_atomic_checkpoint_failure_preserves_previous(tmp_path: Path, monkeypatch):
    import sigma.tree.checkpoint as checkpoint_module

    path = tmp_path / "state.chk"
    old = checkpoint_bytes(b"old")
    new = checkpoint_bytes(b"new-state")
    write_checkpoint_atomic(path, old)

    def fail_replace(src, dst):
        raise OSError("injected replace failure")

    monkeypatch.setattr(checkpoint_module.os, "replace", fail_replace)
    with pytest.raises(OSError, match="injected"):
        write_checkpoint_atomic(path, new)

    assert read_checkpoint(path) == old
    assert not list(tmp_path.glob(".state.chk.*.tmp"))
