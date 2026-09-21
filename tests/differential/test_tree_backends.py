import os

import pytest

from sigma.backends import SERIAL_BACKEND, MultiprocessingTreeBackend
from sigma.presets import simultaneous_v2_2
from sigma.spec import SigmaContextV2
from sigma.v2 import hash_bytes, hash_file

LEAF_SIZE = 65536


def tree_context() -> SigmaContextV2:
    return simultaneous_v2_2(target_round=2)


@pytest.mark.parametrize("size", [0, 1, LEAF_SIZE, LEAF_SIZE + 1, 3 * LEAF_SIZE + 17])
def test_serial_and_multiprocessing_transcripts_match(size: int) -> None:
    payload = bytes((index * 29 + 7) % 256 for index in range(size))
    context = tree_context()
    expected = hash_bytes(payload, context, SERIAL_BACKEND)
    for workers in (1, 2, 3, 4, 5, 8, os.cpu_count() or 1):
        workers = min(workers, 256)
        assert hash_bytes(payload, context, MultiprocessingTreeBackend(workers)) == expected


def test_backend_identity_is_not_serialized() -> None:
    context = tree_context()
    payload = b"x" * (2 * LEAF_SIZE + 3)
    serial = hash_bytes(payload, context, SERIAL_BACKEND)
    parallel = hash_bytes(payload, context, MultiprocessingTreeBackend(3))
    assert serial.context == parallel.context
    assert serial.to_bytes() == parallel.to_bytes()


@pytest.mark.parametrize("workers", [-1, 257])
def test_worker_limits(workers: int) -> None:
    with pytest.raises(ValueError, match="workers"):
        MultiprocessingTreeBackend(workers)


def test_boolean_worker_count_is_rejected() -> None:
    with pytest.raises(TypeError, match="integer"):
        MultiprocessingTreeBackend(False)


def test_multiprocessing_backend_rejects_non_tree_suite() -> None:
    with pytest.raises(ValueError, match="TreeWide"):
        hash_bytes(b"abc", SigmaContextV2(), MultiprocessingTreeBackend(2))


def test_file_serial_and_mmap_workers_are_identical(tmp_path) -> None:
    if os.name == "nt":
        pytest.skip(
            "frozen v2.2 file_snapshot path/fd identity is not portable on Windows; "
            "R12.5 v3 file/process equivalence is tested separately"
        )
    payload = bytes((index * 11) % 256 for index in range(4 * LEAF_SIZE + 19))
    path = tmp_path / "tree-input.bin"
    path.write_bytes(payload)
    context = tree_context()
    expected = hash_file(path, context)
    assert hash_file(path, context, MultiprocessingTreeBackend(3)) == expected
    assert expected == hash_bytes(payload, context)
