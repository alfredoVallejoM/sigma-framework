from sigma.anchors import CrossWide
from sigma.backends import MultiprocessingTreeBackend
from sigma.instrumentation import capture_oracle_inputs
from sigma.presets import lightweight_v2_2, paranoid_deep_v2_2, simultaneous_v2_2
from sigma.rounds import Deep, ThreadedDeepBranchBackend
from sigma.v2 import hash_bytes


def test_oracle_capture_is_opt_in_and_preserves_digest() -> None:
    context = lightweight_v2_2(target_round=1, state_count=2)
    expected = hash_bytes(b"message", context)
    with capture_oracle_inputs() as captured:
        actual = hash_bytes(b"message", context)
    assert actual == expected
    assert captured
    assert any(item.data.startswith(b"SIGMADST") for item in captured)
    assert any(item.data.startswith(b"SIGMADST\x00\x01") for item in captured)


def test_nested_oracle_capture_is_isolated() -> None:
    context = lightweight_v2_2()
    with capture_oracle_inputs() as outer:
        hash_bytes(b"outer-1", context)
        with capture_oracle_inputs() as inner:
            hash_bytes(b"inner", context)
        hash_bytes(b"outer-2", context)
    assert inner
    assert all(item.data != b"inner" for item in outer)


def test_multiprocessing_tree_capture_is_complete_and_deterministic() -> None:
    context = simultaneous_v2_2(target_round=1, state_count=1)
    payload = b"x" * (context.chunk_size + 1)
    with capture_oracle_inputs() as first:
        hash_bytes(payload, context, MultiprocessingTreeBackend(2))
    with capture_oracle_inputs() as second:
        hash_bytes(payload, context, MultiprocessingTreeBackend(2))
    assert first == second
    assert len(first) >= len(context.branches) * 3


def test_threaded_deep_capture_matches_serial_branch_order() -> None:
    context = paranoid_deep_v2_2(target_round=2, state_count=2)
    anchor = CrossWide.compute(context, (b"thread-capture",))
    with capture_oracle_inputs() as serial:
        Deep(context).evaluate_digest(anchor)
    with capture_oracle_inputs() as threaded:
        Deep(context, ThreadedDeepBranchBackend(4)).evaluate_digest(anchor)
    assert threaded == serial
