from sigma.instrumentation import capture_oracle_inputs
from sigma.presets import lightweight_v2_2
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
