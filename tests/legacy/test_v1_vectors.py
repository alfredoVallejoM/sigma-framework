"""Compatibility vectors for reproducible v1 modes.

These tests preserve legacy behavior; they are not claims of cryptographic
security. Simultaneous v1 is excluded because its output depends on the host
and differs between file and memory adapters, as recorded in the audit.
"""

import pytest

from sigma.factory import SigmaFactory


@pytest.mark.parametrize(
    "mode,data,expected",
    [
        (
            "paranoid",
            b"",
            "20375b7019b3aab8d1bef7e5d1ce722e31228c7e1ed50b38d333f044c0b65b1a"
            "c3c4753d2e72210422afbe603d896df5f11c469075736652ba2f9555a01b78e3",
        ),
        (
            "paranoid",
            b"abc",
            "ade05e33591b0414b4200521f3f3749fe0a6d0e150bb2e366b566136a831ff37"
            "030b118c2960903784be8f07515b0aa02a3461b712237fb468b85dd9f5169836",
        ),
        (
            "lightweight",
            b"",
            "22797f047e37aa8ca4b71fde65d692c8117b9c89bd0086e9fcadb172589008c7",
        ),
        (
            "lightweight",
            b"abc",
            "a7d9200d609e4b3b207c897e6965fa42e53c6f01afd3c3d59284dc01562db5cf",
        ),
        (
            "realtime",
            b"",
            "00" * 32,
        ),
        (
            "realtime",
            b"abc",
            "d9937ed4f600277f14e0ecb3087757820cf4669edfd44e1e05a764011916e94d",
        ),
    ],
)
def test_legacy_v1_vectors(mode: str, data: bytes, expected: str) -> None:
    assert SigmaFactory.hash_bytes(data, mode=mode) == expected
    assert SigmaFactory.hash_bytes(data, mode="legacy-v1-" + mode) == expected
