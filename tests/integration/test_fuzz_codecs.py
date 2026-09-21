from scripts.fuzz_codecs import fuzz


def test_codec_mutation_fuzz_harness_smoke() -> None:
    result = fuzz(seed=1234, iterations=100)
    assert set(result) == {
        "context",
        "digest",
        "evidence-cross",
        "evidence-wide",
        "kdf",
        "kdf-record",
        "pow",
        "signed",
        "v3-history",
        "v3-history-context",
        "v3-history-digest",
        "v3-history-layout",
        "v3-round-binding",
    }
