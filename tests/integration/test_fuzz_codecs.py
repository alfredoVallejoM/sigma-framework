from scripts.fuzz_codecs import fuzz


def test_codec_mutation_fuzz_harness_smoke() -> None:
    result = fuzz(seed=1234, iterations=100)
    assert set(result) == {
        "context",
        "digest",
        "evidence-cross",
        "evidence-wide",
        "kdf",
        "kdf-result",
        "pow",
        "signed",
    }
