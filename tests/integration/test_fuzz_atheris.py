import os

from scripts.fuzz_atheris import CODEC_CASES, MAX_FUZZ_INPUT, PARSERS, TestOneInput, write_corpus


def test_coverage_fuzz_target_dispatches_every_codec() -> None:
    for selector, (_, encoded, _) in enumerate(CODEC_CASES):
        TestOneInput(bytes([selector]))
        TestOneInput(bytes([selector]) + os.urandom(128))
        TestOneInput(bytes([selector]) + encoded)


def test_coverage_fuzz_target_enforces_input_budget() -> None:
    TestOneInput(b"\x00" + b"x" * MAX_FUZZ_INPUT)


def test_corpus_contains_one_selected_valid_seed_per_parser(tmp_path) -> None:
    paths = write_corpus(tmp_path)
    assert len(paths) == len(PARSERS)
    for selector, path in enumerate(paths):
        assert path.read_bytes()[0] == selector
