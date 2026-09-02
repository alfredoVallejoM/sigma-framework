from experiments.exp11_pow import run, summarize


def test_pow_campaign_exercises_protocol_attacks_and_reused_challenges() -> None:
    records = run(
        {
            "challenge_modes": ["unique", "reused"],
            "master_seed": "test",
            "max_attempts": 1024,
            "state_counts": [2],
            "target_rounds": [1],
            "total_difficulty_bits": 4,
            "trials": 4,
        }
    )
    assert {record["challenge_mode"] for record in records} == {"unique", "reused"}
    assert all(record["verification_match"] is not False for record in records)
    assert all(record["replay_rejected"] is not False for record in records)
    assert all(record["challenge_substitution_rejected"] is not False for record in records)
    assert all(record["difficulty_downgrade_rejected"] is not False for record in records)
    assert all(record["tampered_digest_rejected"] is not False for record in records)
    assert all(record["resource_exhaustion_rejected"] for record in records)
    assert all(group["quality_control_passed"] for group in summarize(records))


def test_pow_campaign_preserves_right_censoring() -> None:
    records = run(
        {
            "master_seed": "censored",
            "max_attempts": 1,
            "total_difficulty_bits": 16,
            "trials": 4,
        }
    )
    assert any(record["censored"] for record in records)
    assert all(group["censored_trials"] >= 0 for group in summarize(records))
