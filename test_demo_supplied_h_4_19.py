"""Tests for recovery from h[4..19] only: the other 48 words are not inputs."""

import pytest

from compression_inv import recover_from_h_4_19
from demo_supplied_h_4_19 import run_demo, supply_and_recover
from sha256_cli import _H0

MESSAGES = [b"", b"abc", b"hello world", b"a" * 55, b"a" * 100]


@pytest.mark.parametrize("message", MESSAGES)
def test_supplied_words_are_only_h_4_19(message):
    """The solver receives h[4..19] and nothing else from the schedule."""
    records = supply_and_recover(message)
    assert records, "expected at least one block"

    for record in records:
        h_true = record["h_true"]
        h_supplied = record["h_supplied"]
        h_recovered = record["h_recovered"]

        assert len(h_supplied) == 16
        assert h_supplied == list(h_true[4:20])
        assert h_recovered == list(h_true)
        assert record["h_match"] is True


@pytest.mark.parametrize("message", MESSAGES)
def test_recovered_schedule_and_final_state_match(message):
    """The recovered message schedule, final state, and round trip are exact."""
    for record in supply_and_recover(message):
        assert record["ws_match"] is True
        assert record["final_match"] is True
        assert record["round_trip"] is True


@pytest.mark.parametrize("message", MESSAGES)
def test_demo_reports_match(message):
    assert run_demo(message, verbose=False) is True


def test_cli_exit_code():
    from demo_supplied_h_4_19 import main

    assert main(["abc"]) == 0


def test_rejects_wrong_h_mid_length():
    with pytest.raises(ValueError):
        recover_from_h_4_19(_H0, [0] * 15)
    with pytest.raises(ValueError):
        recover_from_h_4_19(_H0, [0] * 17)
