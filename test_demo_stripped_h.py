"""Tests for the stripped-h demo: h[0..7] omitted, inversion still matches."""

import pytest

from demo_stripped_h import run_demo, strip_and_invert

MESSAGES = [b"", b"abc", b"hello world", b"a" * 55, b"a" * 100]


@pytest.mark.parametrize("message", MESSAGES)
def test_stripped_h_prefix_matches(message):
    """With only h[8..63] supplied, all 8 stripped words come back."""
    records = strip_and_invert(message)
    assert records, "expected at least one block"

    for record in records:
        h_true = record["h_true"]
        h_supplied = record["h_supplied"]
        h_recovered = record["h_recovered"]

        # The solver really did receive only the tail.
        assert len(h_supplied) == 56
        assert h_supplied == list(h_true[8:])

        # h[0..3] are the chaining value reversed; h[4..7] are solved.
        assert h_recovered[:8] == list(h_true[:8])
        assert h_recovered[8:] == list(h_true[8:])
        assert record["h_prefix_match"] is True


@pytest.mark.parametrize("message", MESSAGES)
def test_stripped_h_inversion_matches(message):
    """The recovered state, schedule, and round trip are exact."""
    for record in strip_and_invert(message):
        assert record["state_match"] is True
        assert record["ws_match"] is True
        assert record["endpoint_match"] is True
        assert record["round_trip"] is True


@pytest.mark.parametrize("message", MESSAGES)
def test_stripped_h_demo_reports_match(message):
    assert run_demo(message, verbose=False) is True


def test_stripped_h_cli_exit_code():
    from demo_stripped_h import main

    assert main(["abc"]) == 0
