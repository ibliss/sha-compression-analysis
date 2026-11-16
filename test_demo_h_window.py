"""Tests for recovery from any 16-word h window plus S[k+16]."""

import hashlib

import pytest

from compression_inv import recover_from_h_window
from demo_h_window import run_demo, supply_and_recover
from sha256_cli import _H0

MESSAGES = [b"", b"abc", b"hello world", b"a" * 55, b"a" * 100]


@pytest.mark.parametrize("message", MESSAGES)
@pytest.mark.parametrize("window_start", (0, 4, 16, 32, 48))
def test_window_recovers_schedule_and_both_ends(message, window_start):
    """h, W, S[0], and S[64] come back. The digest is not an input."""
    records = supply_and_recover(message, window_start)
    assert records, "expected at least one block"

    for record in records:
        assert len(record["h_supplied"]) == 16
        assert record["h_supplied"] == record["h_true"][window_start : window_start + 16]
        assert record["h_match"] is True
        assert record["ws_match"] is True
        assert record["initial_match"] is True
        assert record["final_match"] is True
        assert record["round_trip"] is True
        assert record["final_was_input"] is (window_start == 48)


def test_every_window_start_on_one_message():
    message = b"abc"
    for window_start in range(49):
        assert run_demo(message, window_start=window_start, verbose=False) is True


def test_inferred_digest_matches_hashlib():
    """The digest is the feed-forward of the recovered ends, for a window that is not the tail."""
    message = b"hello world"
    records = supply_and_recover(message, 16)
    assert len(records) == 1
    assert records[0]["final_was_input"] is False
    digest = b"".join(int(word).to_bytes(4, "big") for word in records[0]["digest_words"])
    assert digest == hashlib.sha256(message).digest()


def test_later_block_window_does_not_assume_iv():
    message = b"a" * 100
    records = supply_and_recover(message, 20)
    assert len(records) == 2
    assert records[1]["initial_recovered"] != tuple(_H0)
    assert records[1]["initial_match"] is True
    assert records[1]["h_match"] is True
    assert records[1]["final_match"] is True


def test_wrong_end_state_does_not_reproduce_the_block():
    records = supply_and_recover(b"abc", 8)
    assert records[0]["h_match"] is True
    end = list(records[0]["final_recovered"])
    # Rebuild the real end state from a fresh recovery, then flip one word of S[24].
    from demo_h_window import _trace
    from sha256_cli import sha256_before

    state, schedules = sha256_before(b"abc")
    states = _trace(state, schedules[0])
    tampered = list(states[24])
    tampered[0] ^= 1
    h_values, ws, initial, _final = recover_from_h_window(
        tampered, records[0]["h_supplied"], 8
    )
    assert ws != tuple(schedules[0])
    assert initial != tuple(state)
    assert h_values != records[0]["h_true"]


def test_rejects_bad_window():
    with pytest.raises(ValueError):
        recover_from_h_window(_H0, [0] * 15, 0)
    with pytest.raises(ValueError):
        recover_from_h_window(_H0, [0] * 16, 49)
    with pytest.raises(ValueError):
        recover_from_h_window([0] * 7, [0] * 16, 0)


def test_cli_exit_code():
    from demo_h_window import main

    assert main(["abc", "--start", "16"]) == 0
    assert main(["abc", "--all"]) == 0
