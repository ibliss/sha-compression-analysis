"""Demo: recover a block from h[4..19] only.

The solver is handed the block's initial state and ``h[4..19]`` (16 of the
64 words).  Nothing in ``h[0..3]`` or ``h[20..63]`` is supplied, and the
final working state is not an input.  The walk still recovers the message
schedule and the rest of the h schedule because:

- ``h[0..3]`` are the chaining value reversed, so they follow from the
  initial state;
- rounds 0..15 recover ``W[0..15]`` from ``h[4..19]`` by subtraction;
- the message-schedule recurrence gives ``W[16..63]``;
- the forward walk reads off ``h[20..63]`` and the final working state.

Usage::

    python demo_supplied_h_4_19.py "hello world"
    python demo_supplied_h_4_19.py -f path/to/file
"""

from __future__ import annotations

import argparse
from typing import Dict, List

from compress import compress64
from compression_inv import recover_from_h_4_19
from sha256_cli import _after_compress_round, sha256_before


def _hex(words) -> str:
    """Format a sequence of 32-bit words as space-separated hex."""
    return " ".join(f"{word:08x}" for word in words)


def supply_and_recover(message: bytes) -> List[Dict[str, object]]:
    """Recover every block of ``message`` from ``h[4..19]`` only.

    Returns one record per block.  Each record holds the true h schedule, the
    16 supplied words, the 64 recovered words, and the match flags.
    """
    state, schedules = sha256_before(message)
    records: List[Dict[str, object]] = []

    for block_index, ws in enumerate(schedules):
        post_state, h_true = compress64(*state, ws, track_h=True)

        # The solver sees only h[4..19].  The other 48 words stay out.
        h_supplied = list(h_true[4:20])
        h_recovered, ws_recovered, final = recover_from_h_4_19(state, h_supplied)

        records.append(
            {
                "block": block_index,
                "h_true": list(h_true),
                "h_supplied": h_supplied,
                "h_recovered": h_recovered,
                "h_match": h_recovered == list(h_true),
                "ws_match": ws_recovered == tuple(ws),
                "ws_recovered": ws_recovered,
                "final_match": final == tuple(post_state),
                "round_trip": compress64(*state, ws_recovered) == post_state,
            }
        )

        state = _after_compress_round(state, *post_state)

    return records


def run_demo(message: bytes, *, verbose: bool = True) -> bool:
    """Run the h[4..19] recovery and report whether every check matched."""
    records = supply_and_recover(message)
    ok = True

    for record in records:
        checks = (
            record["h_match"],
            record["ws_match"],
            record["final_match"],
            record["round_trip"],
        )
        ok = ok and all(checks)

        if verbose:
            print(f"block {record['block']}:")
            print("  supplied  h[4..19] :", _hex(record["h_supplied"]))
            print(
                "  omitted   h[0..3]  :",
                _hex(record["h_true"][:4]),
                "(never given to the solver)",
            )
            print(
                "  omitted   h[20..63]:",
                "44 words",
                "(never given to the solver)",
            )
            print(
                "  recovered h[0..3]  :",
                _hex(record["h_recovered"][:4]),
                "(chaining value, reversed)",
            )
            print(
                "  recovered h[20..23]:",
                _hex(record["h_recovered"][20:24]),
                "(first four words filled by the message rule)",
            )
            print("  h[0..63] match     :", record["h_match"])
            print("  schedule match     :", record["ws_match"])
            print("  final state match  :", record["final_match"])
            print("  round trip         :", record["round_trip"])
            print()

    return ok


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Recover a block from h[4..19] only (16 words supplied)"
    )
    parser.add_argument("message", nargs="?", default="hello world")
    parser.add_argument("-f", "--file", help="read the message from a file")
    args = parser.parse_args(argv)

    if args.file:
        with open(args.file, "rb") as handle:
            message = handle.read()
    else:
        message = args.message.encode("utf-8")

    ok = run_demo(message)
    print("RESULT:", "MATCH" if ok else "MISMATCH")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
