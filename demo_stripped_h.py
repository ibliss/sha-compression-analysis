"""Demo: invert a block with the first 8 h values stripped.

The inverse is handed only ``h[8..63]`` (56 of the 64 words).  Nothing in
``h[0..7]`` is supplied.  The walk still lands exactly on the block's chaining
value because:

- ``h[0..3]`` are the chaining value reversed, so they follow from the known
  endpoint rather than from the supplied schedule;
- ``h[4..7]`` are solved from the endpoint by ``solve_h_prefix``, one
  subtraction per word.

The demo prints the stripped values, the recovered values, and whether the
recovered state, schedule, prefix, and round trip all match.

Usage::

    python demo_stripped_h.py "hello world"
    python demo_stripped_h.py -f path/to/file
"""

from __future__ import annotations

import argparse
from typing import Dict, List

from compress import compress64
from compression_inv import compression64_inv, solve_h_prefix
from sha256_cli import _after_compress_round, sha256_before


def _hex(words) -> str:
    """Format a sequence of 32-bit words as space-separated hex."""
    return " ".join(f"{word:08x}" for word in words)


def strip_and_invert(message: bytes) -> List[Dict[str, object]]:
    """Invert every block of ``message`` with ``h[0..7]`` omitted.

    Returns one record per block.  Each record holds the true h schedule, the
    56 supplied words, the 64 recovered words, and the match flags.
    """
    state, schedules = sha256_before(message)
    records: List[Dict[str, object]] = []

    for block_index, ws in enumerate(schedules):
        post_state = compress64(*state, ws)
        _, h_true = compress64(*state, ws, track_h=True)

        # Strip the first 8 words: the solver only ever sees h[8..63].
        h_supplied = list(h_true[8:])
        h_recovered, ws_recovered, endpoint = solve_h_prefix(
            post_state, h_supplied, state
        )
        inv = compression64_inv(
            *post_state, h_values=h_supplied, initial_state=state
        )

        records.append(
            {
                "block": block_index,
                "h_true": list(h_true),
                "h_supplied": h_supplied,
                "h_recovered": h_recovered,
                "h_prefix_match": h_recovered[:8] == list(h_true[:8]),
                "state_match": inv[:8] == tuple(state),
                "ws_match": inv[8] == tuple(ws),
                "ws_recovered": ws_recovered,
                "endpoint_match": endpoint == tuple(state),
                "round_trip": compress64(*inv[:8], inv[8]) == post_state,
            }
        )

        state = _after_compress_round(state, *post_state)

    return records


def run_demo(message: bytes, *, verbose: bool = True) -> bool:
    """Run the stripped-h inversion and report whether every check matched."""
    records = strip_and_invert(message)
    ok = True

    for record in records:
        checks = (
            record["h_prefix_match"],
            record["state_match"],
            record["ws_match"],
            record["endpoint_match"],
            record["round_trip"],
        )
        ok = ok and all(checks)

        if verbose:
            print(f"block {record['block']}:")
            print("  supplied  h[8..63] :", _hex(record["h_supplied"]))
            print(
                "  omitted   h[0..7]  :",
                _hex(record["h_true"][:8]),
                "(never given to the solver)",
            )
            print(
                "  recovered h[0..3]  :",
                _hex(record["h_recovered"][:4]),
                "(chaining value, reversed)",
            )
            print(
                "  recovered h[4..7]  :",
                _hex(record["h_recovered"][4:8]),
                "(solved from the endpoint)",
            )
            print("  h[0..7] match      :", record["h_prefix_match"])
            print("  state match        :", record["state_match"])
            print("  schedule match     :", record["ws_match"])
            print("  endpoint match     :", record["endpoint_match"])
            print("  round trip         :", record["round_trip"])
            print()

    return ok


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Invert a block with h[0..7] stripped (only h[8..63] supplied)"
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
