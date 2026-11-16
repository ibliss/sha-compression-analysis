"""Demo: recover a block from any 16-word h window.

The solver is handed ``h[k..k+15]`` and the working state ``S[k+16]``.
Nothing else is supplied: not ``S[0]``, not the rest of ``h``, not ``W``,
and not the digest. The inverse of those 16 rounds yields ``W[k..k+15]``;
the message schedule fills the rest; the walks fill the rest of ``h``,
``S[0]``, and ``S[64]``.

The digest is the feed-forward of the recovered ``S[0]`` and ``S[64]``.
It is an output. ``S[64]`` is an input only when ``k = 48``.

Usage::

    python demo_h_window.py "hello world"
    python demo_h_window.py --start 0 "hello world"
    python demo_h_window.py --all "hello world"
    python demo_h_window.py -f path/to/file
"""

from __future__ import annotations

import argparse
import hashlib
from typing import Dict, List, Sequence, Tuple

from compress import K_VALUES, compression, compress64
from compression_inv import H_WINDOW, recover_from_h_window
from sha256_cli import _after_compress_round, sha256_before


def _hex(words) -> str:
    """Format a sequence of 32-bit words as space-separated hex."""
    return " ".join(f"{int(word) & 0xFFFFFFFF:08x}" for word in words)


def _trace(initial: Sequence[int], ws: Sequence[int]) -> List[Tuple[int, ...]]:
    """``states[i]`` is the working state at the start of round ``i``; ``states[64]`` is final."""
    state = tuple(int(word) & 0xFFFFFFFF for word in initial)
    states = [state]
    for index, word in enumerate(ws):
        state = compression(*state, int(word), K_VALUES[index])
        states.append(state)
    return states


def supply_and_recover(message: bytes, window_start: int) -> List[Dict[str, object]]:
    """Recover every block of ``message`` from ``h[k..k+15]`` and ``S[k+16]``."""
    state, schedules = sha256_before(message)
    records: List[Dict[str, object]] = []

    for block_index, ws in enumerate(schedules):
        initial = tuple(state)
        post_state, h_true = compress64(*initial, ws, track_h=True)
        states = _trace(initial, ws)
        h_supplied = list(h_true[window_start : window_start + H_WINDOW])
        h_recovered, ws_recovered, initial_recovered, final = recover_from_h_window(
            states[window_start + H_WINDOW], h_supplied, window_start
        )
        digest_words = _after_compress_round(initial_recovered, *final)

        records.append(
            {
                "block": block_index,
                "window_start": window_start,
                "h_true": list(h_true),
                "h_supplied": h_supplied,
                "h_recovered": h_recovered,
                "h_match": h_recovered == list(h_true),
                "ws_match": ws_recovered == tuple(ws),
                "initial_match": initial_recovered == initial,
                "final_match": final == tuple(post_state),
                "final_was_input": window_start + H_WINDOW == 64,
                "initial_recovered": initial_recovered,
                "final_recovered": final,
                "digest_words": digest_words,
                "round_trip": compress64(*initial_recovered, ws_recovered) == post_state,
            }
        )

        state = _after_compress_round(state, *post_state)

    return records


def run_demo(
    message: bytes, *, window_start: int = 16, verbose: bool = True
) -> bool:
    """Run one window and report whether every check matched."""
    records = supply_and_recover(message, window_start)
    ok = all(
        record["h_match"]
        and record["ws_match"]
        and record["initial_match"]
        and record["final_match"]
        and record["round_trip"]
        for record in records
    )
    if not records:
        return False

    # Chain the recovered feed-forwards. The digest is computed here, not passed in.
    chaining = records[0]["initial_recovered"]
    for record in records:
        chaining = _after_compress_round(chaining, *record["final_recovered"])
    digest = b"".join(int(word).to_bytes(4, "big") for word in chaining)
    ok = ok and digest == hashlib.sha256(message).digest()

    if verbose:
        print(f"window h[{window_start}..{window_start + H_WINDOW - 1}]")
        print(
            "  S[64] is an input :"
            if records[0]["final_was_input"]
            else "  S[64] inferred   :",
            records[0]["final_was_input"],
        )
        for record in records:
            print(f"block {record['block']}:")
            print("  supplied h        :", _hex(record["h_supplied"]))
            print("  h[0..63] match    :", record["h_match"])
            print("  schedule match    :", record["ws_match"])
            print("  S[0] match        :", record["initial_match"])
            print("  S[64] match       :", record["final_match"])
            print("  round trip        :", record["round_trip"])
        print("  inferred digest   :", digest.hex())
        print("  digest match      :", digest == hashlib.sha256(message).digest())
        print()

    return ok


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Recover a block from any 16-word h window plus S[k+16]"
    )
    parser.add_argument("message", nargs="?", default="hello world")
    parser.add_argument("-f", "--file", help="read the message from a file")
    parser.add_argument(
        "--start",
        type=int,
        default=16,
        help="first index k of h[k..k+15] (default 16; S[64] is then inferred)",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="check every window start k = 0..48",
    )
    args = parser.parse_args(argv)

    if args.file:
        with open(args.file, "rb") as handle:
            message = handle.read()
    else:
        message = args.message.encode("utf-8")

    if args.all:
        ok = True
        for start in range(64 - H_WINDOW + 1):
            matched = run_demo(message, window_start=start, verbose=False)
            ok = ok and matched
            print(f"h[{start}..{start + 15}]:", "MATCH" if matched else "MISMATCH")
        print("RESULT:", "MATCH" if ok else "MISMATCH")
        return 0 if ok else 1

    ok = run_demo(message, window_start=args.start)
    print("RESULT:", "MATCH" if ok else "MISMATCH")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
