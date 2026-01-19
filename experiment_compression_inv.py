"""Quick experiment: check that `compression64_inv` inverts the compression loop.

We:
- Use `sha256_before` / `sha256_after` from `sha256_cli.py` to run SHA-256 on
  a message from a file (specified via `-f` argument).
- For each block, save the intermediate working state output of `compress64`.
- Run `compression64_inv` on that intermediate state and verify we recover:
  - the pre-round working state, and
  - the original message schedule words `w[0..63]`.
"""

from __future__ import annotations

import argparse
from typing import Tuple

from compress import MASK32, compress64
from compression_inv import compression64_inv
from basic_inv import (
    inv_expand_message_schedule,
    inv_init_message_schedule,
    inv_split_into_blocks,
    inv_pad_message,
)
from sha256_cli import (
    _after_compress_round,
    sha256,
    sha256_after,
    sha256_before,
)


def _format_state(state: Tuple[int, int, int, int, int, int, int, int]) -> str:
    """Return a compact hex representation of an 8-word state."""
    return " ".join(f"{w:08x}" for w in state)


def run_experiment(msg: bytes) -> None:
    # Compute the expected hash for the input message.
    expected_hex = sha256(msg).hex()

    # High-level SHA-256 using our CLI helpers.
    initial_state, schedules = sha256_before(msg)

    # The message "hello world" fits into a single 512-bit block after padding,
    # but we keep the loop general in case this code is reused.
    state = initial_state
    preimage_blocks: list[bytes] = []
    recovered_schedules: list[tuple[int, ...]] = []
    for block_idx, ws in enumerate(schedules):
        print(f"=== Block {block_idx} ===")
        
        # For the first block, show the expected initial state
        if block_idx == 0:
            print("expected initial working state (SHA-256 initial hash values):")
            print("  ", _format_state(state))

        # Forward compression loop.
        work_out = compress64(*state, ws)
        print("forward working state (post-64-round):")
        print("  ", _format_state(work_out))

        # Invert the 64-round compression loop from the post-round state.
        ### XXX: inv_ws[13,14,15] must be set correctly to control the last 9 bytes of the block
        inv_a, inv_b, inv_c, inv_d, inv_e, inv_f, inv_g, inv_h, inv_ws = compression64_inv(
            *work_out
        )
        inv_state = (inv_a, inv_b, inv_c, inv_d, inv_e, inv_f, inv_g, inv_h)

        print("recovered preimage working state:")
        print("  ", _format_state(inv_state))
        print("original message schedule (w[0..63]):")
        # Format as 8 words per line for readability
        for i in range(0, len(ws), 8):
            chunk = ws[i:i+8]
            hex_chunk = " ".join(f"{w:08x}" for w in chunk)
            print(f"  w[{i:2d}..{i+len(chunk)-1:2d}]: {hex_chunk}")
        print("recovered message schedule (w[0..63]):")
        # Format as 8 words per line for readability
        for i in range(0, len(inv_ws), 8):
            chunk = inv_ws[i:i+8]
            hex_chunk = " ".join(f"{w:08x}" for w in chunk)
            print(f"  w[{i:2d}..{i+len(chunk)-1:2d}]: {hex_chunk}")

        # Check that the recovered preimage matches the actual pre-round state
        # that was used as input to `compress64`.
        print("matches input working state:", inv_state == state)
        print("matches message schedule  :", tuple(ws) == inv_ws)

        # Store the recovered schedule for later verification
        recovered_schedules.append(inv_ws)

        # Additionally, verify that plugging the recovered preimage back into
        # the *forward* compression loop reproduces the post-round state.
        recomputed_work_out = compress64(*inv_state, inv_ws)
        print(
            "round-trip forward(compression64_inv(post_state)) == post_state:",
            recomputed_work_out == work_out,
        )

        # Use Level-4 inverse helpers from `basic_inv.py` to construct a
        # 512-bit *block preimage* (not necessarily a valid SHA-256 padded
        # block) consistent with the recovered schedule.
        ### XXX: w[13,14,15] must be set correctly to control the last 9 bytes of the block
        w0_15 = inv_expand_message_schedule(inv_ws)
        block_bytes = bytes(inv_init_message_schedule(w0_15))
        preimage_blocks.append(block_bytes)
        print("one block-level preimage (64 bytes):")
        print("  ", block_bytes.hex())

        # Update the hash state as the full SHA-256 loop would do.
        state = _after_compress_round(state, *work_out)

    # Level-3 inverse: go from the block-level preimage back to a *padded* message
    # using `inv_split_into_blocks`, then attempt to recover a raw message using
    # `inv_pad_message`.
    padded_list = inv_split_into_blocks([list(b) for b in preimage_blocks])

    preimage_msg_bytes = None
    try:
        # For `inv_pad_message` to succeed, `padded_list` must be a *valid*
        # SHA-256 padded message:
        #   - Its length is a multiple of 64 bytes.
        #   - The last 8 bytes encode the original message length in bits as a
        #     64-bit big-endian integer L, where 0 <= L < 2**64 and L is a
        #     multiple of 8 (i.e. the original length is an integer number of bytes).
        #   - The padding bytes immediately before this length follow the
        #     `0x80 || 0x00*` structure imposed by SHA-256 padding.
        preimage_msg_list = inv_pad_message(padded_list)
        preimage_msg_bytes = bytes(preimage_msg_list)
        print()
        print("recovered raw-message preimage (bytes):")
        print("  ", preimage_msg_bytes)
        print("  as hex:", preimage_msg_bytes.hex())
        
        # Verify that the preimage message produces the expected schedules
        print()
        print("=== Verifying recovered schedules from preimage message ===")
        preimage_initial_state, preimage_schedules = sha256_before(preimage_msg_bytes)
        
        if len(preimage_schedules) != len(recovered_schedules):
            print(f"WARNING: Block count mismatch - preimage has {len(preimage_schedules)} blocks, "
                  f"recovered schedules has {len(recovered_schedules)} blocks")
        else:
            print(f"Block count matches: {len(preimage_schedules)} blocks")
        
        for block_idx, (preimage_ws, recovered_ws) in enumerate(zip(preimage_schedules, recovered_schedules)):
            matches = tuple(preimage_ws) == recovered_ws
            print(f"Block {block_idx} schedule matches recovered: {matches}")
            if not matches:
                # Show first difference
                for i, (pw, rw) in enumerate(zip(preimage_ws, recovered_ws)):
                    if pw != rw:
                        print(f"  First difference at w[{i}]: preimage={pw:08x}, recovered={rw:08x}")
                        break
    except ValueError as e:
        print()
        print("inv_pad_message failed on block-level preimage:", e)
        
        # Even if inv_pad_message failed, we can still verify the block-level preimages
        print()
        print("=== Verifying recovered schedules from block-level preimages ===")
        # Reconstruct padded message from blocks for verification
        padded_from_blocks = b"".join(preimage_blocks)
        if len(padded_from_blocks) % 64 == 0:
            block_preimage_initial_state, block_preimage_schedules = sha256_before(padded_from_blocks)
            
            if len(block_preimage_schedules) != len(recovered_schedules):
                print(f"WARNING: Block count mismatch - block preimage has {len(block_preimage_schedules)} blocks, "
                      f"recovered schedules has {len(recovered_schedules)} blocks")
            else:
                print(f"Block count matches: {len(block_preimage_schedules)} blocks")
            
            for block_idx, (block_preimage_ws, recovered_ws) in enumerate(zip(block_preimage_schedules, recovered_schedules)):
                matches = tuple(block_preimage_ws) == recovered_ws
                print(f"Block {block_idx} schedule matches recovered: {matches}")
                if not matches:
                    # Show first difference
                    for i, (pw, rw) in enumerate(zip(block_preimage_ws, recovered_ws)):
                        if pw != rw:
                            print(f"  First difference at w[{i}]: block_preimage={pw:08x}, recovered={rw:08x}")
                            break
        else:
            print("Cannot verify: block-level preimages do not form a valid padded message")

    # Write the best-effort preimage to disk:
    # - Prefer the *raw message* preimage (if `inv_pad_message` succeeded).
    # - Otherwise, fall back to the block-level preimage bytes.
    with open("preimage.data", "wb") as f:
        if preimage_msg_bytes is not None:
            f.write(preimage_msg_bytes)
        else:
            for b in preimage_blocks:
                f.write(b)

    # Finalize the digest from the final hash state (forward pipeline).
    digest = sha256_after(state)
    digest_hex = digest.hex()

    print()
    print("final digest        :", digest_hex)
    print("expected digest     :", expected_hex)
    print("matches expected    :", digest_hex == expected_hex)

    # If we managed to recover a raw-message preimage, check that hashing it
    # with the forward SHA-256 implementation reproduces the target digest.
    if preimage_msg_bytes is not None:
        digest_from_preimage = sha256(preimage_msg_bytes).hex()
        print("digest(preimage_msg):", digest_from_preimage)
        print("preimage digest ok :", digest_from_preimage == expected_hex)

    # Sanity check using the top-level `sha256` helper.
    direct_hex = sha256(msg).hex()
    print("direct sha256 helper:", direct_hex)
    print("direct == pipeline  :", direct_hex == digest_hex)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Check that compression64_inv inverts the compression loop"
    )
    parser.add_argument(
        "-f",
        "--file",
        required=True,
        help="Input file to process",
    )
    args = parser.parse_args()
    
    with open(args.file, "rb") as f:
        msg = f.read()
    
    run_experiment(msg)

