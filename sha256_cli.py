"""SHA-256 implementation using the `compress64` function from `compress.py`.

This module provides:

- `sha256(data: bytes) -> bytes`: compute the SHA-256 digest of arbitrary data.
- CLI usage: `python sha256_cli.py "message"` prints the hex digest of the
  UTF-8 encoding of `"message"`.
"""

from __future__ import annotations

import sys
from typing import Iterable, List

from compress import MASK32, compress64, _rotr


# Initial hash values (first 32 bits of the fractional parts of the
# square roots of the first 8 primes 2..19), as per FIPS 180-4.
_H0 = [
    0x6A09E667,
    0xBB67AE85,
    0x3C6EF372,
    0xA54FF53A,
    0x510E527F,
    0x9B05688C,
    0x1F83D9AB,
    0x5BE0CD19,
]


def _shr(x: int, n: int) -> int:
    """Right-shift a 32-bit word `x` by `n` bits."""
    x &= MASK32
    return x >> n


def _small_sigma0(x: int) -> int:
    """SHA-256 function σ0 used in the message schedule."""
    return (_rotr(x, 7) ^ _rotr(x, 18) ^ _shr(x, 3)) & MASK32


def _small_sigma1(x: int) -> int:
    """SHA-256 function σ1 used in the message schedule."""
    return (_rotr(x, 17) ^ _rotr(x, 19) ^ _shr(x, 10)) & MASK32


def _pad_message(message: bytes) -> bytes:
    """Pad the input message according to the SHA-256 specification.

    The result length is a multiple of 64 bytes (512 bits).
    """
    ml_bits = len(message) * 8

    # Append the '1' bit (0x80), then k zero bytes so that length ≡ 56 mod 64.
    padded = bytearray(message)
    padded.append(0x80)

    while (len(padded) % 64) != 56:
        padded.append(0x00)

    # Append 64-bit big-endian length in bits.
    padded.extend(ml_bits.to_bytes(8, byteorder="big"))
    return bytes(padded)


def _pad_message_bits(message_bytes: bytes, length_bits: int) -> bytes:
    """Pad a message with explicit bit length according to SHA-256 specification.
    
    This supports non-byte-aligned messages where the actual message length
    in bits is less than len(message_bytes) * 8.
    
    Args:
        message_bytes: The message bytes (may have unused bits in last byte)
        length_bits: The actual message length in bits
    
    Returns:
        Padded message as bytes (multiple of 64 bytes)
    """
    padded = bytearray(message_bytes)
    
    # Calculate how many complete bytes and remaining bits
    remaining_bits = length_bits % 8
    
    if remaining_bits == 0:
        # Message ends on byte boundary - append 0x80
        padded.append(0x80)
    else:
        # Message has partial last byte - set the bit after the message
        # The last byte already contains the message bits in the high positions
        # We need to set the next bit to 1 and clear any lower bits
        
        # Mask to keep only the message bits (high 'remaining_bits' bits)
        mask = (0xFF << (8 - remaining_bits)) & 0xFF
        # The '1' bit to append (immediately after message bits)
        one_bit = 0x80 >> remaining_bits
        
        # Update the last byte: keep message bits, add '1' bit, clear rest
        padded[-1] = (padded[-1] & mask) | one_bit
    
    # Pad with zeros until length ≡ 56 mod 64 (448 bits mod 512)
    while (len(padded) % 64) != 56:
        padded.append(0x00)
    
    # Append 64-bit big-endian length in BITS
    padded.extend(length_bits.to_bytes(8, byteorder="big"))
    
    return bytes(padded)


def _chunks(data: bytes, size: int) -> Iterable[bytes]:
    """Yield successive `size`-byte chunks from `data`."""
    for i in range(0, len(data), size):
        yield data[i : i + size]


def _build_message_schedule(block: bytes) -> List[int]:
    """Given a 512-bit block, build the 64-word message schedule w[0..63]."""
    if len(block) != 64:
        raise ValueError(f"Expected 64-byte block, got {len(block)}")

    w: List[int] = [0] * 64

    # First 16 words come directly from the block (big-endian).
    for i in range(16):
        w[i] = int.from_bytes(block[4 * i : 4 * (i + 1)], byteorder="big") & MASK32

    # Extend to 64 words using the SHA-256 recurrence.
    for i in range(16, 64):
        s0 = _small_sigma0(w[i - 15])
        s1 = _small_sigma1(w[i - 2])
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & MASK32

    return w


#
# Public helper functions (forward operations) for use by inverse tests
#

def pad_message(message):
    """Pad a raw message to a multiple of 64 bytes (512 bits).

    Accepts either a ``bytes`` object or a list/iterable of byte values (0–255),
    and returns the padded message as a list of byte values. This matches the
    representation used in ``basic_inv`` and the inverse test suite.
    """
    if isinstance(message, (bytearray, bytes)):
        msg_bytes = bytes(message)
    else:
        # Assume an iterable of ints in 0..255 (as used in the inverse tests).
        msg_bytes = bytes(message)

    padded_bytes = _pad_message(msg_bytes)
    return list(padded_bytes)


def split_into_blocks(padded):
    """Split a padded message into 512-bit (64-byte) blocks.

    The input must already be padded so that its length is a multiple of 64.
    It may be ``bytes`` or a list/iterable of byte values.

    Returns a list of blocks, where each block is a list of 64 byte values
    (ints 0–255). This shape matches what ``inv_split_into_blocks`` in
    ``basic_inv.py`` expects.
    """
    if isinstance(padded, (bytearray, bytes)):
        # Raw bytes: keep as-is for slicing.
        data = list(padded)
    else:
        # Assume a sequence of integers; do not coerce to ``bytes`` so that
        # values outside 0..255 (e.g. range(512)) are still supported.
        data = list(padded)

    if len(data) % 64 != 0:
        raise ValueError(
            f"Padded message length must be a multiple of 64 bytes, got {len(data)}"
        )

    blocks: List[List[int]] = []
    for i in range(0, len(data), 64):
        block = data[i : i + 64]
        blocks.append(list(block))
    return blocks


def finalize_digest(state: tuple[int, int, int, int, int, int, int, int]) -> bytes:
    """Convert a final chaining value H_N into the 32-byte SHA-256 digest."""
    return _finalize_digest_from_state(state)


def load_hash_state(
    H_i: tuple[int, int, int, int, int, int, int, int]
) -> tuple[int, int, int, int, int, int, int, int]:
    """Load the 8-word chaining value H_i into working registers a..h.

    For the standard SHA-256 compression, this is just an unpacking step,
    so the inverse simply re-packs these registers back into a tuple.
    """
    if not isinstance(H_i, tuple) or len(H_i) != 8:
        raise ValueError(
            f"H_i must be a tuple of 8 integers, got {type(H_i)} "
            f"with length {len(H_i) if hasattr(H_i, '__len__') else 'N/A'}"
        )
    return H_i


def init_message_schedule(M_i) -> List[int]:
    """Initialise the message schedule W[0..63] from a 512-bit block M_i.

    ``M_i`` may be ``bytes`` or a list/iterable of byte values. The return
    value is the full 64-word schedule as a list of 32-bit integers. The
    first 16 words correspond directly to the block bytes, matching what
    ``inv_init_message_schedule`` in ``basic_inv.py`` expects.
    """
    if isinstance(M_i, (bytearray, bytes)):
        block = bytes(M_i)
    else:
        block = bytes(M_i)

    if len(block) != 64:
        raise ValueError(f"Expected 64-byte block, got {len(block)}")

    return _build_message_schedule(block)


def expand_message_schedule(w: List[int], rounds: int = 64) -> List[int]:
    """Expand an initial schedule W[0..15] to W[0..(rounds-1)].

    The input ``w`` must contain at least the first 16 words; any additional
    words are ignored for expansion purposes. The returned list has
    exactly ``rounds`` 32-bit words and leaves the original W[0..15] intact.
    """
    if len(w) < 16:
        raise ValueError(
            f"Message schedule must contain at least 16 words, got {len(w)}"
        )

    # Work on a copy so callers can reuse their original list.
    schedule = list(w[:rounds]) + [0] * max(0, rounds - len(w))

    # Ensure the first 16 words are exactly as provided by the caller.
    for i in range(16, rounds):
        s0 = _small_sigma0(schedule[i - 15])
        s1 = _small_sigma1(schedule[i - 2])
        schedule[i] = (schedule[i - 16] + s0 + schedule[i - 7] + s1) & MASK32

    return schedule


def update_hash_state(
    H_i: tuple[int, int, int, int, int, int, int, int],
    a: int,
    b: int,
    c: int,
    d: int,
    e: int,
    f: int,
    g: int,
    h_out: int,
) -> tuple[int, int, int, int, int, int, int, int]:
    """Update the chaining value H_i with the working registers a..h.

    This is the standard SHA-256 post-compression state update:
        H_{i+1}[j] = (H_i[j] + working[j]) mod 2^32
    """
    return _after_compress_round(H_i, a, b, c, d, e, f, g, h_out)


def _before_compress_round(
    block: bytes, state: tuple[int, int, int, int, int, int, int, int]
) -> tuple[tuple[int, int, int, int, int, int, int, int], List[int]]:
    """Prepare inputs for a single compression round.

    This function does everything needed *before* calling `compress64`,
    namely building the message schedule for the given 512-bit block and
    passing through the current hash state.
    """
    # Reuse `_build_message_schedule` for the per-block work.
    schedule = _build_message_schedule(block)
    return state, schedule


def _after_compress_round(
    prev_state: tuple[int, int, int, int, int, int, int, int],
    a: int,
    b: int,
    c: int,
    d: int,
    e: int,
    f: int,
    g: int,
    h_out: int,
) -> tuple[int, int, int, int, int, int, int, int]:
    """Update the hash state after a single `compress64` call."""
    h0, h1, h2, h3, h4, h5, h6, h7 = prev_state

    h0 = (h0 + a) & MASK32
    h1 = (h1 + b) & MASK32
    h2 = (h2 + c) & MASK32
    h3 = (h3 + d) & MASK32
    h4 = (h4 + e) & MASK32
    h5 = (h5 + f) & MASK32
    h6 = (h6 + g) & MASK32
    h7 = (h7 + h_out) & MASK32

    return (h0, h1, h2, h3, h4, h5, h6, h7)


def _finalize_digest_from_state(
    state: tuple[int, int, int, int, int, int, int, int]
) -> bytes:
    """Convert the final hash state into the 32-byte SHA-256 digest."""
    return b"".join(word.to_bytes(4, byteorder="big") for word in state)


def sha256_before(
    data: bytes,
) -> tuple[tuple[int, int, int, int, int, int, int, int], List[List[int]]]:
    """High-level helper that prepares all inputs needed before compression.

    This performs:
    - Initialization of the SHA-256 state (H0..H7).
    - Padding of the message.
    - Splitting into 512-bit blocks.
    - Building the 64-word message schedule for each block.

    It returns:
    - The initial 8-word state, and
    - A list of message schedules, one per 512-bit block.

    With this, you can implement your own custom compression pipeline, e.g.:

        state0, schedules = sha256_before(data)
        state = state0
        for ws in schedules:
            state = my_special_compress64(state, ws)
        digest = sha256_after(state)
    """
    # Initial hash state (H0..H7).
    state: tuple[int, int, int, int, int, int, int, int] = tuple(_H0)

    padded = _pad_message(data)

    schedules: List[List[int]] = []
    for block in _chunks(padded, 64):
        # `_before_compress_round` creates the per-block schedule.
        _, ws = _before_compress_round(block, state)
        schedules.append(ws)

    return state, schedules


def sha256_before_bits(
    message_bytes: bytes,
    length_bits: int,
) -> tuple[tuple[int, int, int, int, int, int, int, int], List[List[int]]]:
    """High-level helper for bit-level messages.
    
    Like sha256_before, but supports non-byte-aligned messages where the
    actual message length in bits may be less than len(message_bytes) * 8.

    Args:
        message_bytes: The message bytes (may have unused bits in last byte)
        length_bits: The actual message length in bits

    Returns:
        - The initial 8-word state, and
        - A list of message schedules, one per 512-bit block.
    """
    state: tuple[int, int, int, int, int, int, int, int] = tuple(_H0)

    padded = _pad_message_bits(message_bytes, length_bits)

    schedules: List[List[int]] = []
    for block in _chunks(padded, 64):
        _, ws = _before_compress_round(block, state)
        schedules.append(ws)

    return state, schedules


def sha256_after(
    final_state: tuple[int, int, int, int, int, int, int, int]
) -> bytes:
    """High-level helper that finalizes the digest from a final SHA-256 state.

    This function assumes that `final_state` is the 8-word state obtained
    after running your compression pipeline (e.g. a custom `compress64`
    implementation) starting from the initial state returned by
    `sha256_before`.
    """
    return _finalize_digest_from_state(final_state)


def sha256(data: bytes) -> bytes:
    """Compute the SHA-256 digest of `data` using `compress64`.

    High-level flow:

    1. Call a helper that does all work *before* each `compress64` call.
    2. Call `compress64` for each block.
    3. Call a helper that does all work *after* each `compress64` call and
       finally convert the resulting state into the digest.
    """
    # Step 1: perform all work before compression for the full message.
    state, schedules = sha256_before(data)

    # Step 2/3: for each block schedule, call `compress64` followed by the
    # post-processing helper to update the running state.
    for ws in schedules:
        state_args = state

        # Step 2b: call the compression function itself.
        a, b, c, d, e, f, g, h_out = compress64(*state_args, ws)

        # Step 3: perform all post-`compress64` work for this block
        # by updating the running hash state.
        state = _after_compress_round(state, a, b, c, d, e, f, g, h_out)

    # Finalize and return the digest from the final state.
    return sha256_after(state)


def sha256_with_h_tracking(
    data: bytes,
) -> tuple[bytes, List[List[int]]]:
    """Compute SHA-256 while tracking h register values at each round.
    
    Returns:
        (digest, h_values_per_block)
        where h_values_per_block[block_idx] is a list of 64 h values for that block
    """
    state, schedules = sha256_before(data)
    all_h_values: List[List[int]] = []

    for ws in schedules:
        result = compress64(*state, ws, track_h=True)
        work_out, h_values = result
        all_h_values.append(h_values)
        state = _after_compress_round(state, *work_out)

    return sha256_after(state), all_h_values


def sha256_bits(message_bytes: bytes, length_bits: int) -> bytes:
    """Compute SHA-256 for a message with explicit bit length.
    
    Supports non-byte-aligned messages where the actual message length
    in bits may be less than len(message_bytes) * 8.
    """
    state, schedules = sha256_before_bits(message_bytes, length_bits)

    for ws in schedules:
        a, b, c, d, e, f, g, h_out = compress64(*state, ws)
        state = _after_compress_round(state, a, b, c, d, e, f, g, h_out)

    return sha256_after(state)


def sha256_bits_with_h_tracking(
    message_bytes: bytes,
    length_bits: int,
) -> tuple[bytes, List[List[int]]]:
    """Compute SHA-256 for bit-level message while tracking h values.
    
    Args:
        message_bytes: The message bytes (may have unused bits in last byte)
        length_bits: The actual message length in bits
    
    Returns:
        (digest, h_values_per_block)
        where h_values_per_block[block_idx] is a list of 64 h values for that block
    """
    state, schedules = sha256_before_bits(message_bytes, length_bits)
    all_h_values: List[List[int]] = []

    for ws in schedules:
        result = compress64(*state, ws, track_h=True)
        work_out, h_values = result
        all_h_values.append(h_values)
        state = _after_compress_round(state, *work_out)

    return sha256_after(state), all_h_values


def _hexdigest(data: bytes) -> str:
    """Convenience helper to return the SHA-256 hex digest of `data`."""
    return sha256(data).hex()


def main(argv: list[str] | None = None) -> int:
    """CLI entry point.

    Usage:
        python sha256_cli.py "message"
        python sha256_cli.py -f path/to/file

    Without flags, the single argument is interpreted as a UTF-8 string and
    hashed. With `-f`, the following argument is treated as a filename whose
    raw bytes are hashed. The resulting hex digest is printed to stdout.
    """
    if argv is None:
        argv = sys.argv[1:]

    if not argv:
        sys.stderr.write(
            "Usage:\n"
            "  python sha256_cli.py \"message\"\n"
            "  python sha256_cli.py -f path/to/file\n"
        )
        return 1

    # File mode: `-f <filename>`
    if argv[0] == "-f":
        if len(argv) != 2:
            sys.stderr.write("Usage: python sha256_cli.py -f path/to/file\n")
            return 1
        filename = argv[1]
        try:
            with open(filename, "rb") as f:
                data = f.read()
        except OSError as e:
            sys.stderr.write(f"Error reading file '{filename}': {e}\n")
            return 1
        digest_hex = _hexdigest(data)
        print(digest_hex)
        return 0

    # Default: treat the single argument as a UTF-8 string.
    if len(argv) != 1:
        sys.stderr.write(
            "Usage:\n"
            "  python sha256_cli.py \"message\"\n"
            "  python sha256_cli.py -f path/to/file\n"
        )
        return 1

    message_str = argv[0]
    message_bytes = message_str.encode("utf-8")
    digest_hex = _hexdigest(message_bytes)
    print(digest_hex)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

