"""Forward SHA-256 compression (single round).

This implements one iteration of the SHA-256 compression loop as described in
`sha2-compression-operations.md`.

Given the current working state words `(a, b, c, d, e, f, g, h)`, the round
constant `k`, and the message schedule word `w`, this computes:

    S1   = (e >>> 6) ^ (e >>> 11) ^ (e >>> 25)
    ch   = (e & f) ^ (~e & g)
    temp1 = h + S1 + ch + k + w

    S0   = (a >>> 2) ^ (a >>> 13) ^ (a >>> 22)
    maj  = (a & b) ^ (a & c) ^ (b & c)
    temp2 = S0 + maj

    a' = temp1 + temp2
    e' = d + temp1

    b' = a
    c' = b
    d' = c
    f' = e
    g' = f
    h' = g

All additions are performed modulo 2**32, as in SHA-256.
"""

from __future__ import annotations

from typing import Iterable, List, Sequence, Tuple


MASK32 = 0xFFFFFFFF

# Standard SHA-256 round constants k[0..63] from FIPS 180-4.
K_VALUES: Tuple[int, ...] = (
    0x428A2F98,
    0x71374491,
    0xB5C0FBCF,
    0xE9B5DBA5,
    0x3956C25B,
    0x59F111F1,
    0x923F82A4,
    0xAB1C5ED5,
    0xD807AA98,
    0x12835B01,
    0x243185BE,
    0x550C7DC3,
    0x72BE5D74,
    0x80DEB1FE,
    0x9BDC06A7,
    0xC19BF174,
    0xE49B69C1,
    0xEFBE4786,
    0x0FC19DC6,
    0x240CA1CC,
    0x2DE92C6F,
    0x4A7484AA,
    0x5CB0A9DC,
    0x76F988DA,
    0x983E5152,
    0xA831C66D,
    0xB00327C8,
    0xBF597FC7,
    0xC6E00BF3,
    0xD5A79147,
    0x06CA6351,
    0x14292967,
    0x27B70A85,
    0x2E1B2138,
    0x4D2C6DFC,
    0x53380D13,
    0x650A7354,
    0x766A0ABB,
    0x81C2C92E,
    0x92722C85,
    0xA2BFE8A1,
    0xA81A664B,
    0xC24B8B70,
    0xC76C51A3,
    0xD192E819,
    0xD6990624,
    0xF40E3585,
    0x106AA070,
    0x19A4C116,
    0x1E376C08,
    0x2748774C,
    0x34B0BCB5,
    0x391C0CB3,
    0x4ED8AA4A,
    0x5B9CCA4F,
    0x682E6FF3,
    0x748F82EE,
    0x78A5636F,
    0x84C87814,
    0x8CC70208,
    0x90BEFFFA,
    0xA4506CEB,
    0xBEF9A3F7,
    0xC67178F2,
)


def _rotr(x: int, n: int) -> int:
    """Right-rotate a 32-bit word `x` by `n` bits."""
    x &= MASK32
    return ((x >> n) | (x << (32 - n))) & MASK32


def compression(
    a: int,
    b: int,
    c: int,
    d: int,
    e: int,
    f: int,
    g: int,
    h: int,
    w: int,
    k: int,
) -> Tuple[int, int, int, int, int, int, int, int]:
    """Perform one SHA-256 compression round.

    Parameters
    ----------
    a, b, c, d, e, f, g, h : int
        32-bit words representing the current working state.
    w : int
        Message schedule word `w[i]`.
    k : int
        Round constant `k[i]` (e.g., the final-round constant 0xC67178F2).

    Returns
    -------
    (a_new, b_new, c_new, d_new, e_new, f_new, g_new, h_new) : tuple[int, ...]
        Updated working state after one compression round, all reduced modulo 2**32.
    """
    a &= MASK32
    b &= MASK32
    c &= MASK32
    d &= MASK32
    e &= MASK32
    f &= MASK32
    g &= MASK32
    h &= MASK32
    w &= MASK32
    k &= MASK32

    # 1. Compute S1(e)
    S1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)

    # 2. Compute ch(e, f, g)
    ch = (e & f) ^ ((~e) & g)

    # 3. Compute temp1 using the supplied round constant k
    temp1 = (h + S1 + ch + k + w) & MASK32

    # 4. Compute S0(a)
    S0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)

    # 5. Compute maj(a, b, c)
    maj = (a & b) ^ (a & c) ^ (b & c)

    # 6. Compute temp2
    temp2 = (S0 + maj) & MASK32

    # 7. Update state words
    a_new = (temp1 + temp2) & MASK32
    e_new = (d + temp1) & MASK32

    h_new = g
    g_new = f
    f_new = e
    d_new = c
    c_new = b
    b_new = a

    return (
        a_new & MASK32,
        b_new & MASK32,
        c_new & MASK32,
        d_new & MASK32,
        e_new & MASK32,
        f_new & MASK32,
        g_new & MASK32,
        h_new & MASK32,
    )


def compress64(
    a: int,
    b: int,
    c: int,
    d: int,
    e: int,
    f: int,
    g: int,
    h: int,
    ws: Sequence[int],
) -> Tuple[int, int, int, int, int, int, int, int]:
    """Run the full 64-round SHA-256 compression loop for one block.

    Parameters
    ----------
    a, b, c, d, e, f, g, h : int
        Initial working state words (typically the current hash value).
    ws : Sequence[int]
        The 64-word message schedule `w[0..63]` for this block.

    Returns
    -------
    (a, b, c, d, e, f, g, h) : tuple[int, ...]
        Final working state words after 64 rounds.
    """
    if len(ws) != 64:
        raise ValueError(f"compress64 expects 64 message schedule words, got {len(ws)}")

    a_, b_, c_, d_, e_, f_, g_, h_ = a, b, c, d, e, f, g, h
    for i in range(64):
        a_, b_, c_, d_, e_, f_, g_, h_ = compression(
            a_,
            b_,
            c_,
            d_,
            e_,
            f_,
            g_,
            h_,
            ws[i],
            K_VALUES[i],
        )

    return a_ & MASK32, b_ & MASK32, c_ & MASK32, d_ & MASK32, e_ & MASK32, f_ & MASK32, g_ & MASK32, h_ & MASK32

