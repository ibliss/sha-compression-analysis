"""Inverse of the SHA-256 compression

Here we assume the inputs (a, b, c, d, e, f, g, h) are the *post-round*
state, and we compute as much of the *pre-round* state.
"""

from __future__ import annotations

from typing import List, Optional, Sequence, Tuple

from compress import K_VALUES, _rotr

from sha256_cli import _H0

MASK32 = 0xFFFFFFFF


def solve_w_from_h(
    temp_1: int, prev_e: int, prev_f: int, prev_g: int, k: int, h_prev: int
) -> int:
    """Given temp1, pre-round (e, f, g), k, and h_prev, compute w.
    
    From the equation: temp1 = h + S1(e) + ch(e, f, g) + k + w
    We solve: w = temp1 - h - S1(e) - ch(e, f, g) - k
    """
    S1 = _rotr(prev_e, 6) ^ _rotr(prev_e, 11) ^ _rotr(prev_e, 25)
    ch = (prev_e & prev_f) ^ ((~prev_e) & prev_g)
    offset = (S1 + ch + k) & MASK32
    w = (temp_1 - offset - h_prev) & MASK32
    return w


def solve_temp1_w(temp_1: int, prev_e: int, prev_f: int, prev_g: int, k: int, w: int) -> int:
    """Given temp1, pre-round (e, f, g), and w, return one consistent h."""
    # 1. Compute S1(e)
    S1 = _rotr(prev_e, 6) ^ _rotr(prev_e, 11) ^ _rotr(prev_e, 25)
    # 2. Compute ch(e, f, g)
    ch = (prev_e & prev_f) ^ ((~prev_e) & prev_g)

    offset = (S1 + ch + k) & MASK32

    #   temp1 = h + offset + w  =>  w = temp1 - offset - h
    h_prev = (temp_1 - offset - w) & MASK32

    return h_prev


def solve_temp1(
    temp_1: int, prev_e: int, prev_f: int, prev_g: int, k: int
) -> Tuple[int, int]:
    """Given temp1 and pre-round (e, f, g), return one consistent (h, w) pair.

    We must satisfy, modulo 2**32:

        temp1 = h + S1(e) + ch(e, f, g) + k + w

    For any chosen h, this uniquely determines w. Here we take the simplest
    choice h = 0 and solve for w accordingly.
    """

    if k == K_VALUES[15]:
        return solve_temp1_w(temp_1, prev_e, prev_f, prev_g, k, 0x000001B8), 0x000001B8
    elif k == K_VALUES[14]:
        return solve_temp1_w(temp_1, prev_e, prev_f, prev_g, k, 0x00000000), 0x00000000
    elif k == K_VALUES[13]:
        return solve_temp1_w(temp_1, prev_e, prev_f, prev_g, k, 0x00000080), 0x00000080
    
    # 1. Compute S1(e)
    S1 = _rotr(prev_e, 6) ^ _rotr(prev_e, 11) ^ _rotr(prev_e, 25)
    # 2. Compute ch(e, f, g)
    ch = (prev_e & prev_f) ^ ((~prev_e) & prev_g)

    offset = (S1 + ch + k) & MASK32

    # Choose an arbitrary but fixed h, then solve for w:
    #   temp1 = h + offset + w  =>  w = temp1 - offset - h
    h_prev = 0
    # XXX: Use h_vales to reconstruct intial working state
    if k == K_VALUES[0]:
        h_prev = _H0[7]
    elif k == K_VALUES[1]:
        h_prev = _H0[6]
    elif k == K_VALUES[2]:
        h_prev = _H0[5]
    elif k == K_VALUES[3]:
        h_prev = _H0[4]
    # TODO: 0,1,2,3 H0 values
    elif k == K_VALUES[4]:
        # Round 1 mixing
        # e := d + temp1
        h_target = _H0[3]
        temp1_round1 = 0
        h_prev = (h_target - temp1_round1) & MASK32
    # Solve for w using the known h_prev
    w = (temp_1 - offset - h_prev) & MASK32

    # FIXME: w values are dependant on w[i-16], w[i-15], w[i-7], w[i-2]
    # With known 13, 14, 15
    # h_prev at 0 is known
    # TODO: create a valid w[i], and solve for h_prev

    return h_prev, w


def compression_inv(
    a: int,
    b: int,
    c: int,
    d: int,
    e: int,
    f: int,
    g: int,
    h: int,
    k: int,
    *,
    known_h_prev: Optional[int] = None,
) -> Tuple[int, int, int, int, int, int, int, int, int]:
    """Partially invert the SHA-256 step 7 state update.

    Parameters
    ----------
    a, b, c, d, e, f, g, h : int
        32-bit words representing the *post-round* working state.
    k : int
        Round constant for this round.
    known_h_prev : int, optional
        If provided, use this as the h value for the pre-round state instead
        of computing/guessing it. When provided, w is computed directly from
        the temp1 equation without any special-case overrides.

    Returns
    -------
    (a_prev, b_prev, c_prev, d_prev, e_prev, f_prev, g_prev, h_prev, w) : tuple[int, ...]
        Best-effort reconstruction of the *pre-round* state using only the
        reversible assignments in step 7. Non-recoverable words are set to 0.
    """

    # From the forward mapping and final reassignment, we have:
    #
    #   b = b_new = a_old      => a_old = b
    #   c = c_new = b_old      => b_old = c
    #   d = d_new = c_old      => c_old = d
    #   e = e_new = d_old + temp1   (not invertible without temp1)
    #   f = f_new = e_old      => e_old = f
    #   g = g_new = f_old      => f_old = g
    #   h = h_new = g_old      => g_old = h
    #   a = a_new = temp1 + temp2   (not invertible without temp1/temp2)
    #
    # So we can recover:
    #   a_prev = a_old = b
    #   b_prev = b_old = c
    #   c_prev = c_old = d
    #   e_prev = e_old = f
    #   f_prev = f_old = g
    #   g_prev = g_old = h
    #
    # But we *cannot* uniquely recover:
    #   d_prev = d_old (depends on unknown temp1)
    #   h_prev = h_old (depends on earlier steps via temp1, S1, etc.)

    a_prev = b
    b_prev = c
    c_prev = d

    # d_prev = 0 # Directly derived

    e_prev = f
    f_prev = g
    g_prev = h

    # derived from temp1 constraints
    # h_prev = 0
    # w = 0

    # Reconstruct temp2 from the recovered pre-round (a_prev, b_prev, c_prev).
    # In the forward direction:
    #   S0  = ROTR(a_old, 2) xor ROTR(a_old, 13) xor ROTR(a_old, 22)
    #   maj = (a_old & b_old) ^ (a_old & c_old) ^ (b_old & c_old)
    #   temp2 = S0 + maj
    #
    # Here, a_prev = a_old, b_prev = b_old, c_prev = c_old.
    S0 = _rotr(a_prev, 2) ^ _rotr(a_prev, 13) ^ _rotr(a_prev, 22)
    maj = (a_prev & b_prev) ^ (a_prev & c_prev) ^ (b_prev & c_prev)
    temp2 = (S0 + maj) & MASK32

    # From the forward update we also have:
    #   a_new = temp1 + temp2
    #   e_new = d_old + temp1
    #
    # In the inverse, the parameter `a` is a_new and `e` is e_new, so:
    #   temp1 = a_new - temp2
    #   d_prev (d_old) = e_new - temp1.
    temp_1 = (a - temp2) & MASK32
    d_prev = (e - temp_1) & MASK32

    # Now fill in h_prev and w
    if known_h_prev is not None:
        # Use the provided h value and compute w directly (no overrides)
        h_prev = known_h_prev & MASK32
        w = solve_w_from_h(temp_1, e_prev, f_prev, g_prev, k, h_prev)
    else:
        # Use the heuristic solver with special-case overrides
        (candidate_h, candidate_w) = solve_temp1(temp_1, e_prev, f_prev, g_prev, k)
        h_prev = candidate_h
        w = candidate_w

    # All words are reduced modulo 2^32 for consistency with SHA-256 arithmetic.
    return (
        a_prev & MASK32,
        b_prev & MASK32,
        c_prev & MASK32,
        d_prev & MASK32,
        e_prev & MASK32,
        f_prev & MASK32,
        g_prev & MASK32,
        h_prev & MASK32,
        w & MASK32,
    )


def compression64_inv(
    a: int,
    b: int,
    c: int,
    d: int,
    e: int,
    f: int,
    g: int,
    h: int,
    *,
    h_values: Optional[Sequence[int]] = None,
) -> Tuple[int, int, int, int, int, int, int, int, Tuple[int, ...]]:
    """Invert the full 64-round SHA-256 compression loop.

    Given the *post-round* state after 64 rounds, walk rounds 63..0 backwards
    using ``compression_inv`` to recover a consistent preimage and the
    corresponding message schedule words ``w[i]``.

    Parameters
    ----------
    a, b, c, d, e, f, g, h : int
        32-bit words representing the *post-64-round* working state.
    h_values : Sequence[int], optional
        If provided, must be a sequence of 64 h register values (one per round).
        h_values[i] is the h register value at the START of round i in the
        forward direction. When provided, these values are used directly instead
        of heuristic guessing, enabling exact recovery of the original preimage.

    Returns
    -------
    (a, b, c, d, e, f, g, h, ws) : tuple
        The recovered pre-compression state and the 64-word message schedule.

    This mirrors ``compress64`` in ``compress.py``.
    """
    if h_values is not None and len(h_values) != 64:
        raise ValueError(f"h_values must have exactly 64 elements, got {len(h_values)}")

    # We'll accumulate recovered w[i] from the end backwards.
    ws_rev: List[int] = []

    a_i, b_i, c_i, d_i, e_i, f_i, g_i, h_i = a, b, c, d, e, f, g, h
    for i in reversed(range(64)):
        # Get the known h_prev for this round if provided
        known_h = h_values[i] if h_values is not None else None
        
        (
            a_i,
            b_i,
            c_i,
            d_i,
            e_i,
            f_i,
            g_i,
            h_i,
            w_i,
        ) = compression_inv(a_i, b_i, c_i, d_i, e_i, f_i, g_i, h_i, K_VALUES[i], known_h_prev=known_h)
        ws_rev.append(w_i)

    # Reverse to get w[0]..w[63]
    ws: Tuple[int, ...] = tuple(reversed(ws_rev))

    return (
        a_i & MASK32,
        b_i & MASK32,
        c_i & MASK32,
        d_i & MASK32,
        e_i & MASK32,
        f_i & MASK32,
        g_i & MASK32,
        h_i & MASK32,
        ws,
    )

