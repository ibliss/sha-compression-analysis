"""Inverse of the SHA-256 compression

Here we assume the inputs (a, b, c, d, e, f, g, h) are the *post-round*
state, and we compute as much of the *pre-round* state.
"""

from __future__ import annotations

from typing import List, Optional, Sequence, Tuple

from compress import K_VALUES, _rotr, compression

from sha256_cli import _H0, expand_message_schedule

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


# ---------------------------------------------------------------------------
# Solving the four-word prefix h[4..7] from the endpoint
# ---------------------------------------------------------------------------
#
# The endpoint (the block's pre-round working state, i.e. its chaining value)
# names the four prefix words directly: h[7] shifts a[0], h[6] shifts b[0],
# h[5] shifts c[0], and h[4] shifts d[0], each with slope +1.  The solve is
# therefore triangular: fix h[7] from a[0], then h[6] from b[0], and so on.
# Each correction needs one backward pass, so four unknowns cost five passes
# and no search.

#: The prefix positions the endpoint names, highest index first.
PREFIX_UNKNOWN: Tuple[int, ...] = (4, 5, 6, 7)

#: h[k] enters endpoint word ENDPOINT_WORD[k] with slope +1.
ENDPOINT_WORD = {4: 3, 5: 2, 6: 1, 7: 0}


def _backward_walk(
    post_state: Sequence[int],
    h_values: Sequence[int],
) -> Tuple[Tuple[int, int, int, int, int, int, int, int], Tuple[int, ...]]:
    """One backward pass over 64 rounds with every h value known.

    Returns the recovered pre-round state and ``w[0..63]``.
    """
    if len(h_values) != 64:
        raise ValueError(f"h_values must have exactly 64 elements, got {len(h_values)}")

    a_i, b_i, c_i, d_i, e_i, f_i, g_i, h_i = post_state
    ws_rev: List[int] = []
    for i in reversed(range(64)):
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
        ) = compression_inv(
            a_i, b_i, c_i, d_i, e_i, f_i, g_i, h_i, K_VALUES[i], known_h_prev=h_values[i]
        )
        ws_rev.append(w_i)

    state = (
        a_i & MASK32,
        b_i & MASK32,
        c_i & MASK32,
        d_i & MASK32,
        e_i & MASK32,
        f_i & MASK32,
        g_i & MASK32,
        h_i & MASK32,
    )
    return state, tuple(reversed(ws_rev))


def solve_h_prefix(
    post_state: Sequence[int],
    h_tail: Sequence[int],
    initial_state: Sequence[int],
    unknown: Sequence[int] = PREFIX_UNKNOWN,
) -> Tuple[List[int], Tuple[int, ...], Tuple[int, ...]]:
    """Solve any subset of ``h[4..7]`` from the endpoint.

    Parameters
    ----------
    post_state : Sequence[int]
        The 8-word state after round 63.
    h_tail : Sequence[int]
        ``h[8..63]`` (56 words).  ``h[0..3]`` are the block's chaining value,
        reversed, and are filled in from ``initial_state``.
    initial_state : Sequence[int]
        The block's pre-round chaining value (8 words).  This is the endpoint
        the walk must land on; for the first block of a message it is ``H(0)``,
        and for a later block it is the previous chaining value.
    unknown : Sequence[int], optional
        Which prefix words to solve, a subset of ``{4, 5, 6, 7}``.

    Returns
    -------
    (h_values, ws, endpoint) : tuple
        The full 64-word h schedule, the recovered message schedule, and the
        endpoint the walk landed on.
    """
    post_state = tuple(int(word) & MASK32 for word in post_state)
    initial_state = tuple(int(word) & MASK32 for word in initial_state)
    h_tail = [int(word) & MASK32 for word in h_tail]
    if len(post_state) != 8:
        raise ValueError(f"post_state must have 8 words, got {len(post_state)}")
    if len(initial_state) != 8:
        raise ValueError(f"initial_state must have 8 words, got {len(initial_state)}")
    if len(h_tail) != 56:
        raise ValueError(f"h_tail must supply h[8..63] (56 words), got {len(h_tail)}")

    positions = tuple(sorted(set(int(index) for index in unknown)))
    if not set(positions) <= set(PREFIX_UNKNOWN):
        raise ValueError(f"unknown must be a subset of {PREFIX_UNKNOWN}; got {positions}")

    h_values = [0] * 64
    for index in range(4):
        h_values[index] = initial_state[7 - index] & MASK32
    for offset, value in enumerate(h_tail):
        h_values[8 + offset] = value
    for index in positions:
        h_values[index] = 0

    # One pass per unknown, highest first: each correction is a single
    # subtraction from the endpoint word that unknown moves.
    for index in reversed(positions):
        state, _ws = _backward_walk(post_state, h_values)
        word = ENDPOINT_WORD[index]
        h_values[index] = (initial_state[word] - state[word]) & MASK32

    endpoint, ws = _backward_walk(post_state, h_values)
    return h_values, ws, endpoint


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
    initial_state: Optional[Sequence[int]] = None,
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
        If provided, either 64 h register values (one per round) or the 56
        values ``h[8..63]``.  ``h_values[i]`` is the h register at the START of
        round i in the forward direction.  With 64 words the walk is exact.
        With 56 words the four prefix words ``h[4..7]`` are solved from the
        endpoint instead, which requires ``initial_state``.
    initial_state : Sequence[int], optional
        The block's pre-round chaining value (8 words).  Required when
        ``h_values`` supplies only ``h[8..63]``; it is the endpoint the prefix
        solve lands on.

    Returns
    -------
    (a, b, c, d, e, f, g, h, ws) : tuple
        The recovered pre-compression state and the 64-word message schedule.

    This mirrors ``compress64`` in ``compress.py``.
    """
    post_state = (a, b, c, d, e, f, g, h)

    if h_values is None:
        h_full: Optional[List[int]] = None
    else:
        h_list = [int(word) & MASK32 for word in h_values]
        if len(h_list) == 64:
            h_full = h_list
        elif len(h_list) == 56:
            if initial_state is None:
                raise ValueError(
                    "initial_state is required when h_values supplies only h[8..63]"
                )
            _h_full, ws_solved, endpoint = solve_h_prefix(
                post_state, h_list, initial_state
            )
            return (*endpoint, ws_solved)
        else:
            raise ValueError(
                "h_values must supply h[0..63] (64 words) or h[8..63] (56 words), "
                f"got {len(h_list)}"
            )

    # We'll accumulate recovered w[i] from the end backwards.
    ws_rev: List[int] = []

    a_i, b_i, c_i, d_i, e_i, f_i, g_i, h_i = a, b, c, d, e, f, g, h
    for i in reversed(range(64)):
        # Get the known h_prev for this round if provided
        known_h = h_full[i] if h_full is not None else None
        
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


def recover_from_h_4_19(
    initial_state: Sequence[int],
    h_mid: Sequence[int],
) -> Tuple[List[int], Tuple[int, ...], Tuple[int, int, int, int, int, int, int, int]]:
    """Recover a block from its initial state and ``h[4..19]`` only.

    ``h[0..3]`` are the initial state reversed. Rounds 0..15 recover
    ``W[0..15]`` by subtraction, because ``h[i+4]`` is known. The message
    schedule then gives ``W[16..63]``, and the forward walk reads off
    ``h[20..63]`` and the final working state.

    The final working state, ``h[0..3]``, and ``h[20..63]`` are not inputs.
    ``h_mid`` must be exactly 16 words.
    """
    initial = tuple(int(word) & MASK32 for word in initial_state)
    mid = [int(word) & MASK32 for word in h_mid]
    if len(initial) != 8:
        raise ValueError(f"initial_state must have 8 words, got {len(initial)}")
    if len(mid) != 16:
        raise ValueError(f"h_mid must supply h[4..19] (16 words), got {len(mid)}")

    h_known = [initial[7 - index] for index in range(4)] + mid

    state = initial
    ws_prefix: List[int] = []
    for index in range(16):
        a, b, c, d, e, f, g, h_reg = state
        sigma1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)
        ch = (e & f) ^ ((~e) & g)
        w = (h_known[index + 4] - d - h_reg - sigma1 - ch - K_VALUES[index]) & MASK32
        ws_prefix.append(w)
        state = compression(a, b, c, d, e, f, g, h_reg, w, K_VALUES[index])

    ws = tuple(expand_message_schedule(ws_prefix))

    h_schedule: List[int] = []
    state = initial
    for index in range(64):
        h_schedule.append(state[7] & MASK32)
        state = compression(*state, ws[index], K_VALUES[index])

    return h_schedule, ws, state

