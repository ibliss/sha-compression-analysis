import pytest

from compress import compression, compress64
from compression_inv import compression_inv, compression64_inv, solve_h_prefix
from sha256_cli import _after_compress_round, sha256_before


K_FINAL = 0xC67178F2  # Final-round constant k[63]


TEST_VECTORS = [
    # All-zero state to check the basic wiring.
    (0, 0, 0, 0, 0, 0, 0, 0, 0),
    # Mixed non-zero values so that all words are distinguishable from 0.
    (1, 2, 3, 4, 5, 6, 7, 8, 0x67452301),
    (
        0x01234567,
        0x89ABCDEF,
        0xDEADBEEF,
        0xCAFEBABE,
        0x0F0F0F0F,
        0xF0F0F0F0,
        0xAAAAAAAA,
        0x55555555,
        0x12345678,
    ),
]


@pytest.mark.parametrize("a,b,c,d,e,f,g,h,w", TEST_VECTORS)
def test_compression_inverse_recovers_all_words(a, b, c, d, e, f, g, h, w):
    """
    Run a forward compression round, then apply compression_inv and assert that
    all *recoverable* pre-round words (a, b, c, d, e, f, g) are perfectly
    recovered.
    """
    # Forward round.
    a_new, b_new, c_new, d_new, e_new, f_new, g_new, h_new = compression(
        a, b, c, d, e, f, g, h, w, K_FINAL
    )

    # Inversion.
    a_prev, b_prev, c_prev, d_prev, e_prev, f_prev, g_prev, h_prev, w_prev = compression_inv(
        a_new, b_new, c_new, d_new, e_new, f_new, g_new, h_new, K_FINAL
    )

    # Expect perfect recovery of all inputs that compression_inv can currently
    # reconstruct exactly.
    assert a_prev == a
    assert b_prev == b
    assert c_prev == c
    assert d_prev == d
    assert e_prev == e
    assert f_prev == f
    assert g_prev == g


@pytest.mark.parametrize("a,b,c,d,e,f,g,h,w", TEST_VECTORS)
def test_compression_inverse_returns_valid_preimage(a, b, c, d, e, f, g, h, w):
    """
    Verify that compression_inv returns a *true* preimage: running compression
    again on its output (with the recovered w) reproduces the original
    post-round state.
    """
    a_new, b_new, c_new, d_new, e_new, f_new, g_new, h_new = compression(
        a, b, c, d, e, f, g, h, w, K_FINAL
    )

    # Invert the round to obtain a candidate preimage and recovered w.
    (
        a_prev,
        b_prev,
        c_prev,
        d_prev,
        e_prev,
        f_prev,
        g_prev,
        h_prev,
        w_prev,
    ) = compression_inv(a_new, b_new, c_new, d_new, e_new, f_new, g_new, h_new, K_FINAL)

    # Re-run the forward compression using the recovered preimage and w.
    (
        a_roundtrip,
        b_roundtrip,
        c_roundtrip,
        d_roundtrip,
        e_roundtrip,
        f_roundtrip,
        g_roundtrip,
        h_roundtrip,
    ) = compression(
        a_prev, b_prev, c_prev, d_prev, e_prev, f_prev, g_prev, h_prev, w_prev, K_FINAL
    )

    # For a true preimage, the recompressed state must match the original
    # post-round state exactly.
    assert a_roundtrip == a_new
    assert b_roundtrip == b_new
    assert c_roundtrip == c_new
    assert d_roundtrip == d_new
    assert e_roundtrip == e_new
    assert f_roundtrip == f_new
    assert g_roundtrip == g_new
    assert h_roundtrip == h_new


@pytest.mark.parametrize("a,b,c,d,e,f,g,h,w", TEST_VECTORS)
def test_compress64_inverse_returns_valid_preimage(a, b, c, d, e, f, g, h, w):
    """
    Verify that compression64_inv returns a *true* preimage for the full
    64-round loop: running compress64 again on its output (with the recovered
    w[0..63]) reproduces the original post-round state.
    """
    # Build a simple but non-trivial 64-word schedule from the scalar w.
    ws = [((w + i * 0x01020304) & 0xFFFFFFFF) for i in range(64)]

    # Forward 64-round compression.
    (
        a_new,
        b_new,
        c_new,
        d_new,
        e_new,
        f_new,
        g_new,
        h_new,
    ) = compress64(a, b, c, d, e, f, g, h, ws)

    # Invert the 64 rounds to obtain a candidate preimage and recovered schedule.
    (
        a_prev,
        b_prev,
        c_prev,
        d_prev,
        e_prev,
        f_prev,
        g_prev,
        h_prev,
        ws_prev,
    ) = compression64_inv(a_new, b_new, c_new, d_new, e_new, f_new, g_new, h_new)

    # Re-run the forward 64-round compression using the recovered preimage and schedule.
    (
        a_roundtrip,
        b_roundtrip,
        c_roundtrip,
        d_roundtrip,
        e_roundtrip,
        f_roundtrip,
        g_roundtrip,
        h_roundtrip,
    ) = compress64(a_prev, b_prev, c_prev, d_prev, e_prev, f_prev, g_prev, h_prev, ws_prev)

    # For a true preimage, the recompressed state must match the original
    # post-round state exactly.
    assert a_roundtrip == a_new
    assert b_roundtrip == b_new
    assert c_roundtrip == c_new
    assert d_roundtrip == d_new
    assert e_roundtrip == e_new
    assert f_roundtrip == f_new
    assert g_roundtrip == g_new
    assert h_roundtrip == h_new


def _forward_block(message: bytes):
    """Return (state, ws, post_state, h_values) for the first block of `message`."""
    state, schedules = sha256_before(message)
    ws = schedules[0]
    post_state = compress64(*state, ws)
    _, h_values = compress64(*state, ws, track_h=True)
    return state, ws, post_state, h_values


def test_solve_h_prefix_recovers_true_prefix():
    """h[4..7] is solved from the endpoint when only h[8..63] is supplied."""
    state, ws, post_state, h_values = _forward_block(b"abc")

    h_full, ws_recovered, endpoint = solve_h_prefix(post_state, h_values[8:], state)

    assert h_full[4:8] == h_values[4:8]
    assert h_full[8:] == h_values[8:]
    assert h_full[:4] == [state[7 - i] for i in range(4)]
    assert endpoint == tuple(state)
    assert ws_recovered == tuple(ws)


def test_compression64_inv_from_h_tail():
    """The inverse needs only h[8..63]: the four prefix words are solved."""
    state, ws, post_state, h_values = _forward_block(b"abc")

    (
        a_prev,
        b_prev,
        c_prev,
        d_prev,
        e_prev,
        f_prev,
        g_prev,
        h_prev,
        ws_recovered,
    ) = compression64_inv(*post_state, h_values=h_values[8:], initial_state=state)

    assert (a_prev, b_prev, c_prev, d_prev, e_prev, f_prev, g_prev, h_prev) == tuple(state)
    assert ws_recovered == tuple(ws)


def test_compression64_inv_from_h_tail_later_block():
    """The pinned prefix is the block's own chaining value, not H(0)."""
    message = b"a" * 100
    assert len(sha256_before(message)[1]) == 2

    state, schedules = sha256_before(message)
    for block_index, ws in enumerate(schedules):
        post_state = compress64(*state, ws)
        _, h_values = compress64(*state, ws, track_h=True)

        (
            a_prev,
            b_prev,
            c_prev,
            d_prev,
            e_prev,
            f_prev,
            g_prev,
            h_prev,
            ws_recovered,
        ) = compression64_inv(*post_state, h_values=h_values[8:], initial_state=state)

        assert (a_prev, b_prev, c_prev, d_prev, e_prev, f_prev, g_prev, h_prev) == tuple(state), block_index
        assert ws_recovered == tuple(ws), block_index
        state = _after_compress_round(state, *post_state)


def test_compression64_inv_h_tail_requires_initial_state():
    state, ws, post_state, h_values = _forward_block(b"abc")
    with pytest.raises(ValueError):
        compression64_inv(*post_state, h_values=h_values[8:])


def test_compression64_inv_h_tail_wrong_length():
    state, ws, post_state, h_values = _forward_block(b"abc")
    with pytest.raises(ValueError):
        compression64_inv(*post_state, h_values=h_values[9:], initial_state=state)


def test_compression64_inv_full_schedule_unchanged():
    """Passing all 64 h values still takes the direct (no-solve) path."""
    state, ws, post_state, h_values = _forward_block(b"abc")
    result = compression64_inv(*post_state, h_values=h_values)
    assert result[:8] == tuple(state)
    assert result[8] == tuple(ws)

