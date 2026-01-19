import pytest

from compress import compression, compress64
from compression_inv import compression_inv, compression64_inv


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

