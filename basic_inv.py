
#### Utility functions ####


def int2bytes(x, n=4):
	b = [0] * n
	for i in range(n):
		b[i] = x & 0xFF
		x >>= 8
	return b

def bytes2int(bytes):
	s = 0
	l = len(bytes)
	for i in range(l):
		s <<= 8
		s += bytes[l-1-i]
	return s

def bytes2hex(bytes, uc=False):
	digsym = "0123456789abcdef"
	if uc == True:
		digsym = "0123456789ABCDEF"
	l = len(bytes)
	s = ""
	for i in range(l):
		s += digsym[(bytes[i] >> 4) & 0xF]
		s += digsym[bytes[i] & 0xF]
	return s


def lebe(bytes):
	bytes = list(bytes) # copy
	l = len(bytes)
	for i in range(l >> 1):
		bytes[i], bytes[l-1-i] = bytes[l-1-i], bytes[i]
	return bytes

def rotl(d, n):
	return ((d << n) & 0xFFFFFFFF) | (d >> (0x20 - n))

def rotr(d, n):
	return (d >> n) | ((d << (0x20 - n)) & 0xFFFFFFFF)

def rotl64(a, n, l=0x40):
    return ((a >> (l - n)) + (a << n)) & ((1<<l) - 1)



#### Post compression ####

# Inverse standard implementation of post-compression
# Reversing update_hash_state: Hᵢ₊₁ → Hᵢ

def inv_update_hash_state(H_i_plus_1, a, b, c, d, e, f, g, h):
    """
    Inverse update hash state (Level 4)
    
    Input: Hᵢ₊₁:256 bits (8×32-bit words as tuple of integers), 
           a..h:256 bits (8 working 32-bit registers as integers)
    Output: Hᵢ:256 bits (8×32-bit words as tuple of integers)
    
    Reverse the update_hash_state operation by:
    Hᵢ[j] = Hᵢ₊₁[j] - working[j] mod 2³², for j = 0…7
    """
    # Verify H_i_plus_1 is a tuple of 8 integers
    if not isinstance(H_i_plus_1, tuple) or len(H_i_plus_1) != 8:
        raise ValueError(f"H_i_plus_1 must be a tuple of 8 integers, got {type(H_i_plus_1)} with length {len(H_i_plus_1) if hasattr(H_i_plus_1, '__len__') else 'N/A'}")
    
    # Verify all H_i_plus_1 values are 32-bit integers
    for j, h_val in enumerate(H_i_plus_1):
        if not isinstance(h_val, int):
            raise ValueError(f"H_i_plus_1 word {j} is not an integer: {type(h_val)}")
        if h_val < 0 or h_val > 0xFFFFFFFF:
            raise ValueError(f"H_i_plus_1 word {j} is out of 32-bit range: {h_val}")
    
    # Verify all working registers are 32-bit integers
    for name, value in [('a', a), ('b', b), ('c', c), ('d', d), 
                        ('e', e), ('f', f), ('g', g), ('h', h)]:
        if not isinstance(value, int):
            raise ValueError(f"Register {name} is not an integer: {type(value)}")
        if value < 0 or value > 0xFFFFFFFF:
            raise ValueError(f"Register {name} is out of 32-bit range: {value}")
    
    h0, h1, h2, h3, h4, h5, h6, h7 = H_i_plus_1
    h0 = (h0 - a) & 0xFFFFFFFF
    h1 = (h1 - b) & 0xFFFFFFFF
    h2 = (h2 - c) & 0xFFFFFFFF
    h3 = (h3 - d) & 0xFFFFFFFF
    h4 = (h4 - e) & 0xFFFFFFFF
    h5 = (h5 - f) & 0xFFFFFFFF
    h6 = (h6 - g) & 0xFFFFFFFF
    h7 = (h7 - h) & 0xFFFFFFFF
    
    return (h0, h1, h2, h3, h4, h5, h6, h7)


#### Pre compression ####

def inv_load_hash_state(a, b, c, d, e, f, g, h):
    """
    Inverse load hash state (Level 4)
    
    Input: a..h:256 bits (8 working 32-bit registers as integers)
    Output: Hᵢ:256 bits (8×32-bit words as tuple of integers)
    
    Reverse the load_hash_state operation by packing the 8 working registers
    back into a tuple representing Hᵢ.
    """
    # Verify all values are 32-bit integers
    for name, value in [('a', a), ('b', b), ('c', c), ('d', d), 
                        ('e', e), ('f', f), ('g', g), ('h', h)]:
        if not isinstance(value, int):
            raise ValueError(f"Register {name} is not an integer: {type(value)}")
        if value < 0 or value > 0xFFFFFFFF:
            raise ValueError(f"Register {name} is out of 32-bit range: {value}")
    
    H_i = (a, b, c, d, e, f, g, h)
    return H_i

def inv_init_message_schedule(w):
    """
    Inverse init message schedule (Level 4)
    
    Input: W₀..W₁₅:512 bits (16×32-bit words as list of integers)
    Output: Mᵢ:512 bits (512-bit block as bytes)
    
    Reverse the init_message_schedule operation by:
    1. Taking the first 16 words (W[0..15])
    2. Converting each word to 4 bytes using int2bytes
    3. Applying lebe() to reverse the byte order swap
    4. Concatenating all bytes to reconstruct Mᵢ
    """
    if not isinstance(w, (list, tuple)):
        raise ValueError(f"Input must be a list or tuple, got {type(w)}")
    
    if len(w) < 0x10:
        raise ValueError(f"Input must contain at least 16 words (W[0..15]), got {len(w)} words")
    
    # Extract first 16 words
    M_i = []
    for j in range(0x10):
        word = w[j]
        
        # Verify word is a 32-bit integer
        if not isinstance(word, int):
            raise ValueError(f"Word W[{j}] is not an integer: {type(word)}")
        if word < 0 or word > 0xFFFFFFFF:
            raise ValueError(f"Word W[{j}] is out of 32-bit range: {word}")
        
        # Convert word to 4 bytes (little-endian format)
        word_bytes = int2bytes(word, 4)
        
        # Apply lebe() to reverse the byte order swap
        # (lebe is its own inverse)
        swapped_bytes = lebe(word_bytes)
        
        # Append the 4 bytes to M_i
        M_i.extend(swapped_bytes)
    
    return M_i

def inv_expand_message_schedule(w, rounds=64):
    """
    Inverse expand message schedule (Level 4)
    
    Input: W₀..W₆₃:2048 bits (64×32-bit words as list of integers), rounds (default 64)
    Output: W₀..W₁₅:512 bits (first 16 words as list of integers, derived)
    
    Reverse the expand_message_schedule operation by extracting the first 16 words
    from the expanded message schedule. Since expand_message_schedule takes W[0..15]
    as input and expands to W[0..63], the inverse simply returns W[0..15] from the
    expanded schedule.
    """
    if not isinstance(w, (list, tuple)):
        raise ValueError(f"Input must be a list or tuple, got {type(w)}")
    
    # We need at least 16 words to extract W[0..15]
    if len(w) < 0x10:
        raise ValueError(f"Input must contain at least 16 words (W[0..15]), got {len(w)} words")
    
    # Verify all words in the first 16 are 32-bit integers
    for j in range(0x10):
        word = w[j]
        if not isinstance(word, int):
            raise ValueError(f"Word W[{j}] is not an integer: {type(word)}")
        if word < 0 or word > 0xFFFFFFFF:
            raise ValueError(f"Word W[{j}] is out of 32-bit range: {word}")
    
    # Simply return the first 16 words (W[0..15]) from the expanded schedule
    return list(w[:0x10])


#### Message Processing ####

def inv_pad_message(padded_bytes):
    """
    Inverse padding (Level 3)
    
    Input: 512·N bits (padded message as a list/sequence of byte values,
           N = ceil((n+1+64)/512))
    Output: n bits (raw message as a list of byte values)
    
    This is the inverse of ``sha256_cli.pad_message`` / ``_pad_message``,
    which append the original message length in bits as an 8-byte
    big-endian integer.
    """
    # Normalise to a list of ints so slicing works for both bytes and lists.
    padded_list = list(padded_bytes)

    if len(padded_list) < 8:
        raise ValueError("Padded message must be at least 8 bytes (to contain length)")
    
    if len(padded_list) % 64 != 0:
        raise ValueError("Padded message length must be a multiple of 64 bytes (512 bits)")
    
    # Extract the last 8 bytes which contain the original message length in bits
    length_bytes = bytes(padded_list[-8:])
    # _pad_message encodes the length as a big-endian 64-bit integer.
    msglen_bits = int.from_bytes(length_bytes, byteorder="big")
    
    # Calculate original message length in bytes
    # Since msglen_bits = len(original_bytes) << 3, we can recover it with:
    original_length_bytes = msglen_bits >> 3
    
    if original_length_bytes < 0:
        raise ValueError("Invalid message length: negative")
    
    if original_length_bytes > len(padded_list) - 8:
        raise ValueError(
            f"Invalid message length: {original_length_bytes} bytes exceeds available "
            f"{len(padded_list) - 8} bytes"
        )
    
    # Extract the original message (first N bytes) and return as a list[int]
    original_bytes = padded_list[:original_length_bytes]
    
    return original_bytes

def inv_split_into_blocks(blocks):
    """
    Inverse block splitting (Level 3)
    
    Input: N blocks × 512 bits (list of 512-bit blocks M₀…Mₙ₋₁ as bytes)
    Output: 512·N bits (padded message as bytes)
    
    Reverse the block splitting operation by concatenating all blocks back together.

    Note: this function only guarantees that concatenating 64-byte blocks produces a
    bytestream whose length is a multiple of 64. For the resulting list to be a
    *valid SHA-256 padded message* that `inv_pad_message` can successfully invert,
    the concatenation must also satisfy the standard padding constraints:
      - The last 8 bytes encode the original message length in bits as a 64-bit
        big-endian integer L, with 0 <= L < 2**64 and L a multiple of 8.
      - The padding bytes immediately before this length field follow the
        `0x80 || 0x00*` pattern.
    It is the caller's responsibility to ensure these semantic constraints; this
    helper does not modify block contents to enforce them.
    """
    if not blocks:
        return []
    
    # Validate that all blocks are 64 bytes (512 bits)
    for i, block in enumerate(blocks):
        if len(block) != 64:
            raise ValueError(f"Block {i} has invalid length {len(block)} bytes (expected 64 bytes / 512 bits)")
    
    # Concatenate all blocks
    padded_bytes = []
    for block in blocks:
        padded_bytes.extend(block)
    
    return padded_bytes


#### Finalization ####

# Inverse standard implementation of finalization
# Reversing finalize_digest: Digest input → Final chaining value

def inv_finalize_digest(digest_bytes):
    """
    Inverse finalization (Level 3)
    
    Input: 256 bits (digest as bytes)
    Output: H_N:256 bits (8×32-bit words as tuple of integers)
    
    Reverse the finalization operation by:
    1. Splitting the 32-byte digest into 8 chunks of 4 bytes each
    2. Reversing each chunk's byte order (big-endian → little-endian)
    3. Converting each chunk back to a 32-bit integer
    """
    if len(digest_bytes) != 32:
        raise ValueError(f"Digest must be exactly 32 bytes (256 bits), got {len(digest_bytes)} bytes")
    
    # Split digest into 8 chunks of 4 bytes each
    h0_bytes = digest_bytes[0:4]
    h1_bytes = digest_bytes[4:8]
    h2_bytes = digest_bytes[8:12]
    h3_bytes = digest_bytes[12:16]
    h4_bytes = digest_bytes[16:20]
    h5_bytes = digest_bytes[20:24]
    h6_bytes = digest_bytes[24:28]
    h7_bytes = digest_bytes[28:32]
    
    # Reverse each chunk's byte order (big-endian → little-endian)
    # and convert back to integer
    h0 = bytes2int(lebe(h0_bytes))
    h1 = bytes2int(lebe(h1_bytes))
    h2 = bytes2int(lebe(h2_bytes))
    h3 = bytes2int(lebe(h3_bytes))
    h4 = bytes2int(lebe(h4_bytes))
    h5 = bytes2int(lebe(h5_bytes))
    h6 = bytes2int(lebe(h6_bytes))
    h7 = bytes2int(lebe(h7_bytes))
    
    return (h0, h1, h2, h3, h4, h5, h6, h7)


