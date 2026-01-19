#!/usr/bin/env python3
"""
Test suite for inverse operations
Tests that standard operations can be reversed correctly
"""

import sys
import traceback
from pathlib import Path

# Add src directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))


def _import_message_processing():
    """
    Helper function that exposes forward + inverse message-processing
    operations backed by our local modules.

    Forward operations come from `sha256_cli`, inverse operations from
    `basic_inv`.  The returned object provides the attributes:
        - pad_message
        - inv_pad_message
        - split_into_blocks
        - inv_split_into_blocks
    """
    import importlib

    sha256_cli = importlib.import_module('sha256_cli')
    basic_inv = importlib.import_module('basic_inv')

    class MessageProcessing:
        pad_message = staticmethod(sha256_cli.pad_message)
        split_into_blocks = staticmethod(sha256_cli.split_into_blocks)
        inv_pad_message = staticmethod(basic_inv.inv_pad_message)
        inv_split_into_blocks = staticmethod(basic_inv.inv_split_into_blocks)

    return MessageProcessing


def _ensure_list(data):
    """Convert bytes to list if needed, otherwise return as-is."""
    if isinstance(data, bytes):
        return list(data)
    return data


def _run_round_trip_tests(test_name, test_cases, test_func):
    """
    Generic test runner for round-trip tests.
    
    Args:
        test_name: Name of the test (for output messages)
        test_cases: List of test case inputs
        test_func: Function that takes (test_case, index) and returns True,
                   (False, error_msg), or raises an exception
    
    Returns:
        True if all tests passed, False otherwise
    """
    passed = 0
    failed = 0
    
    print("  ", end="", flush=True)  # Start the dot line with indentation
    
    for i, test_case in enumerate(test_cases):
        try:
            # Convert to list if it's bytes
            test_case = _ensure_list(test_case)
            
            # Run the test function
            result = test_func(test_case, i)
            
            if isinstance(result, tuple):
                # test_func returned (success, error_msg)
                success, error_msg = result
                if not success:
                    print("F", end="", flush=True)
                    print(f"\n[FAIL] Test case {i+1}: {error_msg}")
                    failed += 1
                    continue
            elif result is False:
                # test_func returned False (failure)
                print("F", end="", flush=True)
                print(f"\n[FAIL] Test case {i+1}: Test failed")
                failed += 1
                continue
            
            passed += 1
            print(".", end="", flush=True)  # Dot for passing test
        
        except Exception as e:
            print("E", end="", flush=True)  # E for error
            print(f"\n[FAIL] Test case {i+1} raised exception: {e}")
            traceback.print_exc()
            failed += 1
    
    print()  # New line after dots
    print(f"\n[SUMMARY] {test_name}: {passed} passed, {failed} failed")
    
    if failed == 0:
        print(f"[OK] All {test_name} round-trip tests passed!")
        return True
    else:
        print(f"[FAIL] {failed} {test_name} round-trip tests failed")
        return False


def test_pad_message_inverse():
    """
    Test that pad_message and inv_pad_message are inverse operations.
    
    This test:
    1. Takes an original message
    2. Pads it using pad_message
    3. Unpads it using inv_pad_message
    4. Verifies we get back the original message
    """
    print("Testing pad_message / inv_pad_message round-trip...")
    
    try:
        message_processing = _import_message_processing()
        pad_message = message_processing.pad_message
        inv_pad_message = message_processing.inv_pad_message
    except ImportError as e:
        print(f"[FAIL] Failed to import required modules: {e}")
        traceback.print_exc()
        return False
    
    # Test cases with various message lengths
    test_cases = [
        # Empty message
        [],
        # Single byte
        [0x41],
        # Short message (less than 56 bytes)
        [0x48, 0x65, 0x6C, 0x6C, 0x6F],  # "Hello"
        # Exactly 55 bytes (one byte short of needing padding)
        list(range(55)),
        # Exactly 56 bytes (will need padding to next block)
        list(range(56)),
        # 57 bytes (will need padding)
        list(range(57)),
        # Multiple blocks
        list(range(100)),
        list(range(200)),
        # Edge case: exactly 64 bytes (one full block, but still needs padding)
        list(range(64)),
        # Edge case: exactly 63 bytes
        list(range(63)),
        # Random-looking data
        bytes("The quick brown fox jumps over the lazy dog", encoding='utf-8'),
        bytes("Test message with various characters: !@#$%^&*()", encoding='utf-8'),
    ]
    
    def test_func(original_msg, i):
        # Step 1: Pad the message
        padded = pad_message(original_msg)
        
        # Verify padding properties
        if len(padded) % 64 != 0:
            return (False, f"Padded message length ({len(padded)}) is not a multiple of 64")
        
        # Step 2: Unpad the message
        unpadded = inv_pad_message(padded)
        
        # Step 3: Verify we got back the original
        if unpadded != original_msg:
            error_msg = f"Round-trip failed\n"
            error_msg += f"  Original length: {len(original_msg)} bytes\n"
            error_msg += f"  Unpadded length: {len(unpadded)} bytes\n"
            error_msg += f"  Original (first 20): {original_msg[:20]}\n"
            error_msg += f"  Unpadded (first 20): {unpadded[:20]}"
            return (False, error_msg)
        
        return True
    
    success = _run_round_trip_tests("pad_message/inv_pad_message", test_cases, test_func)
    assert success


def test_split_into_blocks_inverse():
    """
    Test that split_into_blocks and inv_split_into_blocks are inverse operations.
    
    This test:
    1. Takes a padded message (multiple of 64 bytes)
    2. Splits it into blocks using split_into_blocks
    3. Merges it back using inv_split_into_blocks
    4. Verifies we get back the original padded message
    """
    print("Testing split_into_blocks / inv_split_into_blocks round-trip...")
    
    try:
        message_processing = _import_message_processing()
        split_into_blocks = message_processing.split_into_blocks
        inv_split_into_blocks = message_processing.inv_split_into_blocks
    except ImportError as e:
        print(f"[FAIL] Failed to import required modules: {e}")
        traceback.print_exc()
        return False
    
    # Test cases: padded messages (must be multiples of 64 bytes)
    test_cases = [
        # Empty (0 blocks)
        [],
        # Single block (64 bytes)
        list(range(64)),
        # Two blocks (128 bytes)
        list(range(128)),
        # Three blocks (192 bytes)
        list(range(192)),
        # Four blocks (256 bytes)
        list(range(256)),
        # Large number of blocks
        list(range(512)),  # 8 blocks
        list(range(1024)),  # 16 blocks
        # Random-looking data (padded to multiple of 64)
        list(bytes("The quick brown fox jumps over the lazy dog. " * 2, encoding='utf-8')) + [0] * 20,  # 100 bytes -> 128 bytes
    ]
    
    def test_func(original_padded, i):
        # Ensure it's a multiple of 64 bytes (required for split_into_blocks)
        # Note: We normalize test cases to be multiples of 64 for this test
        if len(original_padded) % 64 != 0:
            # Pad to next multiple of 64
            padding_needed = 64 - (len(original_padded) % 64)
            original_padded = original_padded + [0] * padding_needed
        
        # Handle empty case: empty list should remain empty
        if len(original_padded) == 0:
            blocks = split_into_blocks(original_padded)
            if blocks != []:
                return (False, f"Empty input should produce empty blocks, got {len(blocks)} blocks")
            merged = inv_split_into_blocks(blocks)
            if merged != []:
                return (False, f"Empty blocks should produce empty output, got length {len(merged)}")
            return True
        
        # Step 1: Split into blocks
        blocks = split_into_blocks(original_padded)
        
        # Verify block properties
        if not all(len(block) == 64 for block in blocks):
            return (False, "Not all blocks are 64 bytes")
        
        if len(blocks) != len(original_padded) // 64:
            return (False, f"Wrong number of blocks. Expected {len(original_padded) // 64}, got {len(blocks)}")
        
        # Step 2: Merge blocks back
        merged = inv_split_into_blocks(blocks)
        
        # Step 3: Verify we got back the original
        if merged != original_padded:
            error_msg = f"Round-trip failed\n"
            error_msg += f"  Original length: {len(original_padded)} bytes\n"
            error_msg += f"  Merged length: {len(merged)} bytes\n"
            error_msg += f"  Number of blocks: {len(blocks)}"
            if len(original_padded) != len(merged):
                error_msg += f"\n  Length mismatch!"
            else:
                # Find first difference
                for j in range(len(original_padded)):
                    if original_padded[j] != merged[j]:
                        error_msg += f"\n  First difference at byte {j}: original={original_padded[j]}, merged={merged[j]}"
                        break
            return (False, error_msg)
        
        return True
    
    success = _run_round_trip_tests("split_into_blocks/inv_split_into_blocks", test_cases, test_func)
    assert success


def test_full_chain_inverse():
    """
    Test the complete chain: pad -> split -> merge -> unpad
    
    This test validates that the full sequence of operations can be reversed:
    1. Takes an original message
    2. Pads it using pad_message
    3. Splits it into blocks using split_into_blocks
    4. Merges blocks back using inv_split_into_blocks
    5. Unpads it using inv_pad_message
    6. Verifies we get back the original message
    
    This ensures the operations work correctly when chained together.
    """
    print("Testing pre-block chain: pad -> split -> merge -> unpad...")
    
    try:
        message_processing = _import_message_processing()
        pad_message = message_processing.pad_message
        split_into_blocks = message_processing.split_into_blocks
        inv_split_into_blocks = message_processing.inv_split_into_blocks
        inv_pad_message = message_processing.inv_pad_message
    except ImportError as e:
        print(f"[FAIL] Failed to import required modules: {e}")
        traceback.print_exc()
        return False
    
    # Test cases with various message lengths
    test_cases = [
        # Empty message
        [],
        # Single byte
        [0x41],
        # Short message
        [0x48, 0x65, 0x6C, 0x6C, 0x6F],  # "Hello"
        # Edge cases around block boundaries
        list(range(55)),
        list(range(56)),
        list(range(57)),
        list(range(63)),
        list(range(64)),
        # Multiple blocks
        list(range(100)),
        list(range(200)),
        # Text data
        bytes("The quick brown fox jumps over the lazy dog", encoding='utf-8'),
    ]
    
    def test_func(original_msg, i):
        # Step 1: Pad the message
        padded = pad_message(original_msg)
        
        # Step 2: Split into blocks
        blocks = split_into_blocks(padded)
        
        # Step 3: Merge blocks back
        merged = inv_split_into_blocks(blocks)
        
        # Verify merged equals padded
        if merged != padded:
            return (False, f"Block merge failed: merged != padded (lengths: {len(merged)} vs {len(padded)})")
        
        # Step 4: Unpad the message
        unpadded = inv_pad_message(merged)
        
        # Step 5: Verify we got back the original
        if unpadded != original_msg:
            error_msg = f"Full chain round-trip failed\n"
            error_msg += f"  Original length: {len(original_msg)} bytes\n"
            error_msg += f"  Unpadded length: {len(unpadded)} bytes\n"
            error_msg += f"  Original (first 20): {original_msg[:20]}\n"
            error_msg += f"  Unpadded (first 20): {unpadded[:20]}"
            return (False, error_msg)
        
        return True
    
    success = _run_round_trip_tests("pre-block chain (pad->split->merge->unpad)", test_cases, test_func)
    assert success


def _import_finalization():
    """
    Helper function to expose forward + inverse finalization operations.

    - forward: finalize_digest (from `sha256_cli`)
    - inverse: inv_finalize_digest (from `basic_inv`)
    """
    import importlib

    sha256_cli = importlib.import_module('sha256_cli')
    basic_inv = importlib.import_module('basic_inv')

    class Finalization:
        finalize_digest = staticmethod(sha256_cli.finalize_digest)
        inv_finalize_digest = staticmethod(basic_inv.inv_finalize_digest)

    return Finalization


def test_finalize_digest_inverse():
    """
    Test that finalize_digest and inv_finalize_digest are inverse operations.
    
    This test:
    1. Takes a chaining value H_N (8×32-bit words as tuple of integers)
    2. Finalizes it using finalize_digest
    3. Reverses it using inv_finalize_digest
    4. Verifies we get back the original chaining value
    """
    print("Testing finalize_digest / inv_finalize_digest round-trip...")
    
    try:
        finalization = _import_finalization()
        finalize_digest = finalization.finalize_digest
        inv_finalize_digest = finalization.inv_finalize_digest
    except ImportError as e:
        print(f"[FAIL] Failed to import required modules: {e}")
        traceback.print_exc()
        return False
    
    # Test cases: various chaining values (8×32-bit words)
    test_cases = [
        # All zeros
        (0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000),
        # All ones
        (0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF),
        # Sequential values
        (0x01234567, 0x89ABCDEF, 0xFEDCBA98, 0x76543210, 0x11111111, 0x22222222, 0x33333333, 0x44444444),
        # Random-looking values
        (0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19),
        # Edge cases: min and max 32-bit values
        (0x00000000, 0x00000001, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFE, 0xFFFFFFFF, 0x12345678, 0x9ABCDEF0),
        # Typical SHA-256 initial hash values
        (0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19),
        # Mixed patterns
        (0xDEADBEEF, 0xCAFEBABE, 0x12345678, 0x9ABCDEF0, 0x11112222, 0x33334444, 0x55556666, 0x77778888),
    ]
    
    def test_func(H_N, i):
        # Ensure it's a tuple
        if not isinstance(H_N, tuple) or len(H_N) != 8:
            return (False, f"Input must be a tuple of 8 integers, got {type(H_N)} with length {len(H_N) if hasattr(H_N, '__len__') else 'N/A'}")
        
        # Verify all values are 32-bit integers
        for j, h in enumerate(H_N):
            if not isinstance(h, int):
                return (False, f"Word {j} is not an integer: {type(h)}")
            if h < 0 or h > 0xFFFFFFFF:
                return (False, f"Word {j} is out of 32-bit range: {h}")
        
        # Step 1: Finalize the chaining value
        digest = finalize_digest(H_N)
        
        # Verify digest properties
        if len(digest) != 32:
            return (False, f"Digest length is {len(digest)} bytes, expected 32 bytes")
        
        # Step 2: Reverse the finalization
        H_N_recovered = inv_finalize_digest(digest)
        
        # Step 3: Verify we got back the original
        if H_N_recovered != H_N:
            error_msg = f"Round-trip failed\n"
            error_msg += f"  Original: {H_N}\n"
            error_msg += f"  Recovered: {H_N_recovered}\n"
            # Find first difference
            for j in range(8):
                if H_N[j] != H_N_recovered[j]:
                    error_msg += f"  First difference at word {j}: original=0x{H_N[j]:08X}, recovered=0x{H_N_recovered[j]:08X}"
                    break
            return (False, error_msg)
        
        return True
    
    success = _run_round_trip_tests("finalize_digest/inv_finalize_digest", test_cases, test_func)
    assert success


def _import_pre_compression():
    """
    Helper function to expose pre-compression forward + inverse operations.

    Forward operations come from `sha256_cli`, inverse operations from
    `basic_inv`.  Returns a dict with keys:
        - load_hash_state
        - init_message_schedule
        - expand_message_schedule
        - inv_load_hash_state
        - inv_init_message_schedule
        - inv_expand_message_schedule
    """
    import importlib

    sha256_cli = importlib.import_module('sha256_cli')
    basic_inv = importlib.import_module('basic_inv')

    return {
        'load_hash_state': sha256_cli.load_hash_state,
        'init_message_schedule': sha256_cli.init_message_schedule,
        'expand_message_schedule': sha256_cli.expand_message_schedule,
        'inv_load_hash_state': basic_inv.inv_load_hash_state,
        'inv_init_message_schedule': basic_inv.inv_init_message_schedule,
        'inv_expand_message_schedule': basic_inv.inv_expand_message_schedule,
    }


def _import_post_compression():
    """
    Helper function to expose post-compression forward + inverse operations.

    - forward: update_hash_state (from `sha256_cli`)
    - inverse: inv_update_hash_state (from `basic_inv`)
    """
    import importlib

    sha256_cli = importlib.import_module('sha256_cli')
    basic_inv = importlib.import_module('basic_inv')

    return {
        'update_hash_state': sha256_cli.update_hash_state,
        'inv_update_hash_state': basic_inv.inv_update_hash_state,
    }


def test_load_hash_state_inverse():
    """
    Test that load_hash_state and inv_load_hash_state are inverse operations.
    
    This test:
    1. Takes a chaining value H_i (8×32-bit words as tuple of integers)
    2. Loads it using load_hash_state
    3. Reverses it using inv_load_hash_state
    4. Verifies we get back the original chaining value
    """
    print("Testing load_hash_state / inv_load_hash_state round-trip...")
    
    try:
        pre_compression = _import_pre_compression()
        load_hash_state = pre_compression['load_hash_state']
        inv_load_hash_state = pre_compression['inv_load_hash_state']
    except ImportError as e:
        print(f"[FAIL] Failed to import required modules: {e}")
        traceback.print_exc()
        return False
    
    # Test cases: various chaining values (8×32-bit words)
    test_cases = [
        # All zeros
        (0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000),
        # All ones
        (0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF),
        # Sequential values
        (0x01234567, 0x89ABCDEF, 0xFEDCBA98, 0x76543210, 0x11111111, 0x22222222, 0x33333333, 0x44444444),
        # Random-looking values
        (0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19),
        # Edge cases: min and max 32-bit values
        (0x00000000, 0x00000001, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFE, 0xFFFFFFFF, 0x12345678, 0x9ABCDEF0),
        # Typical SHA-256 initial hash values
        (0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19),
        # Mixed patterns
        (0xDEADBEEF, 0xCAFEBABE, 0x12345678, 0x9ABCDEF0, 0x11112222, 0x33334444, 0x55556666, 0x77778888),
    ]
    
    def test_func(H_i, i):
        # Ensure it's a tuple
        if not isinstance(H_i, tuple) or len(H_i) != 8:
            return (False, f"Input must be a tuple of 8 integers, got {type(H_i)} with length {len(H_i) if hasattr(H_i, '__len__') else 'N/A'}")
        
        # Verify all values are 32-bit integers
        for j, h in enumerate(H_i):
            if not isinstance(h, int):
                return (False, f"Word {j} is not an integer: {type(h)}")
            if h < 0 or h > 0xFFFFFFFF:
                return (False, f"Word {j} is out of 32-bit range: {h}")
        
        # Step 1: Load the hash state
        a, b, c, d, e, f, g, h = load_hash_state(H_i)
        
        # Step 2: Reverse the load operation
        H_i_recovered = inv_load_hash_state(a, b, c, d, e, f, g, h)
        
        # Step 3: Verify we got back the original
        if H_i_recovered != H_i:
            error_msg = f"Round-trip failed\n"
            error_msg += f"  Original: {H_i}\n"
            error_msg += f"  Recovered: {H_i_recovered}\n"
            # Find first difference
            for j in range(8):
                if H_i[j] != H_i_recovered[j]:
                    error_msg += f"  First difference at word {j}: original=0x{H_i[j]:08X}, recovered=0x{H_i_recovered[j]:08X}"
                    break
            return (False, error_msg)
        
        return True
    
    success = _run_round_trip_tests("load_hash_state/inv_load_hash_state", test_cases, test_func)
    assert success


def test_init_message_schedule_inverse():
    """
    Test that init_message_schedule and inv_init_message_schedule are inverse operations.
    
    This test:
    1. Takes a 512-bit block M_i (as bytes)
    2. Initializes the message schedule using init_message_schedule
    3. Reverses it using inv_init_message_schedule
    4. Verifies we get back the original block
    """
    print("Testing init_message_schedule / inv_init_message_schedule round-trip...")
    
    try:
        pre_compression = _import_pre_compression()
        init_message_schedule = pre_compression['init_message_schedule']
        inv_init_message_schedule = pre_compression['inv_init_message_schedule']
    except ImportError as e:
        print(f"[FAIL] Failed to import required modules: {e}")
        traceback.print_exc()
        return False
    
    # Test cases: various 512-bit blocks (64 bytes each)
    test_cases = [
        # All zeros
        [0] * 64,
        # All ones
        [0xFF] * 64,
        # Sequential bytes
        list(range(64)),
        # Sequential bytes reversed
        list(range(63, -1, -1)),
        # Pattern: alternating 0x00 and 0xFF
        [0x00 if i % 2 == 0 else 0xFF for i in range(64)],
        # Pattern: incrementing pattern
        [i % 256 for i in range(64)],
        # Random-looking data
        bytes("The quick brown fox jumps over the lazy dog. 1234567890!@#$%", encoding='utf-8')[:64],
        # Edge case: first byte 0x00, last byte 0xFF
        [0x00] + [0x55] * 62 + [0xFF],
        # Pattern: each 4-byte word is 0x01234567
        [0x01, 0x23, 0x45, 0x67] * 16,
    ]
    
    def test_func(M_i, i):
        # Ensure it's a list of bytes
        M_i = _ensure_list(M_i)
        
        # Verify it's exactly 64 bytes (512 bits)
        if len(M_i) != 64:
            # Pad or truncate to 64 bytes for this test
            if len(M_i) < 64:
                M_i = M_i + [0] * (64 - len(M_i))
            else:
                M_i = M_i[:64]
        
        # Verify all values are bytes (0-255)
        for j, byte_val in enumerate(M_i):
            if not isinstance(byte_val, int) or byte_val < 0 or byte_val > 255:
                return (False, f"Byte {j} is not a valid byte value: {byte_val}")
        
        # Step 1: Initialize the message schedule
        w = init_message_schedule(M_i)
        
        # Verify w has at least 16 words
        if len(w) < 0x10:
            return (False, f"Message schedule has {len(w)} words, expected at least 16")
        
        # Step 2: Reverse the init operation
        M_i_recovered = inv_init_message_schedule(w)
        
        # Step 3: Verify we got back the original
        if M_i_recovered != M_i:
            error_msg = f"Round-trip failed\n"
            error_msg += f"  Original length: {len(M_i)} bytes\n"
            error_msg += f"  Recovered length: {len(M_i_recovered)} bytes\n"
            if len(M_i) != len(M_i_recovered):
                error_msg += f"  Length mismatch!"
            else:
                # Find first difference
                for j in range(len(M_i)):
                    if M_i[j] != M_i_recovered[j]:
                        error_msg += f"  First difference at byte {j}: original=0x{M_i[j]:02X}, recovered=0x{M_i_recovered[j]:02X}"
                        break
            return (False, error_msg)
        
        return True
    
    success = _run_round_trip_tests("init_message_schedule/inv_init_message_schedule", test_cases, test_func)
    assert success


def test_pre_compression_chain_inverse():
    """
    Test the complete pre-compression chain: load -> init -> expand -> inv_expand -> inv_init -> inv_load
    
    This test validates that the full sequence of pre-compression operations can be reversed:
    1. Takes a chaining value H_i and a 512-bit block M_i
    2. Loads hash state using load_hash_state
    3. Initializes message schedule using init_message_schedule
    4. Expands message schedule using expand_message_schedule
    5. Reverses expansion using inv_expand_message_schedule
    6. Reverses message schedule using inv_init_message_schedule
    7. Reverses hash state using inv_load_hash_state
    8. Verifies we get back the original H_i and M_i
    
    This ensures the operations work correctly when chained together.
    """
    print("Testing pre-compression chain: load->init->expand->inv_expand->inv_init->inv_load...")
    
    try:
        pre_compression = _import_pre_compression()
        load_hash_state = pre_compression['load_hash_state']
        init_message_schedule = pre_compression['init_message_schedule']
        expand_message_schedule = pre_compression['expand_message_schedule']
        inv_load_hash_state = pre_compression['inv_load_hash_state']
        inv_init_message_schedule = pre_compression['inv_init_message_schedule']
        inv_expand_message_schedule = pre_compression['inv_expand_message_schedule']
    except ImportError as e:
        print(f"[FAIL] Failed to import required modules: {e}")
        traceback.print_exc()
        return False
    
    # Test cases: pairs of (H_i, M_i)
    test_cases = [
        # All zeros
        ((0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000),
         [0] * 64),
        # All ones
        ((0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF),
         [0xFF] * 64),
        # Sequential values
        ((0x01234567, 0x89ABCDEF, 0xFEDCBA98, 0x76543210, 0x11111111, 0x22222222, 0x33333333, 0x44444444),
         list(range(64))),
        # SHA-256 initial hash values with random block
        ((0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19),
         bytes("The quick brown fox jumps over the lazy dog. 1234567890!@#$%", encoding='utf-8')[:64]),
        # Edge cases
        ((0x00000000, 0x00000001, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFE, 0xFFFFFFFF, 0x12345678, 0x9ABCDEF0),
         [0x00 if i % 2 == 0 else 0xFF for i in range(64)]),
        # Mixed patterns
        ((0xDEADBEEF, 0xCAFEBABE, 0x12345678, 0x9ABCDEF0, 0x11112222, 0x33334444, 0x55556666, 0x77778888),
         [i % 256 for i in range(64)]),
    ]
    
    def test_func(test_case, i):
        H_i, M_i = test_case
        
        # Ensure M_i is a list of bytes
        M_i = _ensure_list(M_i)
        
        # Verify H_i is a tuple of 8 integers
        if not isinstance(H_i, tuple) or len(H_i) != 8:
            return (False, f"H_i must be a tuple of 8 integers, got {type(H_i)} with length {len(H_i) if hasattr(H_i, '__len__') else 'N/A'}")
        
        # Verify all H_i values are 32-bit integers
        for j, h in enumerate(H_i):
            if not isinstance(h, int):
                return (False, f"H_i word {j} is not an integer: {type(h)}")
            if h < 0 or h > 0xFFFFFFFF:
                return (False, f"H_i word {j} is out of 32-bit range: {h}")
        
        # Ensure M_i is exactly 64 bytes (512 bits)
        if len(M_i) != 64:
            if len(M_i) < 64:
                M_i = M_i + [0] * (64 - len(M_i))
            else:
                M_i = M_i[:64]
        
        # Verify all M_i values are bytes (0-255)
        for j, byte_val in enumerate(M_i):
            if not isinstance(byte_val, int) or byte_val < 0 or byte_val > 255:
                return (False, f"M_i byte {j} is not a valid byte value: {byte_val}")
        
        # Step 1: Load the hash state
        a, b, c, d, e, f, g, h = load_hash_state(H_i)
        
        # Step 2: Initialize the message schedule
        w = init_message_schedule(M_i)
        
        # Verify w has at least 16 words
        if len(w) < 0x10:
            return (False, f"Message schedule has {len(w)} words, expected at least 16")
        
        # Step 3: Expand the message schedule
        w_expanded = expand_message_schedule(w, rounds=64)
        
        # Verify expanded schedule has 64 words
        if len(w_expanded) != 64:
            return (False, f"Expanded schedule has {len(w_expanded)} words, expected 64")
        
        # Step 4: Reverse the expansion
        w_recovered = inv_expand_message_schedule(w_expanded, rounds=64)
        
        # Verify we got back the first 16 words
        if w_recovered != w[:16]:
            return (False, "Expansion round-trip failed: recovered W[0..15] doesn't match original")
        
        # Step 5: Reverse the message schedule initialization
        M_i_recovered = inv_init_message_schedule(w_recovered)
        
        # Step 6: Reverse the hash state
        H_i_recovered = inv_load_hash_state(a, b, c, d, e, f, g, h)
        
        # Step 7: Verify we got back the original H_i
        if H_i_recovered != H_i:
            error_msg = f"Hash state round-trip failed\n"
            error_msg += f"  Original H_i: {H_i}\n"
            error_msg += f"  Recovered H_i: {H_i_recovered}\n"
            # Find first difference
            for j in range(8):
                if H_i[j] != H_i_recovered[j]:
                    error_msg += f"  First difference at word {j}: original=0x{H_i[j]:08X}, recovered=0x{H_i_recovered[j]:08X}"
                    break
            return (False, error_msg)
        
        # Step 8: Verify we got back the original M_i
        if M_i_recovered != M_i:
            error_msg = f"Message schedule round-trip failed\n"
            error_msg += f"  Original M_i length: {len(M_i)} bytes\n"
            error_msg += f"  Recovered M_i length: {len(M_i_recovered)} bytes\n"
            if len(M_i) != len(M_i_recovered):
                error_msg += f"  Length mismatch!"
            else:
                # Find first difference
                for j in range(len(M_i)):
                    if M_i[j] != M_i_recovered[j]:
                        error_msg += f"  First difference at byte {j}: original=0x{M_i[j]:02X}, recovered=0x{M_i_recovered[j]:02X}"
                        break
            return (False, error_msg)
        
        return True
    
    success = _run_round_trip_tests(
        "pre-compression chain (load->init->expand->inv_expand->inv_init->inv_load)",
        test_cases,
        test_func,
    )
    assert success


def test_update_hash_state_inverse():
    """
    Test that update_hash_state and inv_update_hash_state are inverse operations.
    
    This test:
    1. Takes a chaining value H_i and working registers a..h (8×32-bit words each)
    2. Updates it using update_hash_state to get H_i+1
    3. Reverses it using inv_update_hash_state
    4. Verifies we get back the original chaining value H_i
    """
    print("Testing update_hash_state / inv_update_hash_state round-trip...")
    
    try:
        post_compression = _import_post_compression()
        update_hash_state = post_compression['update_hash_state']
        inv_update_hash_state = post_compression['inv_update_hash_state']
    except ImportError as e:
        print(f"[FAIL] Failed to import required modules: {e}")
        traceback.print_exc()
        return False
    
    # Test cases: pairs of (H_i, (a, b, c, d, e, f, g, h))
    test_cases = [
        # All zeros
        ((0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000),
         (0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000)),
        # All ones
        ((0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF),
         (0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF)),
        # Sequential values
        ((0x01234567, 0x89ABCDEF, 0xFEDCBA98, 0x76543210, 0x11111111, 0x22222222, 0x33333333, 0x44444444),
         (0x55555555, 0x66666666, 0x77777777, 0x88888888, 0x99999999, 0xAAAAAAAA, 0xBBBBBBBB, 0xCCCCCCCC)),
        # SHA-256 initial hash values with working registers
        ((0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19),
         (0x12345678, 0x9ABCDEF0, 0xFEDCBA98, 0x76543210, 0x11111111, 0x22222222, 0x33333333, 0x44444444)),
        # Edge cases - test overflow handling
        ((0x00000000, 0x00000001, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFE, 0xFFFFFFFF, 0x12345678, 0x9ABCDEF0),
         (0x00000001, 0xFFFFFFFF, 0x80000000, 0x7FFFFFFF, 0x00000002, 0x00000001, 0xEDCBA988, 0x65432110)),
        # Mixed patterns
        ((0xDEADBEEF, 0xCAFEBABE, 0x12345678, 0x9ABCDEF0, 0x11112222, 0x33334444, 0x55556666, 0x77778888),
         (0x11111111, 0x22222222, 0x33333333, 0x44444444, 0x55555555, 0x66666666, 0x77777777, 0x88888888)),
        # Test with zero working registers (should be identity)
        ((0x01234567, 0x89ABCDEF, 0xFEDCBA98, 0x76543210, 0x11111111, 0x22222222, 0x33333333, 0x44444444),
         (0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000)),
        # Test with maximum values
        ((0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF),
         (0x00000001, 0x00000001, 0x00000001, 0x00000001, 0x00000001, 0x00000001, 0x00000001, 0x00000001)),
    ]
    
    def test_func(test_case, i):
        H_i, working = test_case
        
        # Verify H_i is a tuple of 8 integers
        if not isinstance(H_i, tuple) or len(H_i) != 8:
            return (False, f"H_i must be a tuple of 8 integers, got {type(H_i)} with length {len(H_i) if hasattr(H_i, '__len__') else 'N/A'}")
        
        # Verify working is a tuple of 8 integers
        if not isinstance(working, tuple) or len(working) != 8:
            return (False, f"Working registers must be a tuple of 8 integers, got {type(working)} with length {len(working) if hasattr(working, '__len__') else 'N/A'}")
        
        # Verify all H_i values are 32-bit integers
        for j, h in enumerate(H_i):
            if not isinstance(h, int):
                return (False, f"H_i word {j} is not an integer: {type(h)}")
            if h < 0 or h > 0xFFFFFFFF:
                return (False, f"H_i word {j} is out of 32-bit range: {h}")
        
        # Verify all working register values are 32-bit integers
        for j, w in enumerate(working):
            if not isinstance(w, int):
                return (False, f"Working register {j} is not an integer: {type(w)}")
            if w < 0 or w > 0xFFFFFFFF:
                return (False, f"Working register {j} is out of 32-bit range: {w}")
        
        # Unpack working registers
        a, b, c, d, e, f, g, h = working
        
        # Step 1: Update hash state forward
        H_i_plus_1 = update_hash_state(H_i, a, b, c, d, e, f, g, h)
        
        # Step 2: Reverse the update
        H_i_recovered = inv_update_hash_state(H_i_plus_1, a, b, c, d, e, f, g, h)
        
        # Step 3: Verify we got back the original H_i
        if H_i_recovered != H_i:
            error_msg = f"Round-trip failed\n"
            error_msg += f"  Original H_i: {H_i}\n"
            error_msg += f"  Recovered H_i: {H_i_recovered}\n"
            error_msg += f"  Working registers: {working}\n"
            error_msg += f"  H_i+1: {H_i_plus_1}\n"
            # Find first difference
            for j in range(8):
                if H_i[j] != H_i_recovered[j]:
                    error_msg += f"  First difference at word {j}: original=0x{H_i[j]:08X}, recovered=0x{H_i_recovered[j]:08X}"
                    break
            return (False, error_msg)
        
        return True
    
    success = _run_round_trip_tests("update_hash_state/inv_update_hash_state", test_cases, test_func)
    assert success


def test_expand_message_schedule_inverse():
    """
    Test that expand_message_schedule and inv_expand_message_schedule are inverse operations.
    
    This test:
    1. Takes an initial message schedule W[0..15] (16×32-bit words as list of integers)
    2. Expands it using expand_message_schedule to get W[0..63]
    3. Reverses it using inv_expand_message_schedule to get back W[0..15]
    4. Verifies we get back the original W[0..15]
    """
    print("Testing expand_message_schedule / inv_expand_message_schedule round-trip...")
    
    try:
        pre_compression = _import_pre_compression()
        expand_message_schedule = pre_compression['expand_message_schedule']
        inv_expand_message_schedule = pre_compression['inv_expand_message_schedule']
    except ImportError as e:
        print(f"[FAIL] Failed to import required modules: {e}")
        traceback.print_exc()
        return False
    
    # Test cases: various initial message schedules (W[0..15])
    test_cases = [
        # All zeros
        [0] * 16,
        # All ones
        [0xFFFFFFFF] * 16,
        # Sequential values
        list(range(16)),
        # Random-looking values
        [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
         0x01234567, 0x89ABCDEF, 0xFEDCBA98, 0x76543210, 0x11111111, 0x22222222, 0x33333333, 0x44444444],
        # Edge cases: min and max 32-bit values
        [0x00000000, 0x00000001, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFE, 0xFFFFFFFF] + [0x12345678] * 10,
        # Pattern: alternating 0x00000000 and 0xFFFFFFFF
        [0x00000000 if i % 2 == 0 else 0xFFFFFFFF for i in range(16)],
        # SHA-256 initial hash values pattern
        [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
         0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5],
    ]
    
    def test_func(w_initial, i):
        # Ensure w_initial is a list
        if not isinstance(w_initial, list):
            w_initial = list(w_initial)
        
        # Verify it has exactly 16 words
        if len(w_initial) < 16:
            w_initial = w_initial + [0] * (16 - len(w_initial))
        elif len(w_initial) > 16:
            w_initial = w_initial[:16]
        
        # Verify all values are 32-bit integers
        for j, word in enumerate(w_initial):
            if not isinstance(word, int):
                return (False, f"Word W[{j}] is not an integer: {type(word)}")
            if word < 0 or word > 0xFFFFFFFF:
                return (False, f"Word W[{j}] is out of 32-bit range: {word}")
        
        # Pre-allocate list to 64 elements (as init_message_schedule does)
        # expand_message_schedule expects the list to already have space for indices 16-63
        w_prepared = w_initial.copy() + [0] * (64 - len(w_initial))
        
        # Step 1: Expand the message schedule
        w_expanded = expand_message_schedule(w_prepared, rounds=64)
        
        # Verify expanded schedule has 64 words
        if len(w_expanded) != 64:
            return (False, f"Expanded schedule has {len(w_expanded)} words, expected 64")
        
        # Verify first 16 words match input
        if w_expanded[:16] != w_initial:
            return (False, "First 16 words of expanded schedule don't match input")
        
        # Step 2: Reverse the expansion
        w_recovered = inv_expand_message_schedule(w_expanded, rounds=64)
        
        # Step 3: Verify we got back the original
        if w_recovered != w_initial:
            error_msg = f"Round-trip failed\n"
            error_msg += f"  Original length: {len(w_initial)} words\n"
            error_msg += f"  Recovered length: {len(w_recovered)} words\n"
            if len(w_initial) != len(w_recovered):
                error_msg += f"  Length mismatch!"
            else:
                # Find first difference
                for j in range(len(w_initial)):
                    if w_initial[j] != w_recovered[j]:
                        error_msg += f"  First difference at word {j}: original=0x{w_initial[j]:08X}, recovered=0x{w_recovered[j]:08X}"
                        break
            return (False, error_msg)
        
        return True
    
    success = _run_round_trip_tests("expand_message_schedule/inv_expand_message_schedule", test_cases, test_func)
    assert success


if __name__ == "__main__":
    print("\n" + "=" * 80)
    print("Inverse Operations Test Suite")
    print("=" * 80 + "\n")
    
    results = []
    
    # Run inverse operation tests
    results.append(("pad_message/inv_pad_message", test_pad_message_inverse()))
    results.append(("split_into_blocks/inv_split_into_blocks", test_split_into_blocks_inverse()))
    results.append(("pre-block chain (pad->split->merge->unpad)", test_full_chain_inverse()))
    results.append(("finalize_digest/inv_finalize_digest", test_finalize_digest_inverse()))
    results.append(("load_hash_state/inv_load_hash_state", test_load_hash_state_inverse()))
    results.append(("init_message_schedule/inv_init_message_schedule", test_init_message_schedule_inverse()))
    results.append(("expand_message_schedule/inv_expand_message_schedule", test_expand_message_schedule_inverse()))
    results.append(("pre-compression chain (load->init->expand->inv_expand->inv_init->inv_load)", test_pre_compression_chain_inverse()))
    results.append(("update_hash_state/inv_update_hash_state", test_update_hash_state_inverse()))
    
    # Summary
    print("\n" + "=" * 80)
    print("Test Summary")
    print("=" * 80)
    for name, success in results:
        status = "[PASS]" if success else "[FAIL]"
        print(f"{status} {name}")
    
    print("=" * 80)
    
    # Exit with error code if any test failed
    if all(success for _, success in results):
        print("\n[SUCCESS] All inverse operation tests passed!")
        sys.exit(0)
    else:
        print("\n[ERROR] Some tests failed. See output above for details.")
        sys.exit(1)

