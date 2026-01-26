# SHA-256 Compression Inverse

This project implements the inverse of the SHA-256 compression function, allowing for the reconstruction of pre-round states from post-round states.

## Overview

The SHA-256 algorithm uses a compression function that processes 512-bit blocks through 64 rounds. This implementation provides functions to invert the final compression step, recovering the pre-round state from the post-round state.

## Key Files

- `compression_inv.py` - Main inverse compression functions
- `compress.py` - Forward SHA-256 compression implementation
- `sha256_cli.py` - SHA-256 CLI tool and helper functions
- `test_compression_inv.py` - Test suite for inverse operations
- `experiment_compression_inv.py` - Experimental verification of inverse operations

## Functions

### `compression_inv(a, b, c, d, e, f, g, h, k)`
Invert a single SHA-256 compression round, recovering the pre-round state from the post-round state.

### `compression64_inv(a, b, c, d, e, f, g, h)`
Invert the full 64-round SHA-256 compression loop, recovering a consistent preimage and message schedule words.

## Usage

The inverse functions can be used to analyze SHA-256 compression behavior and verify the correctness of cryptographic operations.

## Experiment

The `experiment_compression_inv.py` file demonstrates how the inverse functions can be used to:
- Verify that `compression64_inv` correctly inverts the compression loop
- Recover preimage data from SHA-256 digests
- Validate message schedules and working states through round-trip verification

## Testing

Run tests with:
```bash
pytest test_compression_inv.py
