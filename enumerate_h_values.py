"""Enumerate all possible messages of a given BIT length and record h values at each round.

For small message lengths, this script:
1. Generates all possible messages (2^N for N bits)
2. Computes SHA-256 while tracking the h register at each round
3. Saves results to data/length/N.yaml

Usage:
    python enumerate_h_values.py <message_length_bits>
    python enumerate_h_values.py 0      # 1 message (empty)
    python enumerate_h_values.py 1      # 2 messages (0, 1)
    python enumerate_h_values.py 8      # 256 messages (1 byte)
    python enumerate_h_values.py 16     # 65536 messages (2 bytes)
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import Dict, Generator, List, Tuple

import yaml

from sha256_cli import sha256_bits_with_h_tracking


def enumerate_messages_bits(length_bits: int) -> Generator[Tuple[bytes, str], None, None]:
    """Generate all possible messages of the given bit length.
    
    Yields:
        (message_bytes, binary_string) tuples
    """
    if length_bits == 0:
        yield b"", ""
        return
    
    total = 2 ** length_bits
    num_bytes = (length_bits + 7) // 8  # Ceiling division
    
    for value in range(total):
        # Convert value to bytes (big-endian, message bits in high positions)
        # For non-byte-aligned lengths, the message occupies the HIGH bits of the last byte
        
        if length_bits % 8 == 0:
            # Byte-aligned: straightforward conversion
            message_bytes = value.to_bytes(num_bytes, byteorder="big")
        else:
            # Non-byte-aligned: shift value to occupy high bits of last byte
            shift = 8 - (length_bits % 8)
            shifted_value = value << shift
            message_bytes = shifted_value.to_bytes(num_bytes, byteorder="big")
        
        # Binary string representation
        binary_str = format(value, f"0{length_bits}b")
        
        yield message_bytes, binary_str


def main():
    parser = argparse.ArgumentParser(
        description="Enumerate all messages of a given BIT length and record h values"
    )
    parser.add_argument(
        "length_bits",
        type=int,
        help="Message length in BITS (WARNING: 2^length messages will be generated)",
    )
    parser.add_argument(
        "--max-messages",
        type=int,
        default=1_000_000,
        help="Maximum number of messages to process (default: 1,000,000)",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="data/length",
        help="Output directory (default: data/length)",
    )
    args = parser.parse_args()

    length_bits = args.length_bits
    total_messages = 2 ** length_bits if length_bits > 0 else 1
    
    print(f"Message length: {length_bits} bits")
    if length_bits % 8 == 0:
        print(f"  (equivalent to {length_bits // 8} bytes)")
    else:
        print(f"  (non-byte-aligned: {length_bits // 8} complete bytes + {length_bits % 8} bits)")
    print(f"Total possible messages: {total_messages:,}")
    
    if total_messages > args.max_messages:
        print(f"ERROR: Too many messages ({total_messages:,} > {args.max_messages:,})")
        print(f"Use --max-messages to increase limit if you really want to proceed")
        sys.exit(1)
    
    # Create output directory
    os.makedirs(args.output_dir, exist_ok=True)
    
    # Enumerate all messages and collect h values
    results: Dict = {
        "message_length_bits": length_bits,
        "message_length_bytes": length_bits // 8 if length_bits % 8 == 0 else f"{length_bits // 8}+{length_bits % 8}bits",
        "total_messages": total_messages,
        "messages": []
    }
    
    print(f"Processing {total_messages:,} messages...")
    
    for idx, (message_bytes, binary_str) in enumerate(enumerate_messages_bits(length_bits)):
        if idx > 0 and idx % 10000 == 0:
            print(f"  Progress: {idx:,} / {total_messages:,} ({100*idx/total_messages:.1f}%)")
        
        digest, h_values_per_block = sha256_bits_with_h_tracking(message_bytes, length_bits)
        
        entry = {
            "message_bits": binary_str,
            "message_hex": message_bytes.hex() if message_bytes else "",
            "digest_hex": digest.hex(),
            "blocks": []
        }
        
        for block_idx, h_values in enumerate(h_values_per_block):
            block_entry = {
                "block_index": block_idx,
                "h_values": [f"{h:08x}" for h in h_values]
            }
            entry["blocks"].append(block_entry)
        
        results["messages"].append(entry)
    
    # Write to YAML file
    output_path = os.path.join(args.output_dir, f"{length_bits}.yaml")
    print(f"Writing results to {output_path}...")
    
    with open(output_path, "w") as f:
        yaml.dump(results, f, default_flow_style=False, sort_keys=False)
    
    print(f"Done! Saved {total_messages:,} message entries to {output_path}")
    
    # Print some statistics
    print("\nSample entries:")
    for i, sample in enumerate(results["messages"][:min(4, len(results["messages"]))]):
        print(f"  [{i}] bits={sample['message_bits'] or '(empty)':<16} hex={sample['message_hex'] or '(empty)':<8} digest={sample['digest_hex'][:16]}...")


if __name__ == "__main__":
    main()
