"""Run enumerate_h_values.py for a range of message lengths.

This script takes a start and end number and runs enumerate_h_values.py
for each value in the range [start, end] (inclusive).

Usage:
    python run_enumerate_range.py <start> <end>
    python run_enumerate_range.py 0 8      # Runs for lengths 0, 1, 2, ..., 8
    python run_enumerate_range.py 4 6     # Runs for lengths 4, 5, 6
"""

from __future__ import annotations

import argparse
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(
        description="Run enumerate_h_values.py for a range of message lengths"
    )
    parser.add_argument(
        "start",
        type=int,
        help="Start message length (inclusive)",
    )
    parser.add_argument(
        "end",
        type=int,
        help="End message length (inclusive)",
    )
    args = parser.parse_args()

    start = args.start
    end = args.end

    if start < 0:
        print(f"ERROR: Start value must be non-negative (got {start})")
        sys.exit(1)
    
    if end < start:
        print(f"ERROR: End value must be >= start (got end={end}, start={start})")
        sys.exit(1)

    print(f"Running enumerate_h_values.py for lengths {start} to {end} (inclusive)")
    print(f"Total runs: {end - start + 1}\n")

    for length in range(start, end + 1):
        print(f"{'='*60}")
        print(f"Processing length: {length} bits")
        print(f"{'='*60}")
        
        try:
            result = subprocess.run(
                [sys.executable, "enumerate_h_values.py", str(length)],
                check=True,
                capture_output=False,  # Show output in real-time
            )
            print(f"\n✓ Completed length {length}\n")
        except subprocess.CalledProcessError as e:
            print(f"\n✗ Failed for length {length} (exit code {e.returncode})\n")
            sys.exit(1)
        except KeyboardInterrupt:
            print(f"\n\nInterrupted at length {length}")
            sys.exit(1)

    print(f"{'='*60}")
    print(f"All runs completed successfully!")
    print(f"Processed lengths {start} through {end}")


if __name__ == "__main__":
    main()
