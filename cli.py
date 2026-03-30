import argparse
import sys
import time
import os
from sigma.factory import SigmaFactory


def main():
    parser = argparse.ArgumentParser(
        description="SigmaHash: The Non-Markovian Integrity Tool",
        epilog="Use 'paranoid' for cold storage, 'simultaneous' for speed, 'lightweight' for IoT.",
    )

    parser.add_argument("files", nargs="+", help="Files to process")

    # BUGFIX: Added 'realtime' to the strategy choices
    parser.add_argument(
        "-m",
        "--mode",
        choices=["paranoid", "simultaneous", "lightweight", "realtime"],
        default="paranoid",
        help="Hashing strategy (default: paranoid)",
    )

    parser.add_argument(
        "-r",
        "--rounds",
        type=int,
        help="Number of recursive rounds (computational difficulty/PoW factor)",
    )

    parser.add_argument(
        "--benchmark",
        action="store_true",
        help="Displays time and speed benchmark statistics",
    )

    args = parser.parse_args()

    # Processing Loop
    for fpath in args.files:
        if not os.path.exists(fpath):
            print(f"[ERROR] File not found: {fpath}", file=sys.stderr)
            continue

        try:
            file_size_mb = os.path.getsize(fpath) / (1024 * 1024)

            start_t = time.time()
            digest = SigmaFactory.hash_file(fpath, mode=args.mode, rounds=args.rounds)
            end_t = time.time()

            duration = end_t - start_t

            # Clean output (Unix-friendly format: Hash  Filename)
            print(f"{digest}  {fpath}")

            if args.benchmark:
                speed = file_size_mb / duration if duration > 0 else 0
                print(
                    f"   -> Mode: {args.mode}, Time: {duration:.4f}s, Speed: {speed:.2f} MB/s",
                    file=sys.stderr,
                )

        except Exception as e:
            # Debugging: Print full traceback exception on failure
            print(f"[ERROR] Failed to process {fpath}: {str(e)}", file=sys.stderr)
            # if os.getenv("DEBUG"): raise e (Optional)


if __name__ == "__main__":
    main()
