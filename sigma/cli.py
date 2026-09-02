import argparse
import os
import sys
import time

from sigma.factory import SigmaFactory


def main():
    parser = argparse.ArgumentParser(
        description="SigmaHash legacy v1 research CLI (not for production security)",
        epilog="Example: sigmahash -m legacy-v1-lightweight example.bin",
    )

    # Hacemos que los archivos sean opcionales (nargs="*") para permitir uso exclusivo de texto
    parser.add_argument("files", nargs="*", help="Files to process (Optional if -t is provided)")

    parser.add_argument(
        "-m",
        "--mode",
        choices=[
            "legacy-v1-paranoid",
            "legacy-v1-simultaneous",
            "legacy-v1-lightweight",
            "legacy-v1-realtime",
            "paranoid",
            "simultaneous",
            "lightweight",
            "realtime",
        ],
        default="legacy-v1-paranoid",
        help="Legacy v1 routing topology (explicit legacy-v1-* names preferred)",
    )

    parser.add_argument(
        "-r",
        "--rounds",
        type=int,
        help="Legacy strategy parameter; semantics differ by mode",
    )

    parser.add_argument(
        "-t",
        "--text",
        type=str,
        help="Direct UTF-8 text input (not a password KDF)",
    )

    parser.add_argument(
        "--benchmark",
        action="store_true",
        help="Displays execution latency and throughput statistics",
    )

    args = parser.parse_args()

    # Validación inicial: Si no hay ni archivos ni texto, mostramos la ayuda
    if not args.files and not args.text:
        parser.print_help(sys.stderr)
        sys.exit(1)

    failed = False

    # 1. Procesamiento de Texto Directo (In-Memory)
    if args.text:
        try:
            # El texto en RAM es diminuto, medimos solo la latencia, no el MB/s
            start_t = time.time()
            digest = SigmaFactory.hash_string(args.text, mode=args.mode, rounds=args.rounds)
            end_t = time.time()

            print(f"{digest}  [TEXT INPUT]")

            if args.benchmark:
                duration = end_t - start_t
                print(
                    f"   -> Mode: {args.mode}, Latency: {duration:.6f}s",
                    file=sys.stderr,
                )
        except Exception as e:
            print(f"[ERROR] Failed to process text input: {e!s}", file=sys.stderr)
            failed = True

    # 2. Procesamiento de Archivos Físicos (Disk I/O)
    for fpath in args.files:
        if not os.path.exists(fpath):
            print(f"[ERROR] File not found: {fpath}", file=sys.stderr)
            failed = True
            continue

        try:
            file_size_mb = os.path.getsize(fpath) / (1024 * 1024)

            start_t = time.time()
            digest = SigmaFactory.hash_file(fpath, mode=args.mode, rounds=args.rounds)
            end_t = time.time()

            duration = end_t - start_t

            # Output limpio estilo Unix (Hash  Filename)
            print(f"{digest}  {fpath}")

            if args.benchmark:
                speed = file_size_mb / duration if duration > 0 else 0
                print(
                    f"   -> Mode: {args.mode}, Time: {duration:.4f}s, Speed: {speed:.2f} MB/s",
                    file=sys.stderr,
                )

        except Exception as e:
            print(f"[ERROR] Failed to process {fpath}: {e!s}", file=sys.stderr)
            failed = True

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
