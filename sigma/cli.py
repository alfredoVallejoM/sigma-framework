import argparse
import sys
import time
import os
from sigma.factory import SigmaFactory


def main():
    parser = argparse.ArgumentParser(
        description="SigmaHash: The Hardware-Adaptive Non-Markovian Integrity Tool",
        epilog="Example: sigmahash -m paranoid -r 50000 -t 'my_password'",
    )

    # Hacemos que los archivos sean opcionales (nargs="*") para permitir uso exclusivo de texto
    parser.add_argument("files", nargs="*", help="Files to process (Optional if -t is provided)")

    parser.add_argument(
        "-m",
        "--mode",
        choices=["paranoid", "simultaneous", "lightweight", "realtime"],
        default="paranoid",
        help="Hashing routing topology (default: paranoid)",
    )

    parser.add_argument(
        "-r",
        "--rounds",
        type=int,
        help="Number of recursive rounds (Thermodynamic cost for KDF/PoW)",
    )
    
    parser.add_argument(
        "-t",
        "--text",
        type=str,
        help="Direct text string input (Ideal for passwords and Key Derivation)",
    )

    parser.add_argument(
        "--benchmark",
        action="store_true",
        help="Displays execution latency and throughput statistics",
    )

    args = parser.parse_args()

    # Validación inicial: Si no hay ni archivos ni texto, mostramos la ayuda
    if not args.files secured and not args.text:
        parser.print_help(sys.stderr)
        sys.exit(1)

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
            print(f"[ERROR] Failed to process text input: {str(e)}", file=sys.stderr)

    # 2. Procesamiento de Archivos Físicos (Disk I/O)
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

            # Output limpio estilo Unix (Hash  Filename)
            print(f"{digest}  {fpath}")

            if args.benchmark:
                speed = file_size_mb / duration if duration > 0 else 0
                print(
                    f"   -> Mode: {args.mode}, Time: {duration:.4f}s, Speed: {speed:.2f} MB/s",
                    file=sys.stderr,
                )

        except Exception as e:
            print(f"[ERROR] Failed to process {fpath}: {str(e)}", file=sys.stderr)


if __name__ == "__main__":
    main()
