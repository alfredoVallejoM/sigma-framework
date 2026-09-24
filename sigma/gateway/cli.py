"""Command-line entrypoint for the PX4 verification gateway daemon."""

from __future__ import annotations

import argparse
import ipaddress
from pathlib import Path

from sigma.artifact import LocalArtifactStoreV1

from .http import serve_gateway_v1
from .runtime import (
    GatewayLimitsV1,
    JsonLinesGatewayAuditSinkV1,
    NullGatewayAuditSinkV1,
)
from .service import GatewayServiceV1


def _is_loopback_host(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def build_parser_v1() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the Sigma PX4 verification gateway daemon."
    )
    parser.add_argument("--store", type=Path, required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument(
        "--allow-nonlocal-bind",
        action="store_true",
        help="Required to bind to a non-loopback host; PX4 does not provide auth/TLS.",
    )
    parser.add_argument("--audit-jsonl", type=Path)
    parser.add_argument("--max-request-bytes", type=int, default=(1 << 30) + (16 << 20))
    parser.add_argument("--max-header-bytes", type=int, default=64 << 10)
    parser.add_argument("--max-metadata-bytes", type=int, default=4 << 20)
    parser.add_argument("--max-source-bytes", type=int, default=1 << 30)
    parser.add_argument("--max-memory-spool-bytes", type=int, default=1 << 20)
    parser.add_argument("--max-proof-value-bytes", type=int, default=64 << 20)
    parser.add_argument("--max-batch-items", type=int, default=256)
    parser.add_argument("--max-batch-total-source-bytes", type=int, default=1 << 30)
    parser.add_argument("--max-concurrent-requests", type=int, default=16)
    parser.add_argument("--max-http-connections", type=int, default=32)
    parser.add_argument("--max-response-bytes", type=int, default=32 << 20)
    parser.add_argument("--max-trajectory-rounds", type=int, default=1_000_064)
    parser.add_argument("--read-chunk-bytes", type=int, default=1 << 20)
    parser.add_argument("--timeout-seconds", type=float, default=120.0)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser_v1()
    args = parser.parse_args(argv)
    if not _is_loopback_host(args.host) and not args.allow_nonlocal_bind:
        parser.error(
            "non-loopback bind requires --allow-nonlocal-bind; "
            "place authentication/TLS in a trusted front proxy"
        )

    limits = GatewayLimitsV1(
        max_request_bytes=args.max_request_bytes,
        max_header_bytes=args.max_header_bytes,
        max_metadata_bytes=args.max_metadata_bytes,
        max_source_bytes=args.max_source_bytes,
        max_memory_spool_bytes=args.max_memory_spool_bytes,
        max_proof_value_bytes=args.max_proof_value_bytes,
        max_batch_items=args.max_batch_items,
        max_batch_total_source_bytes=args.max_batch_total_source_bytes,
        max_concurrent_requests=args.max_concurrent_requests,
        max_http_connections=args.max_http_connections,
        max_response_bytes=args.max_response_bytes,
        max_trajectory_rounds=args.max_trajectory_rounds,
        read_chunk_bytes=args.read_chunk_bytes,
        request_timeout_seconds=args.timeout_seconds,
    )
    audit = (
        NullGatewayAuditSinkV1()
        if args.audit_jsonl is None
        else JsonLinesGatewayAuditSinkV1(args.audit_jsonl)
    )
    service = GatewayServiceV1(
        LocalArtifactStoreV1(args.store),
        limits=limits,
        audit_sink=audit,
    )
    serve_gateway_v1(args.host, args.port, service)
    return 0


__all__ = ["build_parser_v1", "main"]


if __name__ == "__main__":
    raise SystemExit(main())
