"""Run the PX4 verification gateway against one local PX1 store."""

from __future__ import annotations

import argparse
from pathlib import Path

from sigma.artifact import LocalArtifactStoreV1
from sigma.gateway import (
    GatewayLimitsV1,
    GatewayServiceV1,
    JsonLinesGatewayAuditSinkV1,
    NullGatewayAuditSinkV1,
    serve_gateway_v1,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--store", type=Path, required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--audit-jsonl", type=Path)
    parser.add_argument("--max-request-bytes", type=int, default=(1 << 30) + (16 << 20))
    parser.add_argument("--max-source-bytes", type=int, default=1 << 30)
    parser.add_argument("--max-memory-spool-bytes", type=int, default=1 << 20)
    parser.add_argument("--max-proof-value-bytes", type=int, default=64 << 20)
    parser.add_argument("--max-batch-items", type=int, default=256)
    parser.add_argument("--max-concurrent-requests", type=int, default=16)
    parser.add_argument("--timeout-seconds", type=float, default=120.0)
    args = parser.parse_args()

    limits = GatewayLimitsV1(
        max_request_bytes=args.max_request_bytes,
        max_source_bytes=args.max_source_bytes,
        max_memory_spool_bytes=args.max_memory_spool_bytes,
        max_proof_value_bytes=args.max_proof_value_bytes,
        max_batch_items=args.max_batch_items,
        max_concurrent_requests=args.max_concurrent_requests,
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


if __name__ == "__main__":
    raise SystemExit(main())
