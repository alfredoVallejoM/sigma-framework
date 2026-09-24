"""PX4 local/API/HTTP overhead benchmark. Not a correctness gate."""

from __future__ import annotations

import argparse
import http.client
import json
import statistics
import tempfile
import threading
import time
from pathlib import Path

from sigma.artifact import (
    ArtifactProfileV1,
    LocalArtifactStoreV1,
    create_artifact_v1,
    verify_artifact_v1,
)
from sigma.gateway import (
    ARTIFACT_VERIFY_MEDIA_TYPE,
    GatewayServiceV1,
    create_gateway_http_server_v1,
    encode_artifact_verify_request_v1,
)
from sigma.trajectory import VerificationPolicyV1
from sigma.tree import build_tree

DEFAULT_SIZES = (0, 1024, 65_536, 1 << 20)


def _measure(callable_, iterations: int) -> dict[str, float]:
    values = []
    for _ in range(iterations):
        started = time.perf_counter()
        callable_()
        values.append((time.perf_counter() - started) * 1000.0)
    return {
        "median_ms": statistics.median(values),
        "min_ms": min(values),
        "max_ms": max(values),
    }


def run_benchmark(
    *,
    sizes: tuple[int, ...],
    iterations: int,
) -> dict[str, object]:
    if not sizes or any(
        isinstance(size, bool) or not isinstance(size, int) or size < 0
        for size in sizes
    ):
        raise ValueError("sizes must be non-negative integer tuple")
    if isinstance(iterations, bool) or not isinstance(iterations, int) or iterations < 1:
        raise ValueError("iterations must be positive")

    rows: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="sigma-px4-bench-") as temp:
        root = Path(temp)
        store = LocalArtifactStoreV1(root / "store")
        service = GatewayServiceV1(store)
        server = create_gateway_http_server_v1("127.0.0.1", 0, service)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        host, port = server.server_address
        try:
            for size in sizes:
                data = bytes((index * 13 + 7) % 251 for index in range(size))
                artifact = create_artifact_v1(
                    ArtifactProfileV1.TREE,
                    tree_root=build_tree(data),
                )
                store.put_artifact(artifact)
                policy = VerificationPolicyV1(
                    allow_tree_only_artifacts=True,
                    max_input_bytes=max(1, size),
                )
                payload = encode_artifact_verify_request_v1(
                    artifact_id=artifact.artifact_id,
                    policy=policy,
                    source=data,
                )

                local = _measure(
                    lambda: verify_artifact_v1(
                        data,
                        artifact,
                        policy=policy,
                    ),
                    iterations,
                )
                in_process = _measure(
                    lambda: service.handle(
                        method="POST",
                        path="/v1/artifacts/verify",
                        content_type=ARTIFACT_VERIFY_MEDIA_TYPE,
                        body_stream=__import__("io").BytesIO(payload),
                        content_length=len(payload),
                    ),
                    iterations,
                )

                def http_call() -> None:
                    connection = http.client.HTTPConnection(host, port, timeout=30)
                    connection.request(
                        "POST",
                        "/v1/artifacts/verify",
                        body=payload,
                        headers={"Content-Type": ARTIFACT_VERIFY_MEDIA_TYPE},
                    )
                    response = connection.getresponse()
                    response.read()
                    if response.status != 200:
                        raise RuntimeError(f"unexpected PX4 HTTP status {response.status}")
                    connection.close()

                http_result = _measure(http_call, iterations)
                rows.append(
                    {
                        "artifact_wire_bytes": len(artifact.to_bytes()),
                        "http": http_result,
                        "in_process_gateway": in_process,
                        "local_api": local,
                        "request_bytes": len(payload),
                        "source_bytes": size,
                    }
                )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=10)

    return {
        "iterations": iterations,
        "rows": rows,
        "schema": "sigma-px4-gateway-benchmark-v1",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=20)
    parser.add_argument(
        "--sizes",
        default=",".join(str(value) for value in DEFAULT_SIZES),
    )
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    sizes = tuple(int(value) for value in args.sizes.split(",") if value)
    report = run_benchmark(sizes=sizes, iterations=args.iterations)
    payload = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.report is not None:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(payload, encoding="utf-8")
    print(payload, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
