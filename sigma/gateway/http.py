"""PX4 dependency-free HTTP daemon adapter for GatewayServiceV1."""

from __future__ import annotations

import contextlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import ClassVar

from .runtime import (
    GatewayError,
    GatewayErrorCodeV1,
    GatewayResponseV1,
    error_response_v1,
)
from .service import GatewayServiceV1


class GatewayThreadingHTTPServerV1(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        server_address: tuple[str, int],
        service: GatewayServiceV1,
    ) -> None:
        if not isinstance(service, GatewayServiceV1):
            raise TypeError("service must be GatewayServiceV1")
        self.gateway_service = service
        super().__init__(server_address, GatewayHTTPRequestHandlerV1)


class GatewayHTTPRequestHandlerV1(BaseHTTPRequestHandler):
    """Minimal HTTP/1.1 adapter with no credential-bearing default access log."""

    protocol_version: ClassVar[str] = "HTTP/1.1"
    server_version: ClassVar[str] = "SigmaGateway"
    sys_version: ClassVar[str] = ""

    @property
    def _gateway_server(self) -> GatewayThreadingHTTPServerV1:
        server = self.server
        if not isinstance(server, GatewayThreadingHTTPServerV1):
            raise RuntimeError("gateway handler attached to unexpected server")
        return server

    def log_message(self, format: str, *args) -> None:
        # BaseHTTPRequestHandler otherwise logs raw request lines, which can
        # contain query strings and other user-controlled sensitive material.
        return None

    def _write_response(self, response: GatewayResponseV1) -> None:
        self.close_connection = True
        try:
            self.send_response_only(response.status)
            self.send_header("Content-Type", response.content_type)
            self.send_header("Content-Length", str(len(response.body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "close")
            for key, value in response.headers:
                self.send_header(key, value)
            self.end_headers()
            if response.body:
                self.wfile.write(response.body)
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            # The request is already isolated and no state publication depends
            # on response delivery.
            self.close_connection = True

    def _safe_error(
        self,
        *,
        status: int,
        code: GatewayErrorCodeV1,
        message: str,
        retryable: bool = False,
    ) -> None:
        self._write_response(
            error_response_v1(
                GatewayError(
                    status=status,
                    code=code,
                    safe_message=message,
                    retryable=retryable,
                )
            )
        )

    def _aggregate_header_bytes(self) -> int:
        total = 0
        for key, value in self.headers.items():
            total += len(key.encode("ascii", "replace"))
            total += len(value.encode("utf-8", "replace"))
            total += 4
        return total

    def _content_length(self, *, required: bool) -> int:
        transfer_values = self.headers.get_all("Transfer-Encoding") or []
        if transfer_values:
            raise GatewayError(
                status=400,
                code=GatewayErrorCodeV1.BAD_REQUEST,
                safe_message="Transfer-Encoding is not supported by gateway v1",
            )
        length_values = self.headers.get_all("Content-Length") or []
        if len(length_values) > 1:
            raise GatewayError(
                status=400,
                code=GatewayErrorCodeV1.BAD_REQUEST,
                safe_message="multiple Content-Length headers are not accepted",
            )
        raw = None if not length_values else length_values[0]
        if raw is None:
            if required:
                raise GatewayError(
                    status=411,
                    code=GatewayErrorCodeV1.LENGTH_REQUIRED,
                    safe_message="Content-Length is required",
                )
            return 0
        try:
            value = int(raw, 10)
        except ValueError as exc:
            raise GatewayError(
                status=400,
                code=GatewayErrorCodeV1.BAD_REQUEST,
                safe_message="Content-Length is invalid",
            ) from exc
        if value < 0:
            raise GatewayError(
                status=400,
                code=GatewayErrorCodeV1.BAD_REQUEST,
                safe_message="Content-Length is invalid",
            )
        return value

    def _admission_preflight(self, *, required_length: bool) -> int:
        service = self._gateway_server.gateway_service
        if self._aggregate_header_bytes() > service.limits.max_header_bytes:
            raise GatewayError(
                status=431,
                code=GatewayErrorCodeV1.HEADER_TOO_LARGE,
                safe_message="request headers exceed gateway limit",
            )
        length = self._content_length(required=required_length)
        if length > service.limits.max_request_bytes:
            raise GatewayError(
                status=413,
                code=GatewayErrorCodeV1.REQUEST_TOO_LARGE,
                safe_message="request body exceeds gateway limit",
            )
        return length

    def handle_expect_100(self) -> bool:
        try:
            self._admission_preflight(required_length=True)
        except GatewayError as exc:
            self._write_response(error_response_v1(exc))
            return False
        self.send_response_only(100)
        self.end_headers()
        return True

    def _dispatch(self, *, required_length: bool) -> None:
        try:
            content_length = self._admission_preflight(
                required_length=required_length
            )
            content_type = self.headers.get("Content-Type", "")
            response = self._gateway_server.gateway_service.handle(
                method=self.command,
                path=self.path,
                content_type=content_type,
                body_stream=self.rfile,
                content_length=content_length,
            )
        except GatewayError as exc:
            response = error_response_v1(exc)
        except Exception:
            response = error_response_v1(
                GatewayError(
                    status=500,
                    code=GatewayErrorCodeV1.INTERNAL,
                    safe_message="internal gateway transport error",
                )
            )
        self._write_response(response)

    def do_GET(self) -> None:
        self._dispatch(required_length=False)

    def do_POST(self) -> None:
        self._dispatch(required_length=True)

    def _method_not_allowed(self) -> None:
        self._safe_error(
            status=405,
            code=GatewayErrorCodeV1.METHOD_NOT_ALLOWED,
            message="HTTP method is not supported by gateway v1",
        )

    def do_HEAD(self) -> None:
        self._method_not_allowed()

    def do_PUT(self) -> None:
        self._method_not_allowed()

    def do_DELETE(self) -> None:
        self._method_not_allowed()

    def do_PATCH(self) -> None:
        self._method_not_allowed()

    def do_OPTIONS(self) -> None:
        self._method_not_allowed()


def create_gateway_http_server_v1(
    host: str,
    port: int,
    service: GatewayServiceV1,
) -> GatewayThreadingHTTPServerV1:
    if not isinstance(host, str):
        raise TypeError("host must be str")
    if isinstance(port, bool) or not isinstance(port, int) or not 0 <= port <= 65535:
        raise ValueError("port must be 0..65535")
    return GatewayThreadingHTTPServerV1((host, port), service)


def serve_gateway_v1(
    host: str,
    port: int,
    service: GatewayServiceV1,
    *,
    poll_interval: float = 0.5,
) -> None:
    if (
        isinstance(poll_interval, bool)
        or not isinstance(poll_interval, (int, float))
        or poll_interval <= 0
    ):
        raise ValueError("poll_interval must be positive")
    server = create_gateway_http_server_v1(host, port, service)
    try:
        server.serve_forever(poll_interval=float(poll_interval))
    finally:
        with contextlib.suppress(Exception):
            server.server_close()


__all__ = [
    "GatewayHTTPRequestHandlerV1",
    "GatewayThreadingHTTPServerV1",
    "create_gateway_http_server_v1",
    "serve_gateway_v1",
]
