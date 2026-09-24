"""PX4 dependency-free HTTP daemon adapter for GatewayServiceV1."""

from __future__ import annotations

import contextlib
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import ClassVar

from .runtime import (
    GatewayBusyError,
    GatewayError,
    GatewayErrorCodeV1,
    GatewayResponseV1,
    error_response_v1,
)
from .service import GatewayServiceV1


class _HeaderLimitExceeded(RuntimeError):
    pass


class _HeaderBudgetReaderV1:
    """Limit header bytes while http.client.parse_headers is reading them."""

    def __init__(self, raw, limit: int) -> None:
        self.raw = raw
        self.remaining = limit

    def readline(self, limit: int = -1) -> bytes:
        if self.remaining < 0:
            raise _HeaderLimitExceeded()
        read_limit = self.remaining + 1
        if limit >= 0:
            read_limit = min(read_limit, limit)
        line = self.raw.readline(read_limit)
        if len(line) > self.remaining:
            raise _HeaderLimitExceeded()
        self.remaining -= len(line)
        return line


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
        self._connection_slots = threading.BoundedSemaphore(
            service.limits.max_http_connections
        )
        super().__init__(server_address, GatewayHTTPRequestHandlerV1)

    def process_request(self, request, client_address) -> None:
        if self._connection_slots.acquire(blocking=False):
            try:
                super().process_request(request, client_address)
            except BaseException:
                self._connection_slots.release()
                raise
            return

        error = GatewayBusyError(
            safe_message="gateway HTTP connection limit reached"
        )
        response = error_response_v1(error)
        self.gateway_service.audit_transport_rejection(
            method="",
            path="",
            response=response,
            error_code=error.code,
        )
        raw = (
            f"HTTP/1.1 {response.status} Service Unavailable\r\n"
            f"Content-Type: {response.content_type}\r\n"
            f"Content-Length: {len(response.body)}\r\n"
            "Cache-Control: no-store\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode("ascii") + response.body
        try:
            request.sendall(raw)
        except OSError:
            pass
        finally:
            self.shutdown_request(request)

    def process_request_thread(self, request, client_address) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._connection_slots.release()


class GatewayHTTPRequestHandlerV1(BaseHTTPRequestHandler):
    """Minimal HTTP/1.1 adapter with no credential-bearing default access log."""

    protocol_version: ClassVar[str] = "HTTP/1.1"
    server_version: ClassVar[str] = "SigmaGateway"
    sys_version: ClassVar[str] = ""

    def parse_request(self) -> bool:
        original = self.rfile
        self.rfile = _HeaderBudgetReaderV1(
            original,
            self._gateway_server.gateway_service.limits.max_header_bytes,
        )
        try:
            return super().parse_request()
        except _HeaderLimitExceeded:
            self.close_connection = True
            error = GatewayError(
                status=431,
                code=GatewayErrorCodeV1.HEADER_TOO_LARGE,
                safe_message="request headers exceed gateway limit",
            )
            response = error_response_v1(error)
            self._gateway_server.gateway_service.audit_transport_rejection(
                method=getattr(self, "command", ""),
                path=getattr(self, "path", ""),
                response=response,
                error_code=error.code,
            )
            self._write_response(response)
            return False
        finally:
            self.rfile = original

    def send_error(
        self,
        code: int,
        message: str | None = None,
        explain: str | None = None,
    ) -> None:
        if code == 431:
            error_code = GatewayErrorCodeV1.HEADER_TOO_LARGE
            safe_message = "request headers exceed gateway limit"
        elif code in (405, 501):
            error_code = GatewayErrorCodeV1.METHOD_NOT_ALLOWED
            safe_message = "HTTP method is not supported by gateway v1"
        else:
            error_code = GatewayErrorCodeV1.BAD_REQUEST
            safe_message = "malformed HTTP request"
        error = GatewayError(
            status=code,
            code=error_code,
            safe_message=safe_message,
        )
        response = error_response_v1(error)
        self._gateway_server.gateway_service.audit_transport_rejection(
            method=getattr(self, "command", ""),
            path=getattr(self, "path", ""),
            response=response,
            error_code=error.code,
        )
        self._write_response(response)

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(
            self._gateway_server.gateway_service.limits.request_timeout_seconds
        )

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
        error = GatewayError(
            status=status,
            code=code,
            safe_message=message,
            retryable=retryable,
        )
        response = error_response_v1(error)
        self._gateway_server.gateway_service.audit_transport_rejection(
            method=getattr(self, "command", ""),
            path=getattr(self, "path", ""),
            response=response,
            error_code=error.code,
        )
        self._write_response(response)

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
            response = error_response_v1(exc)
            self._gateway_server.gateway_service.audit_transport_rejection(
                method=getattr(self, "command", ""),
                path=getattr(self, "path", ""),
                response=response,
                error_code=exc.code,
            )
            self._write_response(response)
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
            self._gateway_server.gateway_service.audit_transport_rejection(
                method=getattr(self, "command", ""),
                path=getattr(self, "path", ""),
                response=response,
                error_code=exc.code,
            )
        except Exception:
            error = GatewayError(
                status=500,
                code=GatewayErrorCodeV1.INTERNAL,
                safe_message="internal gateway transport error",
            )
            response = error_response_v1(error)
            self._gateway_server.gateway_service.audit_transport_rejection(
                method=getattr(self, "command", ""),
                path=getattr(self, "path", ""),
                response=response,
                error_code=error.code,
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
