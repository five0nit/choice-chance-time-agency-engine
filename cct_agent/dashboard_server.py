"""Loopback-only HTTP server for the CCTAE administrative dashboard."""

from __future__ import annotations

import argparse
from collections.abc import Callable, Mapping, Sequence
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
import json
import os
from pathlib import Path
import socket
import stat
from typing import Any
from urllib.parse import urlsplit

from .dashboard import DashboardUnavailable, build_dashboard_snapshot
from .dashboard_controls import (
    CONTROL_ACTION,
    CONTROL_CAPABILITY,
    DashboardControlDenied,
    DashboardControlService,
    DashboardSessionAuthority,
    load_operator_bootstrap,
)
from .store import EventStore


_CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; "
    "img-src 'self' data:; connect-src 'self'; object-src 'none'; "
    "base-uri 'none'; frame-ancestors 'none'; form-action 'none'"
)
_ASSETS = {
    "/assets/styles.css": ("styles.css", "text/css; charset=utf-8"),
    "/assets/app.js": ("app.js", "text/javascript; charset=utf-8"),
}
_COOKIE_NAME = "cct_operator_session"
_MAX_REQUEST_BYTES = 32 * 1024


def validate_bind_host(host: str) -> str:
    candidate = str(host).strip()
    if candidate not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("dashboard host must be loopback-only")
    return candidate


def _static_bytes(name: str) -> bytes:
    return files("cct_agent").joinpath("dashboard_static", name).read_bytes()


def _control_database_identity(path: Path) -> tuple[int, int, int, int]:
    candidate = path.expanduser().absolute()
    parent = candidate.parent
    try:
        parent_metadata = parent.stat()
        metadata = candidate.lstat()
    except OSError as error:
        raise ValueError("control database is unavailable") from error
    if (
        parent.is_symlink()
        or not stat.S_ISDIR(parent_metadata.st_mode)
        or parent_metadata.st_uid != os.geteuid()
        or parent_metadata.st_mode & 0o022
    ):
        raise ValueError("control database parent must be owner-controlled")
    if (
        candidate.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != os.geteuid()
        or metadata.st_mode & 0o022
    ):
        raise ValueError("control database must be an owner-controlled regular file")
    return (
        parent_metadata.st_dev,
        parent_metadata.st_ino,
        metadata.st_dev,
        metadata.st_ino,
    )


def _handler(
    database: Path,
    now: Callable[[], str] | None,
    sessions: DashboardSessionAuthority | None,
    controls: DashboardControlService | None,
    control_identity: tuple[int, int, int, int] | None,
) -> type[BaseHTTPRequestHandler]:
    class DashboardHandler(BaseHTTPRequestHandler):
        server_version = "CCTAEDashboard/2"
        sys_version = ""

        def _security_headers(self) -> None:
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Security-Policy", _CSP)
            self.send_header("Cross-Origin-Opener-Policy", "same-origin")
            self.send_header("Cross-Origin-Resource-Policy", "same-origin")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header(
                "Permissions-Policy",
                "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
            )
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")

        def _send(
            self,
            status: int,
            body: bytes,
            content_type: str,
            *,
            include_body: bool = True,
            headers: Mapping[str, str] | None = None,
        ) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            if headers:
                for name, value in headers.items():
                    self.send_header(name, value)
            self._security_headers()
            self.end_headers()
            if include_body:
                self.wfile.write(body)

        def _json(
            self,
            status: int,
            payload: dict[str, Any],
            *,
            include_body: bool = True,
            headers: Mapping[str, str] | None = None,
        ) -> None:
            body = json.dumps(
                payload,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode("utf-8")
            self._send(
                status,
                body,
                "application/json; charset=utf-8",
                include_body=include_body,
                headers=headers,
            )

        def _host_allowed(self) -> bool:
            raw = self.headers.get("Host", "")
            try:
                parsed = urlsplit(f"//{raw}")
                host = (parsed.hostname or "").casefold()
                _port = parsed.port
            except ValueError:
                return False
            return host in {"127.0.0.1", "localhost", "::1"}

        def _origin_allowed(self) -> bool:
            raw_host = self.headers.get("Host", "")
            origin = self.headers.get("Origin", "")
            if not raw_host or not origin:
                return False
            try:
                host = urlsplit(f"//{raw_host}")
                source = urlsplit(origin)
                host_port = host.port or 80
                source_port = source.port or 80
            except ValueError:
                return False
            return (
                source.scheme == "http"
                and source.hostname is not None
                and host.hostname is not None
                and source.hostname.casefold() == host.hostname.casefold()
                and source_port == host_port
                and not source.username
                and not source.password
                and source.path in {"", "/"}
                and not source.query
                and not source.fragment
            )

        def _deny_host(self, *, include_body: bool = True) -> None:
            self._json(
                421,
                {
                    "error": "DASHBOARD_HOST_DENIED",
                    "mode": "CONTROLLED_HOST_APPLY" if controls else "READ_ONLY",
                },
                include_body=include_body,
            )

        def _cookie_token(self) -> str | None:
            raw = self.headers.get("Cookie", "")
            if not raw or len(raw) > 4096:
                return None
            cookie = SimpleCookie()
            try:
                cookie.load(raw)
            except Exception:
                return None
            morsel = cookie.get(_COOKIE_NAME)
            return morsel.value if morsel is not None else None

        def _session(self, *, require_csrf: bool) -> dict[str, str]:
            if sessions is None:
                raise DashboardControlDenied("OPERATOR_AUTHENTICATION_REQUIRED")
            return sessions.authenticate(
                self._cookie_token(),
                csrf_token=self.headers.get("X-CCT-CSRF"),
                require_csrf=require_csrf,
            )

        def _assert_control_database(self) -> None:
            if controls is None or control_identity is None:
                raise DashboardControlDenied("CONTROL_ENDPOINT_NOT_INSTALLED")
            try:
                current = _control_database_identity(database)
            except ValueError as error:
                raise DashboardControlDenied("CONTROL_DATABASE_CHANGED") from error
            if current != control_identity:
                raise DashboardControlDenied("CONTROL_DATABASE_CHANGED")

        def _dashboard_payload(self) -> dict[str, Any]:
            snapshot = build_dashboard_snapshot(
                database, now=now() if now is not None else None
            )
            authenticated = False
            if sessions is not None:
                try:
                    self._session(require_csrf=False)
                    authenticated = True
                except DashboardControlDenied:
                    authenticated = False
            installed = controls is not None
            snapshot["mode"] = "CONTROLLED_HOST_APPLY" if installed else "READ_ONLY"
            snapshot["controls"] = {
                "installed": installed,
                "authenticated": authenticated,
                "action": CONTROL_ACTION if installed else None,
                "capability": CONTROL_CAPABILITY if installed else None,
                "host_apply_only": True,
                "browser_direct_state_write": False,
                "lease_creation_enabled": False,
                "ticket_creation_enabled": False,
                "external_effects_enabled": False,
            }
            permission_rows = snapshot.get("permissions")
            if not isinstance(permission_rows, list):
                raise DashboardUnavailable("DASHBOARD_PROJECTION_INVALID")
            for permission in permission_rows:
                if not isinstance(permission, dict):
                    raise DashboardUnavailable("DASHBOARD_PROJECTION_INVALID")
                if installed and permission.get("name") == CONTROL_CAPABILITY:
                    permission["control_state"] = (
                        "READY" if authenticated else "AUTHENTICATION_REQUIRED"
                    )
                else:
                    permission["control_state"] = "NOT_AVAILABLE"
            return snapshot

        def _get(self, *, include_body: bool) -> None:
            if not self._host_allowed():
                self._deny_host(include_body=include_body)
                return
            path = urlsplit(self.path).path
            if path == "/":
                self._send(
                    200,
                    _static_bytes("index.html"),
                    "text/html; charset=utf-8",
                    include_body=include_body,
                )
                return
            if path in _ASSETS:
                name, content_type = _ASSETS[path]
                self._send(
                    200,
                    _static_bytes(name),
                    content_type,
                    include_body=include_body,
                )
                return
            if path == "/api/dashboard":
                try:
                    snapshot = self._dashboard_payload()
                except DashboardUnavailable as error:
                    self._json(
                        503,
                        {
                            "error": str(error),
                            "mode": (
                                "CONTROLLED_HOST_APPLY" if controls else "READ_ONLY"
                            ),
                        },
                        include_body=include_body,
                    )
                    return
                self._json(200, snapshot, include_body=include_body)
                return
            if path == "/api/operator/session":
                if sessions is None:
                    self._json(
                        200,
                        {"installed": False, "authenticated": False},
                        include_body=include_body,
                    )
                    return
                try:
                    session = self._session(require_csrf=False)
                except DashboardControlDenied:
                    self._json(
                        200,
                        {"installed": True, "authenticated": False},
                        include_body=include_body,
                    )
                    return
                self._json(
                    200,
                    {
                        "installed": True,
                        "authenticated": True,
                        "principal_id": session["principal_id"],
                        "session_id_sha256": session["session_id_sha256"],
                        "csrf_token": session["csrf_token"],
                        "expires_at": session["expires_at"],
                    },
                    include_body=include_body,
                )
                return
            self._json(
                404,
                {
                    "error": "DASHBOARD_ROUTE_NOT_FOUND",
                    "mode": "CONTROLLED_HOST_APPLY" if controls else "READ_ONLY",
                },
                include_body=include_body,
            )

        def do_GET(self) -> None:  # noqa: N802
            self._get(include_body=True)

        def do_HEAD(self) -> None:  # noqa: N802
            self._get(include_body=False)

        def _read_json(self) -> Mapping[str, Any]:
            if self.headers.get("Transfer-Encoding"):
                raise DashboardControlDenied("CONTROL_REQUEST_INVALID")
            content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip()
            if content_type.casefold() != "application/json":
                raise DashboardControlDenied("CONTROL_CONTENT_TYPE_REQUIRED")
            raw_length = self.headers.get("Content-Length")
            try:
                length = int(raw_length or "")
            except ValueError as error:
                raise DashboardControlDenied("CONTROL_REQUEST_INVALID") from error
            if not 1 <= length <= _MAX_REQUEST_BYTES:
                raise DashboardControlDenied("CONTROL_REQUEST_TOO_LARGE")
            body = self.rfile.read(length)
            if len(body) != length:
                raise DashboardControlDenied("CONTROL_REQUEST_INVALID")
            try:
                payload = json.loads(body.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise DashboardControlDenied("CONTROL_REQUEST_INVALID") from error
            if not isinstance(payload, Mapping):
                raise DashboardControlDenied("CONTROL_REQUEST_INVALID")
            return payload

        @staticmethod
        def _exact_body(
            body: Mapping[str, Any], fields: set[str]
        ) -> Mapping[str, Any]:
            if {str(key) for key in body} != fields:
                raise DashboardControlDenied("CONTROL_REQUEST_INVALID")
            return body

        def _control_error(self, error: DashboardControlDenied) -> None:
            reason = error.reason_code
            if reason in {
                "OPERATOR_AUTHENTICATION_REQUIRED",
                "OPERATOR_SESSION_EXPIRED",
            }:
                status = 401
            elif reason in {
                "OPERATOR_CSRF_DENIED",
                "OPERATOR_SESSION_DENIED",
                "OPERATOR_BOOTSTRAP_CONSUMPTION_FAILED",
                "OPERATOR_CONFIRMATION_INVALID",
                "OPERATOR_PRINCIPAL_MISMATCH",
                "CONTROL_TARGET_DENIED",
            }:
                status = 403
            elif reason == "GLOBAL_KILL_SWITCH_ACTIVE":
                status = 423
            elif reason in {
                "CONTROL_PREVIEW_STALE",
                "OPERATOR_CONFIRMATION_EXPIRED",
                "CONTROL_CONFIRMATION_REPLAYED",
                "CONTROL_NO_CHANGE",
                "CONTROL_ENABLE_WITH_ACTIVE_LEASES_DENIED",
                "CONTROL_DATABASE_CHANGED",
            }:
                status = 409
            elif reason == "CONTROL_ENDPOINT_NOT_INSTALLED":
                status = 405
            else:
                status = 400
            self._json(
                status,
                {
                    "error": reason,
                    "mode": "CONTROLLED_HOST_APPLY" if controls else "READ_ONLY",
                },
            )

        def _open_session(self, body: Mapping[str, Any]) -> None:
            if sessions is None:
                raise DashboardControlDenied("CONTROL_ENDPOINT_NOT_INSTALLED")
            row = self._exact_body(body, {"bootstrap_token"})
            opened = sessions.open_session(row["bootstrap_token"])
            cookie = (
                f"{_COOKIE_NAME}={opened['session_token']}; HttpOnly; "
                f"SameSite=Strict; Path=/; Max-Age=900"
            )
            self._json(
                200,
                {
                    "installed": True,
                    "authenticated": True,
                    "principal_id": opened["principal_id"],
                    "session_id_sha256": opened["session_id_sha256"],
                    "csrf_token": opened["csrf_token"],
                    "expires_at": opened["expires_at"],
                },
                headers={"Set-Cookie": cookie},
            )

        def _post(self) -> None:
            if not self._host_allowed():
                self._deny_host()
                return
            if controls is None or sessions is None:
                self._deny_mutation()
                return
            if not self._origin_allowed():
                self._json(
                    403,
                    {
                        "error": "DASHBOARD_ORIGIN_DENIED",
                        "mode": "CONTROLLED_HOST_APPLY",
                    },
                )
                return
            path = urlsplit(self.path).path
            try:
                body = self._read_json()
                if path == "/api/operator/session":
                    self._open_session(body)
                    return
                session = self._session(require_csrf=True)
                self._assert_control_database()
                if path == "/api/controls/preview":
                    row = self._exact_body(body, {"draft"})
                    payload = controls.preview(
                        row["draft"], expires_at=session["expires_at"]
                    )
                elif path == "/api/controls/confirm":
                    row = self._exact_body(body, {"preview"})
                    payload = controls.confirm(row["preview"], session=session)
                elif path == "/api/controls/apply":
                    row = self._exact_body(body, {"preview", "confirmation"})
                    payload = controls.apply(
                        row["preview"],
                        row["confirmation"],
                        session_id_sha256=session["session_id_sha256"],
                    )
                    self._assert_control_database()
                else:
                    self._json(
                        404,
                        {
                            "error": "DASHBOARD_ROUTE_NOT_FOUND",
                            "mode": "CONTROLLED_HOST_APPLY",
                        },
                    )
                    return
                self._json(200, dict(payload))
            except DashboardControlDenied as error:
                self._control_error(error)
            except (KeyError, TypeError, ValueError):
                self._json(
                    400,
                    {
                        "error": "CONTROL_REQUEST_INVALID",
                        "mode": "CONTROLLED_HOST_APPLY",
                    },
                )
            except Exception:
                self._json(
                    500,
                    {
                        "error": "CONTROL_INTERNAL_ERROR",
                        "mode": "CONTROLLED_HOST_APPLY",
                    },
                )

        def do_POST(self) -> None:  # noqa: N802
            self._post()

        def _deny_mutation(self) -> None:
            if not self._host_allowed():
                self._deny_host()
                return
            self._json(
                405,
                {
                    "error": "READ_ONLY_DASHBOARD" if controls is None else "CONTROL_METHOD_DENIED",
                    "detail": (
                        "Mutation endpoints are not installed in this release."
                        if controls is None
                        else "Use the exact authenticated preview, confirmation, and apply routes."
                    ),
                },
            )

        do_PUT = _deny_mutation  # type: ignore[assignment]
        do_PATCH = _deny_mutation  # type: ignore[assignment]
        do_DELETE = _deny_mutation  # type: ignore[assignment]
        do_OPTIONS = _deny_mutation  # type: ignore[assignment]

        def log_message(self, format: str, *args: object) -> None:
            del format, args

    return DashboardHandler


class _IPv6ThreadingHTTPServer(ThreadingHTTPServer):
    address_family = socket.AF_INET6


def create_dashboard_server(
    *,
    database: str | Path,
    host: str = "127.0.0.1",
    port: int = 8787,
    now: Callable[[], str] | None = None,
    sessions: DashboardSessionAuthority | None = None,
    controls: DashboardControlService | None = None,
) -> ThreadingHTTPServer:
    bind_host = validate_bind_host(host)
    if isinstance(port, bool) or not isinstance(port, int) or not 0 <= port <= 65_535:
        raise ValueError("dashboard port must be between 0 and 65535")
    if (sessions is None) != (controls is None):
        raise ValueError("dashboard sessions and controls must be installed together")
    database_path = Path(database).expanduser().absolute()
    control_identity = None
    if controls is not None:
        if controls.sessions is not sessions:
            raise ValueError("dashboard controls must use the configured session authority")
        if sessions is None or sessions.durable_bootstrap_consumption is not True:
            raise ValueError(
                "controlled dashboard requires durable bootstrap-file consumption"
            )
        if controls.store.path.expanduser().absolute() != database_path:
            raise ValueError("dashboard controls must bind the displayed database")
        control_identity = _control_database_identity(database_path)
    server_type = _IPv6ThreadingHTTPServer if bind_host == "::1" else ThreadingHTTPServer
    return server_type(
        (bind_host, port),
        _handler(database_path, now, sessions, controls, control_identity),
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="cct-dashboard",
        description="Run the loopback-only CCTAE operator dashboard.",
    )
    parser.add_argument("--db", required=True, help="Existing CCTAE agency.sqlite path")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument(
        "--operator-bootstrap",
        help="Owner-only bootstrap JSON enabling the bounded operator.web control",
    )
    args = parser.parse_args(argv)
    database = Path(args.db).expanduser().absolute()
    sessions = None
    controls = None
    if args.operator_bootstrap:
        bootstrap = load_operator_bootstrap(Path(args.operator_bootstrap))
        _control_database_identity(database)
        sessions = DashboardSessionAuthority(bootstrap)
        controls = DashboardControlService(EventStore(database), sessions=sessions)
        _control_database_identity(database)
    server = create_dashboard_server(
        database=database,
        host=args.host,
        port=args.port,
        sessions=sessions,
        controls=controls,
    )
    shown_host = f"[{args.host}]" if args.host == "::1" else args.host
    mode = "CONTROLLED_HOST_APPLY" if controls is not None else "READ_ONLY"
    print(
        f"CCTAE dashboard {mode} at "
        f"http://{shown_host}:{server.server_address[1]}/"
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
