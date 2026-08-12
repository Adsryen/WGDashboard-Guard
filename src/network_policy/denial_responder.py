"""Minimal local HTTP responder for denied WireGuard forwarding requests."""

from __future__ import annotations

from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import argparse
import json

from .compiler import DENIAL_RESPONSE_PORT


def _prefers_chinese(value: str) -> bool:
    return any(part.strip().lower().startswith("zh") for part in value.split(","))


def _prefers_json(accept: str, path: str) -> bool:
    return "application/json" in accept.lower() or path.startswith("/api/")


def denial_payload(chinese: bool) -> dict[str, str]:
    return {
        "error": "vpn_access_denied",
        "message": "当前 VPN 端点没有访问权限，请联系管理员申请。"
        if chinese
        else "This VPN endpoint is not authorized to access this resource. Contact an administrator.",
    }


def denial_html(chinese: bool) -> str:
    if chinese:
        title = "VPN 访问被拒绝"
        message = "当前 VPN 端点没有访问权限。"
        detail = "请联系管理员申请所需资源的访问权限。"
    else:
        title = "VPN access denied"
        message = "This VPN endpoint is not authorized to access this resource."
        detail = "Contact an administrator to request access."
    return f"""<!doctype html>
<html lang={'zh-CN' if chinese else 'en'}>
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>{title}</title></head>
<body><main><h1>{title}</h1><p>{message}</p><p>{detail}</p></main></body>
</html>"""


class DenialRequestHandler(BaseHTTPRequestHandler):
    server_version = "WGDashboardVPNDenial"
    sys_version = ""

    def _respond(self) -> None:
        chinese = _prefers_chinese(self.headers.get("Accept-Language", ""))
        if _prefers_json(self.headers.get("Accept", ""), self.path):
            body = json.dumps(denial_payload(chinese), ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            content_type = "application/json; charset=utf-8"
        else:
            body = denial_html(chinese).encode("utf-8")
            content_type = "text/html; charset=utf-8"
        self.send_response(HTTPStatus.FORBIDDEN)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    do_GET = _respond
    do_HEAD = _respond
    do_POST = _respond
    do_PUT = _respond
    do_PATCH = _respond
    do_DELETE = _respond
    do_OPTIONS = _respond
    do_CONNECT = _respond

    def log_message(self, format: str, *args) -> None:
        """Avoid recording requested paths or source details in responder logs."""


def serve(host: str = "0.0.0.0", port: int = DENIAL_RESPONSE_PORT) -> None:
    ThreadingHTTPServer((host, port), DenialRequestHandler).serve_forever()


def main() -> None:
    parser = argparse.ArgumentParser(description="WGDashboard VPN denial responder")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=DENIAL_RESPONSE_PORT)
    args = parser.parse_args()
    serve(args.host, args.port)


if __name__ == "__main__":
    main()
