"""提供不依赖第三方框架的 HTTP/JSON 边界。"""

from __future__ import annotations

import argparse
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

from .errors import DomainError, ValidationError
from .incident_service import IncidentService
from .service import DomainService
from .storage import Database


def _incident_path(path: str) -> tuple[str | None, str | None]:
    """拆分 /incidents/{id}/... 路径，返回 (incident_id, 子动作)。"""

    parts = [part for part in urlparse(path).path.strip("/").split("/") if part]
    if len(parts) < 2 or parts[0] != "incidents":
        return None, None
    incident_id = parts[1]
    action = "/".join(parts[2:]) if len(parts) > 2 else ""
    return incident_id, action


def route(service: DomainService, method: str, path: str, body: dict[str, Any] | None,
          headers: dict[str, str] | None = None) -> tuple[int, dict[str, Any]]:
    """把一个 HTTP 语义请求分派到领域服务。"""

    headers = headers or {}
    body = body or {}
    parsed = urlparse(path)
    actor_id = headers.get("X-Actor-Id", "")
    incidents = IncidentService(service.database, service.clock)
    try:
        if method == "GET" and parsed.path == "/health":
            valid, count = service.verify_audit()
            return 200, {"status": "ok", "audit_valid": valid, "audit_events": count}
        if method == "POST" and parsed.path == "/organizations":
            receipt = service.register_organization(actor_id=actor_id, **body)
            return 200 if receipt.replayed else 201, receipt.__dict__
        if method == "POST" and parsed.path == "/actors":
            receipt = service.register_actor(actor_id=actor_id, **body)
            return 200 if receipt.replayed else 201, receipt.__dict__
        if method == "POST" and parsed.path == "/sites":
            receipt = service.register_site(actor_id=actor_id, **body)
            return 200 if receipt.replayed else 201, receipt.__dict__
        if method == "POST" and parsed.path == "/domain-records":
            receipt = service.record_domain_data(actor_id=actor_id, **body)
            return 200 if receipt.replayed else 201, receipt.__dict__
        if method == "GET" and parsed.path == "/domain-records":
            query = parse_qs(parsed.query)
            site_id = query.get("site_id", [""])[0]
            if not site_id:
                raise ValidationError("site_id 不能为空")
            category = query.get("category", [None])[0]
            return 200, {"items": [item.__dict__ for item in service.list_domain_data(site_id, category)]}
        if method == "GET" and parsed.path == "/audit-events":
            query = parse_qs(parsed.query)
            after = int(query.get("after_sequence", ["0"])[0])
            return 200, {"items": service.audit_events(after)}

        # ----------------------------------------------------- 事件处置服务

        if method == "POST" and parsed.path == "/incidents":
            result = incidents.report_incident(actor_id=actor_id, **body)
            return 200 if result["receipt"]["replayed"] else 201, result
        if method == "GET" and parsed.path == "/incidents":
            query = parse_qs(parsed.query)
            items = incidents.list_incidents(
                actor_id,
                status=query.get("status", [None])[0],
                organization_id=query.get("organization_id", [None])[0],
            )
            return 200, {"items": items}
        incident_id, action = _incident_path(parsed.path)
        if incident_id is not None:
            if method == "GET" and action == "":
                return 200, incidents.get_incident(actor_id, incident_id)
            if method == "POST" and action == "supplement":
                return 200, incidents.supplement_incident(
                    actor_id=actor_id, incident_id=incident_id, **body)
            if method == "POST" and action == "escalate":
                return 200, incidents.escalate_incident(
                    actor_id=actor_id, incident_id=incident_id, **body)
            if method == "POST" and action == "withdraw":
                return 200, incidents.withdraw_false_positive(
                    actor_id=actor_id, incident_id=incident_id, **body)
            if method == "POST" and action == "actions/complete":
                return 200, incidents.complete_action(
                    actor_id=actor_id, incident_id=incident_id, **body)
            if method == "POST" and action == "owner":
                return 200, incidents.assign_owner(
                    actor_id=actor_id, incident_id=incident_id, **body)
            if method == "POST" and action == "close":
                return 200, incidents.close_incident(
                    actor_id=actor_id, incident_id=incident_id, **body)
            if method == "POST" and action == "reopen":
                return 200, incidents.reopen_incident(
                    actor_id=actor_id, incident_id=incident_id, **body)
        if method == "POST" and parsed.path == "/incident-notifications/deliver":
            result = incidents.deliver_pending_notifications(
                limit=int(body.get("limit", 100)))
            return 200, result
        if method == "GET" and parsed.path == "/incident-notifications/pending":
            return 200, incidents.pending_notification_summary(actor_id)
        return 404, {"error": "route_not_found", "message": "接口不存在"}
    except DomainError as exc:
        return exc.status, {"error": exc.code, "message": str(exc)}
    except (TypeError, ValueError) as exc:
        return 400, {"error": "invalid_request", "message": str(exc)}


class Handler(BaseHTTPRequestHandler):
    """把标准库 HTTP 请求转换为路由调用。"""

    service: DomainService

    def _handle(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length) if length else b"{}"
        try:
            body = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._write(400, {"error": "invalid_json", "message": "请求体必须是 UTF-8 JSON"})
            return
        status, payload = route(self.service, self.command, self.path, body,
                                {"X-Actor-Id": self.headers.get("X-Actor-Id", "")})
        self._write(status, payload)

    def _write(self, status: int, payload: dict[str, Any]) -> None:
        data = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        self._handle()

    def do_POST(self) -> None:
        self._handle()

    def log_message(self, format: str, *args: object) -> None:
        return


def _start_notification_pump(service: DomainService, interval_seconds: float = 5.0):
    """启动后台线程：服务重启后自动继续推进未送达通报。"""

    incidents = IncidentService(service.database, service.clock)

    def _run() -> None:
        while True:
            try:
                incidents.deliver_pending_notifications()
            except Exception:
                pass
            time.sleep(interval_seconds)

    thread = threading.Thread(target=_run, name="notification-pump", daemon=True)
    thread.start()
    return thread


def main() -> int:
    """启动本地 HTTP 服务。"""

    parser = argparse.ArgumentParser(description="启动科技战略协作基础服务")
    parser.add_argument("--database", default="service.sqlite3")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    database = Database(args.database)
    service = DomainService(database)
    Handler.service = service
    _start_notification_pump(service)
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        database.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
