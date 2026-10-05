"""提供领域服务共享的时钟、幂等、权限与输入校验能力。"""

from __future__ import annotations

import json
import re
from typing import Any, Callable

from .audit import canonical_json, digest
from .clock import Clock, SystemClock
from .errors import ConflictError, NotFoundError, PermissionDenied, ValidationError
from .models import Actor, WriteReceipt


IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{1,63}$")
ROLES = frozenset({"admin", "operator", "reviewer", "auditor"})


class BaseService:
    """协调权限、幂等、事务和审计规则的公共基类。"""

    def __init__(self, database, clock: Clock | None = None) -> None:
        self.database = database
        self.clock = clock or SystemClock()

    def _now(self) -> str:
        return self.clock.now().isoformat().replace("+00:00", "Z")

    def _identifier(self, value: str, field: str) -> str:
        value = str(value).strip()
        if not IDENTIFIER.fullmatch(value):
            raise ValidationError(f"{field} 格式无效")
        return value

    def _text(self, value: str, field: str, limit: int = 200) -> str:
        value = str(value).strip()
        if not value or len(value) > limit:
            raise ValidationError(f"{field} 不能为空且不能超过 {limit} 个字符")
        return value

    def _optional_text(self, value: str | None, field: str, limit: int = 200) -> str | None:
        if value is None or not str(value).strip():
            return None
        return self._text(value, field, limit)

    def _actor(self, connection, actor_id: str) -> Actor:
        row = connection.execute("SELECT * FROM actors WHERE actor_id=?", (actor_id,)).fetchone()
        if row is None:
            raise NotFoundError("操作者不存在")
        actor = Actor(row["actor_id"], row["display_name"], row["role"],
                      row["organization_id"], bool(row["active"]))
        if not actor.active:
            raise PermissionDenied("操作者已停用")
        return actor

    def _require(self, actor: Actor, *roles: str) -> None:
        if actor.role not in roles:
            raise PermissionDenied("当前角色不能执行该动作")

    def _idempotent_ex(
        self,
        connection,
        *,
        request_id: str,
        action: str,
        payload: dict[str, Any],
        create: Callable[[], tuple[str, str, dict[str, Any]]],
    ) -> tuple[WriteReceipt, dict[str, Any]]:
        """执行幂等写入，同时返回收据和业务响应。"""

        request_id = self._identifier(request_id, "request_id")
        payload_hash = digest(payload)
        row = connection.execute(
            "SELECT * FROM request_receipts WHERE request_id=?", (request_id,)
        ).fetchone()
        if row:
            if row["action"] != action or row["payload_hash"] != payload_hash:
                raise ConflictError("request_id 已被不同内容使用")
            receipt = WriteReceipt(request_id, row["resource_type"], row["resource_id"], True)
            return receipt, json.loads(row["response_json"])
        resource_type, resource_id, response = create()
        connection.execute(
            "INSERT INTO request_receipts(request_id,action,payload_hash,resource_type,resource_id,"
            "response_json,created_at) VALUES(?,?,?,?,?,?,?)",
            (request_id, action, payload_hash, resource_type, resource_id,
             canonical_json(response), self._now()),
        )
        return WriteReceipt(request_id, resource_type, resource_id, False), response

    def _idempotent(
        self,
        connection,
        *,
        request_id: str,
        action: str,
        payload: dict[str, Any],
        create: Callable[[], tuple[str, str, dict[str, Any]]],
    ) -> WriteReceipt:
        """执行幂等写入并返回收据。"""

        receipt, _ = self._idempotent_ex(
            connection, request_id=request_id, action=action, payload=payload, create=create
        )
        return receipt
