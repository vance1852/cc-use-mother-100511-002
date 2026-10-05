"""定义基础服务在模块边界使用的数据对象。"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Actor:
    """表示具有明确角色的后台操作者。"""

    actor_id: str
    display_name: str
    role: str
    organization_id: str
    active: bool


@dataclass(frozen=True)
class Site:
    """表示科研创新机构下的业务场所。"""

    site_id: str
    organization_id: str
    name: str
    timezone_name: str
    version: int


@dataclass(frozen=True)
class DomainRecord:
    """表示已经持久化的领域资料记录。"""

    record_id: str
    site_id: str
    category: str
    external_key: str
    payload: dict[str, Any]
    created_by: str
    created_at: str


@dataclass(frozen=True)
class WriteReceipt:
    """描述一次幂等写入的稳定结果。"""

    request_id: str
    resource_type: str
    resource_id: str
    replayed: bool


@dataclass(frozen=True)
class IncidentAction:
    """表示事件处置方案中的一个可跟踪动作。"""

    action_id: str
    incident_id: str
    code: str
    title: str
    stage: str
    owner_role: str
    blocking: bool
    sla_hours: int | None
    status: str
    sort_order: int
    assignee_id: str | None
    created_at: str
    completed_at: str | None


@dataclass(frozen=True)
class IncidentNotification:
    """表示一次需要送达的处置通报。"""

    notification_id: str
    incident_id: str
    recipient: str
    recipient_name: str
    channel: str
    sla_minutes: int | None
    status: str
    attempts: int
    last_error: str | None
    created_at: str
    delivered_at: str | None
