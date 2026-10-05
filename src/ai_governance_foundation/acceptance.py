"""运行基础服务与事件处置服务的离线端到端验收。"""

from __future__ import annotations

import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from .clock import FixedClock
from .incident_service import IncidentService
from .service import DomainService
from .storage import Database


def _bootstrap(service: DomainService) -> None:
    service.register_organization(request_id="req-org", actor_id="bootstrap",
                                  organization_id="org-001", name="示范科研机构")
    service.register_actor(request_id="req-admin", actor_id="bootstrap", new_actor_id="admin-001",
                           display_name="系统管理员", role="admin", organization_id="org-001")
    service.register_actor(request_id="req-operator", actor_id="admin-001",
                           new_actor_id="operator-001", display_name="项目负责人",
                           role="operator", organization_id="org-001")
    service.register_actor(request_id="req-reviewer", actor_id="admin-001",
                           new_actor_id="reviewer-001", display_name="值班安全负责人",
                           role="reviewer", organization_id="org-001")
    service.register_site(request_id="req-site", actor_id="operator-001", site_id="site-001",
                          organization_id="org-001", name="一号创新节点",
                          timezone_name="Asia/Shanghai")


def _foundation_chain(service: DomainService) -> dict[str, object]:
    first = service.record_domain_data(request_id="req-data", actor_id="operator-001",
                                       site_id="site-001", category="institution_profile",
                                       external_key="record-001",
                                       data={"name": "基础资料", "enabled": True})
    replay = service.record_domain_data(request_id="req-data", actor_id="operator-001",
                                        site_id="site-001", category="institution_profile",
                                        external_key="record-001",
                                        data={"name": "基础资料", "enabled": True})
    return {"first_replayed": first.replayed, "second_replayed": replay.replayed}


def _incident_chain(incidents: IncidentService) -> dict[str, object]:
    """技术团队先以不完整信息上报，系统先行隔离，随后合并、升级、处置并结案。"""

    # 信息不全：缺少影响范围与证据摘要，事件进入隔离而不是被丢弃
    reported = incidents.report_incident(
        request_id="inc-tech", actor_id="operator-001", source="agent-gateway",
        severity="medium", source_ref="AGENT-2026-1005-01")
    incident_id = reported["incident_id"]
    quarantined_view = incidents.get_incident("operator-001", incident_id)

    # 隔离期间仍可先执行遏制动作
    incidents.complete_action(request_id="inc-contain", actor_id="operator-001",
                              incident_id=incident_id, code="contain")

    # 业务方补齐影响范围与证据摘要，解除隔离
    incidents.supplement_incident(
        request_id="inc-supplement", actor_id="operator-001", incident_id=incident_id,
        impact_scope={"systems": ["工单系统"], "external_endpoints": ["vendor.example"],
                      "affected_users": 42},
        evidence_summary="网关审计日志显示智能体使用过期凭据外呼供应商接口")

    # 法务方就同一事件再次上报（相同来源事件号），自动合并且按更高严重级别升级
    merged = incidents.report_incident(
        request_id="inc-legal", actor_id="reviewer-001", source="agent-gateway",
        severity="high", source_ref="AGENT-2026-1005-01",
        impact_scope={"regulatory_window": "72h"}, evidence_summary="法务确认存在对外通报义务")

    # 值班安全负责人指定责任人
    incidents.assign_owner(request_id="inc-owner", actor_id="reviewer-001",
                           incident_id=incident_id, assignee_id="operator-001")

    # 重启前：推进通报；未送达的通报在重新打开服务后继续
    first_delivery = incidents.deliver_pending_notifications()

    # 按处置方案完成全部阻断动作
    view = incidents.get_incident("reviewer-001", incident_id)
    completed = 0
    used_requests: set[str] = set()
    for action in view["actions"]:
        if action["status"] != "pending":
            continue
        actor = "operator-001" if action["owner_role"] == "operator" else "reviewer-001"
        request = f"inc-done-{action['code']}"
        if request in used_requests:
            continue
        used_requests.add(request)
        incidents.complete_action(request_id=request, actor_id=actor,
                                  incident_id=incident_id, code=action["code"])
        completed += 1

    # 通报全部送达后才能结案
    second_delivery = incidents.deliver_pending_notifications()
    incidents.close_incident(
        request_id="inc-close", actor_id="reviewer-001", incident_id=incident_id,
        conclusion="确认越权外呼已切断，凭据已轮换，供应商侧无数据落库；已按时完成监管与内部通报")
    final = incidents.get_incident("reviewer-001", incident_id)

    return {
        "incident_id": incident_id,
        "initially_quarantined": quarantined_view["status"] == "quarantined",
        "merged": merged["merged"],
        "final_severity": final["severity"],
        "report_count": final["report_count"],
        "actions_completed": completed,
        "first_delivery": first_delivery,
        "second_delivery": second_delivery,
        "final_status": final["status"],
        "owner": final["owner"]["assignee"]["actor_id"],
        "pending_actions_left": len(final["pending_actions"]),
        "timeline_kinds": [entry["kind"] for entry in final["timeline"]],
        "timeline_versions": [entry["version"] for entry in final["timeline"]
                              if entry["version"] is not None],
        "conclusion": final["conclusion"],
    }


def run() -> dict[str, object]:
    """执行完整登记与事件处置链并返回结果。"""

    with tempfile.TemporaryDirectory() as directory:
        database = Database(Path(directory) / "acceptance.sqlite3")
        service = DomainService(database, FixedClock(
            datetime(2026, 10, 5, 8, 0, tzinfo=timezone.utc)))
        incidents = IncidentService(database, service.clock)
        _bootstrap(service)
        foundation = _foundation_chain(service)
        incident = _incident_chain(incidents)
        valid, event_count = service.verify_audit()
        record_count = len(service.list_domain_data("site-001"))

        # 模拟重新打开服务：状态、未送达通报与时间线都从 SQLite 恢复
        database.close()
        reopened_db = Database(Path(directory) / "acceptance.sqlite3")
        reopened_service = DomainService(reopened_db, FixedClock(
            datetime(2026, 10, 5, 9, 30, tzinfo=timezone.utc)))
        reopened_incidents = IncidentService(reopened_db, reopened_service.clock)
        after_restart = reopened_incidents.get_incident("reviewer-001", incident["incident_id"])
        pending_after_restart = reopened_incidents.pending_notification_summary("reviewer-001")
        reopened_valid, _ = reopened_service.verify_audit()
        reopened_db.close()

        result = {
            "status": "ok",
            "audit_events": event_count,
            "audit_valid": valid and reopened_valid,
            "records": record_count,
            **foundation,
            "incident": incident,
            "after_restart": {
                "status": after_restart["status"],
                "timeline_entries": len(after_restart["timeline"]),
                "pending_notifications": pending_after_restart["pending_notifications"],
            },
        }
        return result


def main() -> int:
    """打印验收结果并设置退出码。"""

    result = run()
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
    incident = result["incident"]
    ok = (
        result["status"] == "ok"
        and result["audit_valid"]
        and result["first_replayed"] is False
        and result["second_replayed"] is True
        and incident["initially_quarantined"]
        and incident["merged"]
        and incident["final_severity"] == "high"
        and incident["final_status"] == "closed"
        and incident["pending_actions_left"] == 0
        and result["after_restart"]["pending_notifications"] == 0
    )
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
