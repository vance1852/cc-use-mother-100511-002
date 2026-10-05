"""按事件严重级别生成处置阶段、动作清单与通报对象。"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


# 严重级别自低而高，升级时据此补齐中间级别的动作与通报。
SEVERITIES = ("low", "medium", "high", "critical")
SEVERITY_LABELS = {
    "low": "低",
    "medium": "中",
    "high": "高",
    "critical": "危急",
}


@dataclass(frozen=True)
class ActionSpec:
    """描述一个处置阶段内需要完成的动作。"""

    code: str
    title: str
    stage: str
    owner_role: str
    blocking: bool = True
    sla_hours: int | None = None


@dataclass(frozen=True)
class NotificationSpec:
    """描述一个必须送达的通报对象及其时限。"""

    recipient: str
    recipient_name: str
    channel: str
    sla_minutes: int | None


@dataclass(frozen=True)
class SeverityPlan:
    """描述某一严重级别的完整处置方案。"""

    severity: str
    stage_codes: tuple[str, ...]
    actions: tuple[ActionSpec, ...]
    notifications: tuple[NotificationSpec, ...]
    owner_role: str


# 处置阶段（所有级别共用同一顺序骨架，按级别取前缀并插入额外关卡）。
STAGE_LABELS = {
    "triage": "分诊确认",
    "containment": "隔离遏制",
    "investigation": "调查取证",
    "review": "法务/合规复核",
    "remediation": "修复处置",
    "verification": "验证与结论",
}


def _plan(
    severity: str,
    stage_codes: tuple[str, ...],
    actions: tuple[ActionSpec, ...],
    notifications: tuple[NotificationSpec, ...],
    owner_role: str,
) -> SeverityPlan:
    return SeverityPlan(severity, stage_codes, actions, notifications, owner_role)


_PLANS: dict[str, SeverityPlan] = {
    "low": _plan(
        "low",
        ("triage", "investigation", "verification"),
        (
            ActionSpec("triage", "分诊并确认影响", "triage", "operator", sla_hours=24),
            ActionSpec("assess", "评估是否需要进一步处置", "investigation", "reviewer", sla_hours=48),
            ActionSpec("document", "记录结论并归档", "verification", "operator", sla_hours=72),
        ),
        (NotificationSpec("team_lead", "业务团队负责人", "console", 240),),
        "operator",
    ),
    "medium": _plan(
        "medium",
        ("triage", "containment", "investigation", "remediation", "verification"),
        (
            ActionSpec("triage", "分诊并确认影响", "triage", "operator", sla_hours=8),
            ActionSpec("contain", "限制涉事智能体的外部访问", "containment", "operator", sla_hours=12),
            ActionSpec("investigate", "调查访问链路与证据", "investigation", "reviewer", sla_hours=24),
            ActionSpec("remediate", "执行修复并恢复服务", "remediation", "operator", sla_hours=48),
            ActionSpec("verify", "验证修复并给出结论", "verification", "reviewer", sla_hours=72),
        ),
        (
            NotificationSpec("team_lead", "业务团队负责人", "console", 120),
            NotificationSpec("security_oncall", "安全值班组", "console", 120),
        ),
        "operator",
    ),
    "high": _plan(
        "high",
        ("triage", "containment", "investigation", "review", "remediation", "verification"),
        (
            ActionSpec("triage", "分诊并确认影响范围", "triage", "operator", sla_hours=2),
            ActionSpec("contain", "立即隔离涉事智能体与凭据", "containment", "operator", sla_hours=4),
            ActionSpec("investigate", "保全证据并调查根因", "investigation", "reviewer", sla_hours=12),
            ActionSpec("legal_review", "法务合规复核通报义务", "review", "reviewer", sla_hours=24),
            ActionSpec("remediate", "执行修复并恢复服务", "remediation", "operator", sla_hours=48),
            ActionSpec("verify", "验证修复、出具结论", "verification", "reviewer", sla_hours=72),
        ),
        (
            NotificationSpec("security_oncall", "安全值班组", "console", 30),
            NotificationSpec("duty_security_officer", "值班安全负责人", "console", 30),
            NotificationSpec("legal", "法务合规", "console", 60),
            NotificationSpec("business_owner", "业务方负责人", "console", 60),
        ),
        "reviewer",
    ),
    "critical": _plan(
        "critical",
        ("containment", "investigation", "review", "remediation", "verification"),
        (
            ActionSpec("emergency_isolate", "紧急切断全部外部访问", "containment", "operator", sla_hours=1),
            ActionSpec("contain", "隔离涉事智能体、凭据与网络区域", "containment", "operator", sla_hours=2),
            ActionSpec("investigate", "全面保全证据并调查根因", "investigation", "reviewer", sla_hours=6),
            ActionSpec("legal_review", "法务合规复核监管通报义务", "review", "reviewer", sla_hours=8),
            ActionSpec("executive_report", "向管理层提交态势报告", "review", "reviewer", sla_hours=12),
            ActionSpec("remediate", "执行修复并分批恢复服务", "remediation", "operator", sla_hours=24),
            ActionSpec("postmortem", "复盘并落实改进措施", "verification", "reviewer", sla_hours=72),
        ),
        (
            NotificationSpec("security_oncall", "安全值班组", "console", 10),
            NotificationSpec("duty_security_officer", "值班安全负责人", "console", 10),
            NotificationSpec("legal", "法务合规", "console", 30),
            NotificationSpec("business_owner", "业务方负责人", "console", 30),
            NotificationSpec("executive", "管理层值班代表", "console", 30),
        ),
        "reviewer",
    ),
}


def is_valid_severity(value: str) -> bool:
    return value in _PLANS


def plan_for(severity: str) -> SeverityPlan:
    try:
        return _PLANS[severity]
    except KeyError as exc:
        raise ValueError(f"未知严重级别: {severity}") from exc


def stages_for(severity: str) -> list[dict[str, Any]]:
    plan = plan_for(severity)
    return [{"code": code, "title": STAGE_LABELS[code]} for code in plan.stage_codes]


def missing_action_codes(current_severity: str, target_severity: str) -> list[str]:
    """升级时返回需要新增的动作代码（目标级别有而当前级别没有的）。"""

    current = {spec.code for spec in plan_for(current_severity).actions}
    target = plan_for(target_severity).actions
    return [spec.code for spec in target if spec.code not in current]


def missing_notification_recipients(current_severity: str, target_severity: str) -> list[str]:
    """升级时返回需要新增通报的对象。"""

    current = {spec.recipient for spec in plan_for(current_severity).notifications}
    target = plan_for(target_severity).notifications
    return [spec.recipient for spec in target if spec.recipient not in current]
