"""提供安全事件的登记、合并、隔离、升级、撤回与处置跟踪能力。"""

from __future__ import annotations

import json
import uuid
from typing import Any, Callable

from .audit import append_event, canonical_json, digest
from .base import BaseService
from .errors import ConflictError, NotFoundError, PermissionDenied, ValidationError
from .models import IncidentAction, IncidentNotification
from .policy import (
    SEVERITIES,
    STAGE_LABELS,
    is_valid_severity,
    missing_notification_recipients,
    plan_for,
)
from .storage import Database


# 事件生命周期状态。阶段细节由 current_stage 承载，状态保持精简稳定。
STATUS_REGISTERED = "registered"
STATUS_QUARANTINED = "quarantined"
STATUS_ACTIVE = "active"
STATUS_FALSE_POSITIVE = "false_positive"
STATUS_CLOSED = "closed"

TERMINAL_STATUSES = frozenset({STATUS_FALSE_POSITIVE, STATUS_CLOSED})
MUTATING_ROLES = ("admin", "operator", "reviewer")
REVIEW_ROLES = ("admin", "reviewer")

ACTION_PENDING = "pending"
ACTION_DONE = "done"
ACTION_CANCELED = "canceled"

NOTIFICATION_PENDING = "pending"
NOTIFICATION_DELIVERED = "delivered"
NOTIFICATION_CANCELED = "canceled"


class IncidentService(BaseService):
    """协调事件处置的权限、幂等、事务、时间线与持久化通报。"""

    def __init__(self, database: Database, clock=None,
                 sender: Callable[[dict[str, Any], dict[str, Any]], None] | None = None) -> None:
        super().__init__(database, clock)
        self._sender = sender or self._console_sender

    @staticmethod
    def _console_sender(notification: dict[str, Any], incident: dict[str, Any]) -> None:
        """默认控制台通道：写入站内通报队列，本地即可视为送达。"""

        return None

    # ------------------------------------------------------------------ 登记

    def report_incident(self, *, request_id: str, actor_id: str, source: str,
                        severity: str, impact_scope: dict[str, Any] | None = None,
                        evidence_summary: str | None = None,
                        evidence: list[dict[str, Any]] | None = None,
                        source_ref: str | None = None, dedup_key: str | None = None,
                        title: str | None = None) -> dict[str, Any]:
        """登记一次事件上报；与未结案事件同源同键时自动合并。"""

        payload = {"actor_id": actor_id, "source": source, "severity": severity,
                   "impact_scope": impact_scope, "evidence_summary": evidence_summary,
                   "evidence": evidence, "source_ref": source_ref, "dedup_key": dedup_key,
                   "title": title}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, *MUTATING_ROLES)
            source = self._text(source, "source", 120)
            if not is_valid_severity(severity):
                raise ValidationError("severity 必须是 low/medium/high/critical 之一")
            source_ref = self._optional_text(source_ref, "source_ref", 120)
            dedup_key = self._optional_text(dedup_key, "dedup_key", 120)
            title = self._optional_text(title, "title", 200) or f"{source} 事件上报"
            impact_scope = impact_scope if isinstance(impact_scope, dict) else None
            evidence_summary = evidence_summary.strip() if isinstance(evidence_summary, str) and evidence_summary.strip() else None
            evidence = self._validate_evidence(evidence)
            missing = self._missing_fields(impact_scope, evidence_summary)

            fingerprint = self._fingerprint(actor.organization_id, source, source_ref, dedup_key)
            existing = None
            if fingerprint:
                existing = connection.execute(
                    "SELECT * FROM incidents WHERE fingerprint=? AND status NOT IN (?, ?)",
                    (fingerprint, STATUS_FALSE_POSITIVE, STATUS_CLOSED),
                ).fetchone()

            def create() -> tuple[str, str, dict[str, Any]]:
                if existing is not None:
                    return self._merge_report(
                        connection, actor=actor, existing=existing, source=source,
                        severity=severity, impact_scope=impact_scope,
                        evidence_summary=evidence_summary, evidence=evidence,
                        source_ref=source_ref, moment=self._now(),
                    )
                return self._create_incident(
                    connection, actor=actor, source=source, severity=severity,
                    impact_scope=impact_scope, evidence_summary=evidence_summary, evidence=evidence,
                    source_ref=source_ref, dedup_key=dedup_key, fingerprint=fingerprint, title=title,
                    missing=missing,
                )

            receipt, response = self._idempotent_ex(
                connection, request_id=request_id, action="report_incident",
                payload=payload, create=create,
            )
            response["receipt"] = receipt.__dict__
            return response

    def _create_incident(self, connection, *, actor, source: str, severity: str,
                         impact_scope: dict[str, Any] | None, evidence_summary: str | None,
                         evidence: list[dict[str, Any]], source_ref: str | None,
                         dedup_key: str | None, fingerprint: str | None, title: str,
                         missing: list[str]) -> tuple[str, str, dict[str, Any]]:
        moment = self._now()
        incident_id = uuid.uuid4().hex
        plan = plan_for(severity)
        quarantined = bool(missing)
        status = STATUS_QUARANTINED if quarantined else STATUS_ACTIVE
        first_stage = self._clamp_quarantine_stage(
            severity, plan.stage_codes[0], quarantined
        )
        if fingerprint is None:
            fingerprint = digest({"incident_id": incident_id})
        connection.execute(
            "INSERT INTO incidents(incident_id,organization_id,source,source_ref,title,severity,"
            "impact_scope_json,evidence_summary,evidence_json,missing_fields_json,fingerprint,"
            "status,current_stage,owner_role,assignee_id,version,reopen_count,conclusion,"
            "report_count,created_at,updated_at,quarantined_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (incident_id, actor.organization_id, source, source_ref, title, severity,
             canonical_json(impact_scope or {}), evidence_summary, canonical_json(evidence),
             canonical_json(missing), fingerprint, status, first_stage, plan.owner_role, None, 1, 0,
             None, 1, moment, moment, moment if quarantined else None),
        )
        self._seed_actions(connection, incident_id, severity, moment)
        self._seed_notifications(connection, incident_id, severity, moment)
        event = append_event(
            connection, actor_id=actor.actor_id, action="incident.reported",
            resource_type="incident", resource_id=incident_id,
            detail={"source": source, "source_ref": source_ref, "dedup_key": dedup_key,
                    "severity": severity, "status": status, "current_stage": first_stage,
                    "missing_fields": missing, "impact_scope": impact_scope or {},
                    "evidence_summary": evidence_summary, "report_count": 1},
            occurred_at=moment,
        )
        self._timeline(connection, incident_id=incident_id, version=1, event=event,
                       kind="created", actor_id=actor.actor_id,
                       to_status=status, to_stage=first_stage,
                       note="信息不全，先行隔离" if quarantined else None,
                       detail={"severity": severity, "missing_fields": missing,
                               "source": source, "source_ref": source_ref},
                       occurred_at=moment)
        return "incident", incident_id, {"incident_id": incident_id, "merged": False, "status": status}

    def _merge_report(self, connection, *, actor, existing, source: str, severity: str,
                      impact_scope: dict[str, Any] | None, evidence_summary: str | None,
                      evidence: list[dict[str, Any]], source_ref: str | None,
                      moment: str) -> tuple[str, str, dict[str, Any]]:
        """把重复上报并入既有事件，取最高级别并合并影响范围与证据。"""

        incident_id = existing["incident_id"]
        merged_scope = {**(self._json(existing["impact_scope_json"])), **(impact_scope or {})}
        merged_evidence = self._json(existing["evidence_json"]) + evidence
        if evidence_summary:
            merged_summary = (
                f"{existing['evidence_summary']}\n---\n{evidence_summary}"
                if existing["evidence_summary"] else evidence_summary
            )
        else:
            merged_summary = existing["evidence_summary"]
        missing_after = self._missing_fields(merged_scope, merged_summary)
        severity_before = existing["severity"]
        severity_after = severity if SEVERITIES.index(severity) > SEVERITIES.index(severity_before) else severity_before
        new_actions: list[str] = []
        new_recipients: list[str] = []
        superseded: list[str] = []
        if severity_after != severity_before:
            superseded = self._cancel_superseded_actions(connection, incident_id, severity_before, severity_after, moment)
            new_actions = self._add_plan_actions(connection, incident_id, severity_before, severity_after, moment)
            new_recipients = self._add_plan_notifications(connection, incident_id, severity_before, severity_after, moment)
        status_before = existing["status"]
        status_after = status_before
        if status_before == STATUS_QUARANTINED and not missing_after:
            status_after = STATUS_ACTIVE
        version = existing["version"] + 1
        raw_stage = self._recompute_stage(connection, incident_id, severity_after, existing["current_stage"])
        stage_after = self._clamp_quarantine_stage(
            severity_after, raw_stage, status_after == STATUS_QUARANTINED
        )
        connection.execute(
            "UPDATE incidents SET impact_scope_json=?, evidence_summary=?, evidence_json=?, "
            "missing_fields_json=?, severity=?, report_count=report_count+1, current_stage=?, "
            "status=?, version=?, updated_at=? WHERE incident_id=?",
            (canonical_json(merged_scope), merged_summary, canonical_json(merged_evidence),
             canonical_json(missing_after), severity_after, stage_after, status_after, version,
             moment, incident_id),
        )
        event = append_event(
            connection, actor_id=actor.actor_id, action="incident.report_merged",
            resource_type="incident", resource_id=incident_id,
            detail={"merged_from_source": source, "source_ref": source_ref,
                    "severity_before": severity_before, "severity_after": severity_after,
                    "status_before": status_before, "status_after": status_after,
                    "report_count": existing["report_count"] + 1,
                    "missing_fields_after": missing_after,
                    "new_actions": new_actions, "new_notifications": new_recipients,
                    "canceled_actions": superseded},
            occurred_at=moment,
        )
        note = f"合并来自 {source} 的重复上报"
        if status_after != status_before:
            note += "；信息补齐，解除隔离"
        self._timeline(connection, incident_id=incident_id, version=version, event=event,
                       kind="merged", actor_id=actor.actor_id,
                       from_status=status_before if status_after != status_before else None,
                       to_status=status_after if status_after != status_before else None,
                       from_stage=existing["current_stage"] if stage_after != existing["current_stage"] else None,
                       to_stage=stage_after if stage_after != existing["current_stage"] else None,
                       note=note,
                       detail={"source": source, "source_ref": source_ref,
                               "severity_before": severity_before, "severity_after": severity_after},
                       occurred_at=moment)
        return "incident", incident_id, {"incident_id": incident_id, "merged": True,
                                         "status": status_after, "severity": severity_after}

    # ------------------------------------------------------------------ 补充/隔离解除

    def supplement_incident(self, *, request_id: str, actor_id: str, incident_id: str,
                            impact_scope: dict[str, Any] | None = None,
                            evidence_summary: str | None = None,
                            evidence: list[dict[str, Any]] | None = None,
                            note: str | None = None) -> dict[str, Any]:
        """补充缺失信息；信息补齐后解除先行隔离，进入正常处置流程。"""

        payload = {"actor_id": actor_id, "incident_id": incident_id, "impact_scope": impact_scope,
                   "evidence_summary": evidence_summary, "evidence": evidence, "note": note}

        def create() -> tuple[str, str, dict[str, Any]]:
            moment = self._now()
            row = self._require_incident(connection, incident_id)
            actor = self._actor(connection, actor_id)
            self._require(actor, *MUTATING_ROLES)
            self._require_same_org(actor, row)
            if row["status"] not in (STATUS_QUARANTINED, STATUS_ACTIVE):
                raise ConflictError("事件已结案，不能继续补充信息")
            scope = self._json(row["impact_scope_json"])
            if isinstance(impact_scope, dict):
                scope.update(impact_scope)
            merged_evidence = self._json(row["evidence_json"]) + self._validate_evidence(evidence)
            summary = row["evidence_summary"]
            if isinstance(evidence_summary, str) and evidence_summary.strip():
                addition = evidence_summary.strip()
                summary = f"{summary}\n---\n{addition}" if summary else addition
            missing = self._missing_fields(scope, summary)
            was_quarantined = row["status"] == STATUS_QUARANTINED
            if was_quarantined and not missing:
                status_after = STATUS_ACTIVE
            else:
                status_after = row["status"]
            stage_before = row["current_stage"]
            if status_after != row["status"] or was_quarantined:
                raw_stage = self._recompute_stage(connection, incident_id, row["severity"], stage_before)
                stage_after = self._clamp_quarantine_stage(
                    row["severity"], raw_stage, status_after == STATUS_QUARANTINED
                )
            else:
                stage_after = stage_before
            version = row["version"] + 1
            connection.execute(
                "UPDATE incidents SET impact_scope_json=?, evidence_summary=?, evidence_json=?, "
                "missing_fields_json=?, status=?, current_stage=?, version=?, updated_at=? "
                "WHERE incident_id=?",
                (canonical_json(scope), summary, canonical_json(merged_evidence),
                 canonical_json(missing), status_after, stage_after, version, moment, incident_id),
            )
            event = append_event(
                connection, actor_id=actor.actor_id, action="incident.supplemented",
                resource_type="incident", resource_id=incident_id,
                detail={"missing_fields_before": self._json(row["missing_fields_json"]),
                        "missing_fields_after": missing,
                        "status_before": row["status"], "status_after": status_after,
                        "stage_before": stage_before, "stage_after": stage_after},
                occurred_at=moment,
            )
            self._timeline(connection, incident_id=incident_id, version=version, event=event,
                           kind="supplemented", actor_id=actor.actor_id,
                           from_status=row["status"] if status_after != row["status"] else None,
                           to_status=status_after if status_after != row["status"] else None,
                           from_stage=stage_before if stage_after != stage_before else None,
                           to_stage=stage_after if stage_after != stage_before else None,
                           note=note or ("信息补齐，解除隔离" if status_after != row["status"] else None),
                           detail={"missing_fields": missing}, occurred_at=moment)
            return "incident", incident_id, {"incident_id": incident_id, "status": status_after,
                                             "current_stage": stage_after,
                                             "missing_fields": missing}

        with self.database.transaction(immediate=True) as connection:
            receipt, response = self._idempotent_ex(
                connection, request_id=request_id, action="supplement_incident",
                payload=payload, create=create,
            )
            response["receipt"] = receipt.__dict__
            return response

    # ------------------------------------------------------------------ 升级

    def escalate_incident(self, *, request_id: str, actor_id: str, incident_id: str,
                          severity: str, reason: str) -> dict[str, Any]:
        """把事件升级到更高严重级别，补齐处置阶段、动作与通报对象。"""

        payload = {"actor_id": actor_id, "incident_id": incident_id,
                   "severity": severity, "reason": reason}
        if not is_valid_severity(severity):
            raise ValidationError("severity 必须是 low/medium/high/critical 之一")
        reason = self._text(reason, "reason", 500)

        def create() -> tuple[str, str, dict[str, Any]]:
            moment = self._now()
            row = self._require_incident(connection, incident_id)
            actor = self._actor(connection, actor_id)
            self._require(actor, *REVIEW_ROLES)
            self._require_same_org(actor, row)
            if row["status"] in TERMINAL_STATUSES:
                raise ConflictError("事件已结案，不能升级")
            before = row["severity"]
            if SEVERITIES.index(severity) <= SEVERITIES.index(before):
                raise ConflictError("升级目标级别必须高于当前级别")
            new_actions = self._add_plan_actions(connection, incident_id, before, severity, moment)
            new_recipients = self._add_plan_notifications(connection, incident_id, before, severity, moment)
            superseded = self._cancel_superseded_actions(connection, incident_id, before, severity, moment)
            raw_stage = self._recompute_stage(connection, incident_id, severity, row["current_stage"])
            stage_after = self._clamp_quarantine_stage(
                severity, raw_stage, row["status"] == STATUS_QUARANTINED
            )
            version = row["version"] + 1
            connection.execute(
                "UPDATE incidents SET severity=?, current_stage=?, owner_role=?, version=?, updated_at=? "
                "WHERE incident_id=?",
                (severity, stage_after, plan_for(severity).owner_role, version, moment, incident_id),
            )
            event = append_event(
                connection, actor_id=actor.actor_id, action="incident.escalated",
                resource_type="incident", resource_id=incident_id,
                detail={"severity_before": before, "severity_after": severity, "reason": reason,
                        "new_actions": new_actions, "new_notifications": new_recipients,
                        "canceled_actions": superseded,
                        "stage_before": row["current_stage"], "stage_after": stage_after},
                occurred_at=moment,
            )
            self._timeline(connection, incident_id=incident_id, version=version, event=event,
                           kind="escalated", actor_id=actor.actor_id,
                           from_stage=row["current_stage"], to_stage=stage_after,
                           note=f"升级为 {severity}：{reason}",
                           detail={"severity_before": before, "severity_after": severity,
                                   "new_actions": new_actions, "new_notifications": new_recipients,
                                   "canceled_actions": superseded},
                           occurred_at=moment)
            return "incident", incident_id, {"incident_id": incident_id, "severity": severity,
                                             "current_stage": stage_after,
                                             "new_actions": new_actions,
                                             "new_notifications": new_recipients,
                                             "canceled_actions": superseded}

        with self.database.transaction(immediate=True) as connection:
            receipt, response = self._idempotent_ex(
                connection, request_id=request_id, action="escalate_incident",
                payload=payload, create=create,
            )
            response["receipt"] = receipt.__dict__
            return response

    # ------------------------------------------------------------------ 撤回误报

    def withdraw_false_positive(self, *, request_id: str, actor_id: str, incident_id: str,
                                reason: str) -> dict[str, Any]:
        """撤回事件并标记为误报，取消未完成动作与通报，处置过程留痕。"""

        payload = {"actor_id": actor_id, "incident_id": incident_id, "reason": reason}
        reason = self._text(reason, "reason", 500)

        def create() -> tuple[str, str, dict[str, Any]]:
            moment = self._now()
            row = self._require_incident(connection, incident_id)
            actor = self._actor(connection, actor_id)
            self._require(actor, *REVIEW_ROLES)
            self._require_same_org(actor, row)
            if row["status"] in TERMINAL_STATUSES:
                raise ConflictError("事件已经结案，不能撤回")
            canceled_actions = connection.execute(
                "UPDATE incident_actions SET status=?, completed_at=? WHERE incident_id=? AND status=?",
                (ACTION_CANCELED, moment, incident_id, ACTION_PENDING),
            ).rowcount
            canceled_notifications = connection.execute(
                "UPDATE incident_notifications SET status=?, last_error=? "
                "WHERE incident_id=? AND status=?",
                (NOTIFICATION_CANCELED, "事件撤回：误报", incident_id, NOTIFICATION_PENDING),
            ).rowcount
            version = row["version"] + 1
            connection.execute(
                "UPDATE incidents SET status=?, conclusion=?, version=?, updated_at=?, closed_at=? "
                "WHERE incident_id=?",
                (STATUS_FALSE_POSITIVE, f"误报撤回：{reason}", version, moment, moment, incident_id),
            )
            event = append_event(
                connection, actor_id=actor.actor_id, action="incident.withdrawn_false_positive",
                resource_type="incident", resource_id=incident_id,
                detail={"reason": reason, "canceled_actions": canceled_actions,
                        "canceled_notifications": canceled_notifications},
                occurred_at=moment,
            )
            self._timeline(connection, incident_id=incident_id, version=version, event=event,
                           kind="withdrawn", actor_id=actor.actor_id,
                           from_status=row["status"], to_status=STATUS_FALSE_POSITIVE,
                           note=f"撤回误报：{reason}",
                           detail={"canceled_actions": canceled_actions,
                                   "canceled_notifications": canceled_notifications},
                           occurred_at=moment)
            return "incident", incident_id, {"incident_id": incident_id,
                                             "status": STATUS_FALSE_POSITIVE}

        with self.database.transaction(immediate=True) as connection:
            receipt, response = self._idempotent_ex(
                connection, request_id=request_id, action="withdraw_false_positive",
                payload=payload, create=create,
            )
            response["receipt"] = receipt.__dict__
            return response

    # ------------------------------------------------------------------ 动作推进

    def complete_action(self, *, request_id: str, actor_id: str, incident_id: str,
                        code: str, note: str | None = None) -> dict[str, Any]:
        """完成一个处置动作；当前阶段的阻断动作全部完成时自动进入下一阶段。"""

        payload = {"actor_id": actor_id, "incident_id": incident_id, "code": code, "note": note}
        code = self._text(code, "code", 80)
        note = self._optional_text(note, "note", 500)

        def create() -> tuple[str, str, dict[str, Any]]:
            moment = self._now()
            row = self._require_incident(connection, incident_id)
            actor = self._actor(connection, actor_id)
            self._require(actor, *MUTATING_ROLES)
            self._require_same_org(actor, row)
            if row["status"] in TERMINAL_STATUSES:
                raise ConflictError("事件已结案，动作不能继续推进")
            action_row = connection.execute(
                "SELECT * FROM incident_actions WHERE incident_id=? AND code=?",
                (incident_id, code),
            ).fetchone()
            if action_row is None:
                raise NotFoundError("处置动作不存在")
            if action_row["status"] == ACTION_DONE:
                raise ConflictError("该动作已经完成")
            if action_row["status"] == ACTION_CANCELED:
                raise ConflictError("该动作已随事件撤回而取消")
            if row["status"] == STATUS_QUARANTINED and action_row["stage"] != "containment":
                raise ConflictError("信息缺失隔离期间，仅可执行隔离遏制动作，请先补充信息")
            if actor.role not in ("admin", action_row["owner_role"]):
                raise PermissionDenied("当前角色不能完成该动作")
            connection.execute(
                "UPDATE incident_actions SET status=?, assignee_id=?, completed_at=? WHERE action_id=?",
                (ACTION_DONE, actor.actor_id, moment, action_row["action_id"]),
            )
            stage_before = row["current_stage"]
            raw_stage = self._recompute_stage(connection, incident_id, row["severity"], stage_before)
            stage_after = self._clamp_quarantine_stage(
                row["severity"], raw_stage, row["status"] == STATUS_QUARANTINED
            )
            version = row["version"] + 1
            connection.execute(
                "UPDATE incidents SET current_stage=?, version=?, updated_at=? WHERE incident_id=?",
                (stage_after, version, moment, incident_id),
            )
            event = append_event(
                connection, actor_id=actor.actor_id, action="incident.action_completed",
                resource_type="incident", resource_id=incident_id,
                detail={"code": code, "stage": action_row["stage"],
                        "stage_before": stage_before, "stage_after": stage_after},
                occurred_at=moment,
            )
            self._timeline(connection, incident_id=incident_id, version=version, event=event,
                           kind="action_completed", actor_id=actor.actor_id,
                           from_stage=stage_before if stage_after != stage_before else None,
                           to_stage=stage_after if stage_after != stage_before else None,
                           note=note or f"完成动作 {code}",
                           detail={"code": code, "stage": action_row["stage"]},
                           occurred_at=moment)
            return "incident_action", action_row["action_id"], {
                "incident_id": incident_id, "action_id": action_row["action_id"],
                "code": code, "status": ACTION_DONE, "current_stage": stage_after}

        with self.database.transaction(immediate=True) as connection:
            receipt, response = self._idempotent_ex(
                connection, request_id=request_id, action="complete_action",
                payload=payload, create=create,
            )
            response["receipt"] = receipt.__dict__
            return response

    def assign_owner(self, *, request_id: str, actor_id: str, incident_id: str,
                     assignee_id: str, note: str | None = None) -> dict[str, Any]:
        """指定事件的当前责任人。"""

        payload = {"actor_id": actor_id, "incident_id": incident_id,
                   "assignee_id": assignee_id, "note": note}

        def create() -> tuple[str, str, dict[str, Any]]:
            moment = self._now()
            row = self._require_incident(connection, incident_id)
            actor = self._actor(connection, actor_id)
            self._require(actor, *REVIEW_ROLES)
            self._require_same_org(actor, row)
            assignee = self._actor(connection, assignee_id)
            self._require_same_org(assignee, row)
            if row["status"] in TERMINAL_STATUSES:
                raise ConflictError("事件已结案，不能变更责任人")
            version = row["version"] + 1
            connection.execute(
                "UPDATE incidents SET assignee_id=?, version=?, updated_at=? WHERE incident_id=?",
                (assignee_id, version, moment, incident_id),
            )
            event = append_event(
                connection, actor_id=actor.actor_id, action="incident.owner_assigned",
                resource_type="incident", resource_id=incident_id,
                detail={"assignee_id": assignee_id}, occurred_at=moment,
            )
            self._timeline(connection, incident_id=incident_id, version=version, event=event,
                           kind="owner_assigned", actor_id=actor.actor_id,
                           note=note or f"责任人变更为 {assignee.display_name}",
                           detail={"assignee_id": assignee_id}, occurred_at=moment)
            return "incident", incident_id, {"incident_id": incident_id,
                                             "assignee_id": assignee_id}

        with self.database.transaction(immediate=True) as connection:
            receipt, response = self._idempotent_ex(
                connection, request_id=request_id, action="assign_owner",
                payload=payload, create=create,
            )
            response["receipt"] = receipt.__dict__
            return response

    # ------------------------------------------------------------------ 结案/重开

    def close_incident(self, *, request_id: str, actor_id: str, incident_id: str,
                       conclusion: str) -> dict[str, Any]:
        """在全部阻断动作完成后给出最终结论并结案。"""

        payload = {"actor_id": actor_id, "incident_id": incident_id, "conclusion": conclusion}
        conclusion = self._text(conclusion, "conclusion", 2000)

        def create() -> tuple[str, str, dict[str, Any]]:
            moment = self._now()
            row = self._require_incident(connection, incident_id)
            actor = self._actor(connection, actor_id)
            self._require(actor, *REVIEW_ROLES)
            self._require_same_org(actor, row)
            if row["status"] in TERMINAL_STATUSES:
                raise ConflictError("事件已经结案")
            if row["status"] == STATUS_QUARANTINED:
                raise ConflictError("事件仍处于信息缺失隔离状态，不能结案")
            pending_blocking = connection.execute(
                "SELECT COUNT(*) AS count FROM incident_actions WHERE incident_id=? "
                "AND status=? AND blocking=1",
                (incident_id, ACTION_PENDING),
            ).fetchone()["count"]
            if pending_blocking:
                raise ConflictError(f"仍有 {pending_blocking} 个阻断动作未完成，不能结案")
            pending_notifications = connection.execute(
                "SELECT COUNT(*) AS count FROM incident_notifications WHERE incident_id=? AND status=?",
                (incident_id, NOTIFICATION_PENDING),
            ).fetchone()["count"]
            if pending_notifications:
                raise ConflictError(f"仍有 {pending_notifications} 条通报未送达，不能结案")
            version = row["version"] + 1
            connection.execute(
                "UPDATE incidents SET status=?, conclusion=?, version=?, updated_at=?, closed_at=? "
                "WHERE incident_id=?",
                (STATUS_CLOSED, conclusion, version, moment, moment, incident_id),
            )
            event = append_event(
                connection, actor_id=actor.actor_id, action="incident.closed",
                resource_type="incident", resource_id=incident_id,
                detail={"conclusion": conclusion}, occurred_at=moment,
            )
            self._timeline(connection, incident_id=incident_id, version=version, event=event,
                           kind="closed", actor_id=actor.actor_id,
                           from_status=row["status"], to_status=STATUS_CLOSED,
                           note="最终结论：" + conclusion,
                           detail={"conclusion": conclusion}, occurred_at=moment)
            return "incident", incident_id, {"incident_id": incident_id, "status": STATUS_CLOSED}

        with self.database.transaction(immediate=True) as connection:
            receipt, response = self._idempotent_ex(
                connection, request_id=request_id, action="close_incident",
                payload=payload, create=create,
            )
            response["receipt"] = receipt.__dict__
            return response

    def reopen_incident(self, *, request_id: str, actor_id: str, incident_id: str,
                        reason: str) -> dict[str, Any]:
        """重新打开已结案事件（问题复发或误报裁定被新证据推翻）。"""

        payload = {"actor_id": actor_id, "incident_id": incident_id, "reason": reason}
        reason = self._text(reason, "reason", 500)

        def create() -> tuple[str, str, dict[str, Any]]:
            moment = self._now()
            row = self._require_incident(connection, incident_id)
            actor = self._actor(connection, actor_id)
            self._require(actor, *REVIEW_ROLES)
            self._require_same_org(actor, row)
            if row["status"] not in TERMINAL_STATUSES:
                raise ConflictError("事件尚未结案，无需重新打开")
            missing = self._json(row["missing_fields_json"])
            status_after = STATUS_QUARANTINED if missing else STATUS_ACTIVE
            # 误报裁定被推翻时，恢复此前取消的动作与通报，使处置与通报继续推进。
            restored_actions = connection.execute(
                "UPDATE incident_actions SET status=?, assignee_id=NULL, completed_at=? "
                "WHERE incident_id=? AND status=?",
                (ACTION_PENDING, None, incident_id, ACTION_CANCELED),
            ).rowcount
            restored_notifications = connection.execute(
                "UPDATE incident_notifications SET status=?, last_error=NULL "
                "WHERE incident_id=? AND status=?",
                (NOTIFICATION_PENDING, incident_id, NOTIFICATION_CANCELED),
            ).rowcount
            raw_stage = self._recompute_stage(connection, incident_id, row["severity"], None)
            stage_after = self._clamp_quarantine_stage(
                row["severity"], raw_stage, status_after == STATUS_QUARANTINED
            )
            version = row["version"] + 1
            connection.execute(
                "UPDATE incidents SET status=?, current_stage=?, version=?, updated_at=?, "
                "closed_at=NULL, reopen_count=reopen_count+1, quarantined_at=? WHERE incident_id=?",
                (status_after, stage_after, version, moment,
                 moment if status_after == STATUS_QUARANTINED else None, incident_id),
            )
            event = append_event(
                connection, actor_id=actor.actor_id, action="incident.reopened",
                resource_type="incident", resource_id=incident_id,
                detail={"reason": reason, "status_before": row["status"],
                        "status_after": status_after, "reopen_count": row["reopen_count"] + 1,
                        "restored_actions": restored_actions,
                        "restored_notifications": restored_notifications},
                occurred_at=moment,
            )
            self._timeline(connection, incident_id=incident_id, version=version, event=event,
                           kind="reopened", actor_id=actor.actor_id,
                           from_status=row["status"], to_status=status_after, to_stage=stage_after,
                           note=f"重新打开：{reason}",
                           detail={"reason": reason, "restored_actions": restored_actions,
                                   "restored_notifications": restored_notifications},
                           occurred_at=moment)
            return "incident", incident_id, {"incident_id": incident_id, "status": status_after,
                                             "current_stage": stage_after,
                                             "restored_actions": restored_actions,
                                             "restored_notifications": restored_notifications}

        with self.database.transaction(immediate=True) as connection:
            receipt, response = self._idempotent_ex(
                connection, request_id=request_id, action="reopen_incident",
                payload=payload, create=create,
            )
            response["receipt"] = receipt.__dict__
            return response

    # ------------------------------------------------------------------ 通报派发

    def deliver_pending_notifications(self, *, limit: int = 100) -> dict[str, int]:
        """推进所有未送达通报；服务重启后重复调用即可继续，采用至少一次语义。"""

        rows = self.database.connection.execute(
            "SELECT n.*, i.organization_id, i.severity, i.title AS incident_title, i.status AS incident_status "
            "FROM incident_notifications n JOIN incidents i ON i.incident_id=n.incident_id "
            "WHERE n.status=? ORDER BY n.created_at LIMIT ?",
            (NOTIFICATION_PENDING, limit),
        ).fetchall()
        delivered = 0
        failed = 0
        for row in rows:
            notification = {
                "notification_id": row["notification_id"],
                "incident_id": row["incident_id"],
                "recipient": row["recipient"],
                "recipient_name": row["recipient_name"],
                "channel": row["channel"],
                "sla_minutes": row["sla_minutes"],
                "attempts": row["attempts"],
            }
            incident = {"incident_id": row["incident_id"],
                        "organization_id": row["organization_id"],
                        "severity": row["severity"], "title": row["incident_title"],
                        "status": row["incident_status"]}
            try:
                self._sender(notification, incident)
            except Exception as exc:  # 通道失败时保留待派发状态，等待重试
                failed += 1
                with self.database.transaction(immediate=True) as connection:
                    connection.execute(
                        "UPDATE incident_notifications SET attempts=attempts+1, last_error=? "
                        "WHERE notification_id=? AND status=?",
                        (str(exc)[:300], row["notification_id"], NOTIFICATION_PENDING),
                    )
                continue
            with self.database.transaction(immediate=True) as connection:
                moment = self._now()
                cursor = connection.execute(
                    "UPDATE incident_notifications SET status=?, attempts=attempts+1, "
                    "delivered_at=?, last_error=NULL WHERE notification_id=? AND status=?",
                    (NOTIFICATION_DELIVERED, moment, row["notification_id"], NOTIFICATION_PENDING),
                )
                if cursor.rowcount == 0:
                    continue  # 已被并发派发或事件撤回取消
                event = append_event(
                    connection, actor_id="system", action="incident.notification_delivered",
                    resource_type="incident", resource_id=row["incident_id"],
                    detail={"notification_id": row["notification_id"],
                            "recipient": row["recipient"], "channel": row["channel"]},
                    occurred_at=moment,
                )
                self._timeline(connection, incident_id=row["incident_id"],
                               version=None, event=event,
                               kind="notification_delivered", actor_id="system",
                               note=f"通报送达 {row['recipient_name']}",
                               detail={"notification_id": row["notification_id"],
                                       "recipient": row["recipient"], "channel": row["channel"]},
                               occurred_at=moment)
                delivered += 1
        return {"delivered": delivered, "failed": failed, "examined": len(rows)}

    # ------------------------------------------------------------------ 查询

    def get_incident(self, actor_id: str, incident_id: str) -> dict[str, Any]:
        """返回事件当前责任人、未完成动作、通报、结论与完整时间线。"""

        with self.database.transaction() as connection:
            actor = self._actor(connection, actor_id)
            row = self._require_incident(connection, incident_id)
            self._require_same_org(actor, row)
            return self._incident_view(connection, row)

    def list_incidents(self, actor_id: str, *, status: str | None = None,
                       organization_id: str | None = None) -> list[dict[str, Any]]:
        """列出操作者可见的事件（默认本组织，管理员可按组织筛选）。"""

        query = "SELECT * FROM incidents"
        parameters: list[Any] = []
        clauses: list[str] = []
        with self.database.transaction() as connection:
            actor = self._actor(connection, actor_id)
            if organization_id:
                if actor.role != "admin" and organization_id != actor.organization_id:
                    raise PermissionDenied("不能查询其他组织的事件")
                clauses.append("organization_id=?")
                parameters.append(organization_id)
            elif actor.role != "admin":
                clauses.append("organization_id=?")
                parameters.append(actor.organization_id)
            if status:
                clauses.append("status=?")
                parameters.append(status)
            if clauses:
                query += " WHERE " + " AND ".join(clauses)
            query += " ORDER BY created_at, incident_id"
            views = []
            for row in connection.execute(query, parameters):
                views.append(self._incident_view(connection, row, include_timeline=False))
            return views

    def pending_notification_summary(self, actor_id: str) -> dict[str, Any]:
        """供重启后健康检查使用：返回尚未送达的通报数量。"""

        with self.database.transaction() as connection:
            actor = self._actor(connection, actor_id)
            parameters: list[Any] = []
            org_filter = ""
            if actor.role != "admin":
                org_filter = " AND i.organization_id=?"
                parameters.append(actor.organization_id)
            row = connection.execute(
                "SELECT COUNT(*) AS count FROM incident_notifications n "
                "JOIN incidents i ON i.incident_id=n.incident_id WHERE n.status=?" + org_filter,
                [NOTIFICATION_PENDING, *parameters],
            ).fetchone()
            return {"pending_notifications": row["count"]}

    # ------------------------------------------------------------------ 视图组装

    def _incident_view(self, connection, row, *, include_timeline: bool = True) -> dict[str, Any]:
        incident_id = row["incident_id"]
        plan = plan_for(row["severity"])
        actions_rows = connection.execute(
            "SELECT * FROM incident_actions WHERE incident_id=? ORDER BY sort_order, code",
            (incident_id,),
        ).fetchall()
        actions = [self._action_dict(item) for item in actions_rows]
        notifications_rows = connection.execute(
            "SELECT * FROM incident_notifications WHERE incident_id=? ORDER BY created_at, recipient",
            (incident_id,),
        ).fetchall()
        notifications = [self._notification_dict(item) for item in notifications_rows]
        assignee = None
        if row["assignee_id"]:
            assignee_row = connection.execute(
                "SELECT * FROM actors WHERE actor_id=?", (row["assignee_id"],)
            ).fetchone()
            if assignee_row:
                assignee = {"actor_id": assignee_row["actor_id"],
                            "display_name": assignee_row["display_name"],
                            "role": assignee_row["role"]}
        pending_actions = [item for item in actions if item["status"] == ACTION_PENDING]
        pending_blocking = [item for item in pending_actions if item["blocking"]]
        timeline = []
        if include_timeline:
            timeline = self._timeline_view(connection, incident_id)
        return {
            "incident_id": incident_id,
            "organization_id": row["organization_id"],
            "title": row["title"],
            "source": row["source"],
            "source_ref": row["source_ref"],
            "severity": row["severity"],
            "status": row["status"],
            "current_stage": row["current_stage"],
            "stages": [{"code": code, "title": STAGE_LABELS[code]} for code in plan.stage_codes],
            "impact_scope": self._json(row["impact_scope_json"]),
            "evidence_summary": row["evidence_summary"],
            "evidence": self._json(row["evidence_json"]),
            "missing_fields": self._json(row["missing_fields_json"]),
            "quarantined": row["status"] == STATUS_QUARANTINED,
            "owner": {"role": row["owner_role"], "assignee": assignee},
            "report_count": row["report_count"],
            "reopen_count": row["reopen_count"],
            "version": row["version"],
            "conclusion": row["conclusion"],
            "actions": actions,
            "pending_actions": pending_actions,
            "ready_to_close": row["status"] == STATUS_ACTIVE and not pending_blocking
            and not [n for n in notifications if n["status"] == NOTIFICATION_PENDING],
            "notifications": notifications,
            "pending_notifications": [n for n in notifications if n["status"] == NOTIFICATION_PENDING],
            "timeline": timeline,
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "quarantined_at": row["quarantined_at"],
            "closed_at": row["closed_at"],
        }

    def _timeline_view(self, connection, incident_id: str) -> list[dict[str, Any]]:
        rows = connection.execute(
            "SELECT t.*, a.sequence AS audit_sequence FROM incident_timeline t "
            "JOIN audit_events a ON a.event_hash=t.event_hash "
            "WHERE t.incident_id=? ORDER BY t.seq",
            (incident_id,),
        ).fetchall()
        return [{
            "seq": item["seq"], "version": item["version"], "kind": item["kind"],
            "from_status": item["from_status"], "to_status": item["to_status"],
            "from_stage": item["from_stage"], "to_stage": item["to_stage"],
            "actor_id": item["actor_id"], "note": item["note"],
            "detail": self._json(item["detail_json"]), "occurred_at": item["occurred_at"],
            "audit_event_hash": item["event_hash"], "audit_sequence": item["audit_sequence"],
        } for item in rows]

    # ------------------------------------------------------------------ 内部工具

    def _require_incident(self, connection, incident_id: str):
        row = connection.execute("SELECT * FROM incidents WHERE incident_id=?", (incident_id,)).fetchone()
        if row is None:
            raise NotFoundError("事件不存在")
        return row

    def _require_same_org(self, actor, row) -> None:
        if actor.organization_id != row["organization_id"] and actor.role != "admin":
            raise PermissionDenied("不能操作其他组织的事件")

    @staticmethod
    def _json(value: str) -> Any:
        return json.loads(value)

    @staticmethod
    def _missing_fields(impact_scope: dict[str, Any] | None,
                        evidence_summary: str | None) -> list[str]:
        missing: list[str] = []
        if not impact_scope:
            missing.append("impact_scope")
        if not evidence_summary:
            missing.append("evidence_summary")
        return missing

    @staticmethod
    def _validate_evidence(evidence: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
        if evidence is None:
            return []
        if not isinstance(evidence, list):
            raise ValidationError("evidence 必须是证据对象数组")
        normalized: list[dict[str, Any]] = []
        for index, item in enumerate(evidence):
            if not isinstance(item, dict):
                raise ValidationError(f"evidence[{index}] 必须是对象")
            ref = str(item.get("ref", "")).strip()
            if not ref:
                raise ValidationError(f"evidence[{index}].ref 不能为空")
            entry = {"ref": ref[:200]}
            if item.get("kind"):
                entry["kind"] = str(item["kind"])[:80]
            if item.get("sha256"):
                entry["sha256"] = str(item["sha256"])[:128]
            normalized.append(entry)
        return normalized

    @staticmethod
    def _fingerprint(organization_id: str, source: str, source_ref: str | None,
                     dedup_key: str | None) -> str | None:
        if dedup_key:
            return digest({"type": "dedup_key", "organization_id": organization_id,
                           "dedup_key": dedup_key})
        if source_ref:
            return digest({"type": "source_ref", "organization_id": organization_id,
                           "source": source, "source_ref": source_ref})
        return None

    def _seed_actions(self, connection, incident_id: str, severity: str, moment: str) -> None:
        for order, spec in enumerate(plan_for(severity).actions):
            connection.execute(
                "INSERT INTO incident_actions(action_id,incident_id,code,title,stage,owner_role,"
                "blocking,sla_hours,status,sort_order,assignee_id,created_at,completed_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (uuid.uuid4().hex, incident_id, spec.code, spec.title, spec.stage,
                 spec.owner_role, 1 if spec.blocking else 0, spec.sla_hours,
                 ACTION_PENDING, order, None, moment, None),
            )

    def _seed_notifications(self, connection, incident_id: str, severity: str, moment: str) -> None:
        for spec in plan_for(severity).notifications:
            connection.execute(
                "INSERT INTO incident_notifications(notification_id,incident_id,recipient,"
                "recipient_name,channel,sla_minutes,status,attempts,last_error,created_at,delivered_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (uuid.uuid4().hex, incident_id, spec.recipient, spec.recipient_name, spec.channel,
                 spec.sla_minutes, NOTIFICATION_PENDING, 0, None, moment, None),
            )

    def _add_plan_actions(self, connection, incident_id: str, before: str, after: str,
                          moment: str) -> list[str]:
        target_specs = {spec.code: spec for spec in plan_for(after).actions}
        existing = {row["code"] for row in connection.execute(
            "SELECT code FROM incident_actions WHERE incident_id=?", (incident_id,))}
        added: list[str] = []
        for order, spec in enumerate(plan_for(after).actions):
            if spec.code in existing:
                continue
            connection.execute(
                "INSERT INTO incident_actions(action_id,incident_id,code,title,stage,owner_role,"
                "blocking,sla_hours,status,sort_order,assignee_id,created_at,completed_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (uuid.uuid4().hex, incident_id, spec.code, spec.title, spec.stage, spec.owner_role,
                 1 if spec.blocking else 0, spec.sla_hours, ACTION_PENDING, order, None, moment, None),
            )
            added.append(spec.code)
        # 按新级别方案统一重排全部动作，避免新增动作与历史动作排序号冲突。
        for order, spec in enumerate(plan_for(after).actions):
            connection.execute(
                "UPDATE incident_actions SET sort_order=?, stage=?, owner_role=? "
                "WHERE incident_id=? AND code=?",
                (order, spec.stage, spec.owner_role, incident_id, spec.code),
            )
        return added

    def _add_plan_notifications(self, connection, incident_id: str, before: str, after: str,
                                moment: str) -> list[str]:
        recipients = missing_notification_recipients(before, after)
        target = {spec.recipient: spec for spec in plan_for(after).notifications}
        added: list[str] = []
        for recipient in recipients:
            spec = target[recipient]
            connection.execute(
                "INSERT OR IGNORE INTO incident_notifications(notification_id,incident_id,recipient,"
                "recipient_name,channel,sla_minutes,status,attempts,last_error,created_at,delivered_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (uuid.uuid4().hex, incident_id, spec.recipient, spec.recipient_name, spec.channel,
                 spec.sla_minutes, NOTIFICATION_PENDING, 0, None, moment, None),
            )
            added.append(recipient)
        return added

    def _cancel_superseded_actions(self, connection, incident_id: str, before: str,
                                   after: str, moment: str) -> list[str]:
        """升级时取消新方案中不再存在的待办动作，已完成的保留作为历史。"""

        target_codes = {spec.code for spec in plan_for(after).actions}
        rows = connection.execute(
            "SELECT action_id, code FROM incident_actions WHERE incident_id=? AND status=?",
            (incident_id, ACTION_PENDING),
        ).fetchall()
        canceled: list[str] = []
        for row in rows:
            if row["code"] not in target_codes:
                connection.execute(
                    "UPDATE incident_actions SET status=?, completed_at=? WHERE action_id=?",
                    (ACTION_CANCELED, moment, row["action_id"]),
                )
                canceled.append(row["code"])
        return canceled

    def _recompute_stage(self, connection, incident_id: str, severity: str,
                         current_stage: str | None) -> str:
        """返回最早的、仍存在待办阻断动作的阶段；全部完成时停留在最后阶段。"""

        plan = plan_for(severity)
        for stage in plan.stage_codes:
            count = connection.execute(
                "SELECT COUNT(*) AS count FROM incident_actions WHERE incident_id=? AND stage=? "
                "AND status=? AND blocking=1",
                (incident_id, stage, ACTION_PENDING),
            ).fetchone()["count"]
            if count:
                return stage
        return plan.stage_codes[-1]

    @staticmethod
    def _clamp_quarantine_stage(severity: str, stage: str, quarantined: bool) -> str:
        """信息缺失隔离期间，处置焦点锁定在隔离遏制，不进入后续阶段。"""

        if not quarantined:
            return stage
        stages = plan_for(severity).stage_codes
        return "containment" if "containment" in stages else stages[0]

    def _timeline(self, connection, *, incident_id: str, version: int | None, event: dict[str, Any],
                  kind: str, actor_id: str, occurred_at: str,
                  from_status: str | None = None, to_status: str | None = None,
                  from_stage: str | None = None, to_stage: str | None = None,
                  note: str | None = None, detail: dict[str, Any] | None = None) -> None:
        seq_row = connection.execute(
            "SELECT COALESCE(MAX(seq),0)+1 AS next_seq FROM incident_timeline WHERE incident_id=?",
            (incident_id,),
        ).fetchone()
        connection.execute(
            "INSERT INTO incident_timeline(incident_id,seq,version,event_id,event_hash,kind,"
            "from_status,to_status,from_stage,to_stage,actor_id,note,detail_json,occurred_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (incident_id, seq_row["next_seq"], version, event["event_id"], event["event_hash"],
             kind, from_status, to_status, from_stage, to_stage, actor_id, note,
             canonical_json(detail or {}), occurred_at),
        )

    @staticmethod
    def _action_dict(row) -> dict[str, Any]:
        return IncidentAction(
            action_id=row["action_id"], incident_id=row["incident_id"], code=row["code"],
            title=row["title"], stage=row["stage"], owner_role=row["owner_role"],
            blocking=bool(row["blocking"]), sla_hours=row["sla_hours"], status=row["status"],
            sort_order=row["sort_order"], assignee_id=row["assignee_id"],
            created_at=row["created_at"], completed_at=row["completed_at"],
        ).__dict__

    @staticmethod
    def _notification_dict(row) -> dict[str, Any]:
        return IncidentNotification(
            notification_id=row["notification_id"], incident_id=row["incident_id"],
            recipient=row["recipient"], recipient_name=row["recipient_name"],
            channel=row["channel"], sla_minutes=row["sla_minutes"], status=row["status"],
            attempts=row["attempts"], last_error=row["last_error"],
            created_at=row["created_at"], delivered_at=row["delivered_at"],
        ).__dict__
