import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from ai_governance_foundation.clock import FixedClock
from ai_governance_foundation.errors import ConflictError, NotFoundError, PermissionDenied
from ai_governance_foundation.incident_service import IncidentService
from ai_governance_foundation.service import DomainService
from ai_governance_foundation.storage import Database


class IncidentServiceTest(unittest.TestCase):
    def setUp(self):
        self.database = Database()
        self.clock = FixedClock(datetime(2026, 10, 5, 2, 0, tzinfo=timezone.utc))
        self.service = DomainService(self.database, self.clock)
        self.incidents = IncidentService(self.database, self.clock)
        self.service.register_organization(request_id="org", actor_id="bootstrap",
                                           organization_id="o1", name="科研机构一")
        self.service.register_actor(request_id="admin", actor_id="bootstrap", new_actor_id="a1",
                                    display_name="管理员", role="admin", organization_id="o1")
        self.service.register_actor(request_id="op", actor_id="a1", new_actor_id="op1",
                                    display_name="值班员", role="operator", organization_id="o1")
        self.service.register_actor(request_id="rv", actor_id="a1", new_actor_id="rv1",
                                    display_name="复核员", role="reviewer", organization_id="o1")
        self.service.register_actor(request_id="au", actor_id="a1", new_actor_id="au1",
                                    display_name="审计员", role="auditor", organization_id="o1")

    def tearDown(self):
        self.database.close()

    def _report(self, request_id="r1", **overrides):
        params = {"actor_id": "op1", "source": "agent-gateway", "severity": "high",
                  "source_ref": "evt-001", "impact_scope": {"systems": ["billing"]},
                  "evidence_summary": "网关日志显示智能体越权访问外部系统"}
        params.update(overrides)
        return self.incidents.report_incident(request_id=request_id, **params)

    # ------------------------------------------------------------------ 登记与隔离

    def test_missing_information_quarantines_and_generates_plan(self):
        result = self.incidents.report_incident(
            request_id="r1", actor_id="op1", source="agent-gateway", severity="high",
            source_ref="evt-001")
        self.assertFalse(result["receipt"]["replayed"])
        view = self.incidents.get_incident("op1", result["incident_id"])
        self.assertEqual("quarantined", view["status"])
        self.assertTrue(view["quarantined"])
        self.assertEqual(["impact_scope", "evidence_summary"], view["missing_fields"])
        self.assertEqual("containment", view["current_stage"])
        stages = [stage["code"] for stage in view["stages"]]
        self.assertEqual(["triage", "containment", "investigation", "review",
                          "remediation", "verification"], stages)
        self.assertEqual(4, len(view["notifications"]))
        self.assertTrue(any(n["recipient"] == "duty_security_officer" for n in view["notifications"]))

    def test_quarantine_blocks_non_containment_actions(self):
        result = self.incidents.report_incident(
            request_id="r1", actor_id="op1", source="agent-gateway", severity="high",
            source_ref="evt-001")
        iid = result["incident_id"]
        with self.assertRaises(ConflictError):
            self.incidents.complete_action(request_id="bad", actor_id="op1",
                                           incident_id=iid, code="investigate")
        # 隔离遏制动作允许先行执行
        self.incidents.complete_action(request_id="ok", actor_id="op1",
                                       incident_id=iid, code="contain")
        view = self.incidents.get_incident("op1", iid)
        self.assertEqual("containment", view["current_stage"])

    def test_supplement_releases_quarantine(self):
        result = self.incidents.report_incident(
            request_id="r1", actor_id="op1", source="agent-gateway", severity="high",
            source_ref="evt-001")
        iid = result["incident_id"]
        self.incidents.supplement_incident(
            request_id="s1", actor_id="op1", incident_id=iid,
            impact_scope={"systems": ["billing"], "users": 12},
            evidence_summary="日志与抓包已固定")
        view = self.incidents.get_incident("op1", iid)
        self.assertEqual("active", view["status"])
        self.assertEqual([], view["missing_fields"])
        self.assertFalse(view["quarantined"])

    # ------------------------------------------------------------------ 合并

    def test_duplicate_reports_merge_by_source_reference(self):
        first = self._report(request_id="r1")
        second = self.incidents.report_incident(
            request_id="r2", actor_id="op1", source="agent-gateway", severity="high",
            source_ref="evt-001", impact_scope={"users": 300},
            evidence_summary="业务方补充了会话记录")
        self.assertTrue(second["merged"])
        self.assertEqual(first["incident_id"], second["incident_id"])
        view = self.incidents.get_incident("op1", first["incident_id"])
        self.assertEqual(2, view["report_count"])
        self.assertEqual(300, view["impact_scope"]["users"])
        self.assertIn("会话记录", view["evidence_summary"])
        self.assertEqual(["created", "merged"], [t["kind"] for t in view["timeline"]])

    def test_merge_takes_higher_severity_and_extends_plan(self):
        first = self._report(request_id="r1", severity="medium")
        self.incidents.report_incident(
            request_id="r2", actor_id="op1", source="agent-gateway", severity="critical",
            source_ref="evt-001", impact_scope={"users": 1}, evidence_summary="升级为危急")
        view = self.incidents.get_incident("op1", first["incident_id"])
        self.assertEqual("critical", view["severity"])
        codes = {a["code"] for a in view["actions"]}
        self.assertIn("emergency_isolate", codes)
        self.assertIn("executive_report", codes)
        self.assertIn("postmortem", codes)
        recipients = {n["recipient"] for n in view["notifications"]}
        self.assertIn("executive", recipients)

    def test_closed_incident_allows_fresh_report_with_same_fingerprint(self):
        first = self._report(request_id="r1")
        iid = first["incident_id"]
        self.incidents.withdraw_false_positive(request_id="w1", actor_id="rv1",
                                               incident_id=iid, reason="规则误判")
        second = self._report(request_id="r2")
        self.assertFalse(second["merged"])
        self.assertNotEqual(iid, second["incident_id"])

    def test_merge_completes_missing_information_and_releases_quarantine(self):
        # 技术团队信息不全先行隔离
        first = self.incidents.report_incident(
            request_id="r1", actor_id="op1", source="agent-gateway", severity="low",
            source_ref="evt-7")
        iid = first["incident_id"]
        self.assertEqual("quarantined", first["status"])
        # 法务方就同一事件上报，带来完整影响范围与证据 -> 合并同时解除隔离
        merged = self.incidents.report_incident(
            request_id="r2", actor_id="op1", source="agent-gateway", severity="medium",
            source_ref="evt-7", impact_scope={"systems": ["crm"]},
            evidence_summary="法务已固定审计日志与会话记录")
        self.assertTrue(merged["merged"])
        view = self.incidents.get_incident("op1", iid)
        self.assertEqual("active", view["status"])
        self.assertEqual([], view["missing_fields"])
        self.assertEqual("medium", view["severity"])

    def test_escalation_while_quarantined_keeps_focus_on_containment(self):
        first = self.incidents.report_incident(
            request_id="r1", actor_id="op1", source="agent-gateway", severity="medium",
            source_ref="evt-8")
        iid = first["incident_id"]
        self.incidents.escalate_incident(
            request_id="e1", actor_id="rv1", incident_id=iid,
            severity="critical", reason="影响升级但信息仍不全")
        view = self.incidents.get_incident("rv1", iid)
        self.assertEqual("quarantined", view["status"])
        self.assertEqual("containment", view["current_stage"])

    def test_replayed_report_returns_same_receipt(self):
        first = self._report(request_id="r1")
        second = self._report(request_id="r1")
        self.assertTrue(second["receipt"]["replayed"])
        self.assertEqual(first["incident_id"], second["incident_id"])
        view = self.incidents.get_incident("op1", first["incident_id"])
        self.assertEqual(1, view["report_count"])

    # ------------------------------------------------------------------ 升级

    def test_escalation_adds_actions_and_notifications(self):
        first = self._report(request_id="r1", severity="low")
        result = self.incidents.escalate_incident(
            request_id="e1", actor_id="rv1", incident_id=first["incident_id"],
            severity="high", reason="发现对外数据泄露迹象")
        self.assertIn("legal_review", result["new_actions"])
        self.assertIn("legal", result["new_notifications"])
        view = self.incidents.get_incident("rv1", first["incident_id"])
        self.assertEqual("high", view["severity"])
        # low 级别独有、high 方案中不存在的待办动作应被废弃取消
        self.assertIn("canceled", {a["status"] for a in view["actions"] if a["code"] == "assess"})

    def test_operator_cannot_escalate(self):
        first = self._report(request_id="r1", severity="low")
        with self.assertRaises(PermissionDenied):
            self.incidents.escalate_incident(
                request_id="e1", actor_id="op1", incident_id=first["incident_id"],
                severity="high", reason="试图自行升级")

    def test_escalation_cannot_lower_severity(self):
        first = self._report(request_id="r1", severity="high")
        with self.assertRaises(ConflictError):
            self.incidents.escalate_incident(
                request_id="e1", actor_id="rv1", incident_id=first["incident_id"],
                severity="low", reason="试图降级")

    # ------------------------------------------------------------------ 撤回与重开

    def test_false_positive_withdrawal_cancels_pending_work(self):
        first = self._report(request_id="r1", severity="medium")
        iid = first["incident_id"]
        self.incidents.withdraw_false_positive(request_id="w1", actor_id="rv1",
                                               incident_id=iid, reason="告警规则误判")
        view = self.incidents.get_incident("rv1", iid)
        self.assertEqual("false_positive", view["status"])
        self.assertTrue(all(a["status"] == "canceled" for a in view["actions"]))
        self.assertTrue(all(n["status"] == "canceled" for n in view["notifications"]))
        self.assertIn("误报撤回", view["conclusion"])

    def test_reopen_restores_canceled_actions_and_notifications(self):
        first = self._report(request_id="r1", severity="medium")
        iid = first["incident_id"]
        self.incidents.withdraw_false_positive(request_id="w1", actor_id="rv1",
                                               incident_id=iid, reason="规则误判")
        self.incidents.reopen_incident(request_id="ro1", actor_id="rv1",
                                       incident_id=iid, reason="新证据推翻误报裁定")
        view = self.incidents.get_incident("rv1", iid)
        self.assertEqual("active", view["status"])
        self.assertTrue(any(a["status"] == "pending" for a in view["actions"]))
        self.assertTrue(any(n["status"] == "pending" for n in view["notifications"]))
        self.assertEqual(1, view["reopen_count"])

    # ------------------------------------------------------------------ 结案

    def _complete_medium_plan(self, iid):
        view = self.incidents.get_incident("rv1", iid)
        for action in view["actions"]:
            actor = "op1" if action["owner_role"] == "operator" else "rv1"
            self.incidents.complete_action(
                request_id=f"done-{action['code']}", actor_id=actor,
                incident_id=iid, code=action["code"])

    def test_cannot_close_with_pending_blocking_actions(self):
        first = self._report(request_id="r1", severity="medium")
        with self.assertRaises(ConflictError):
            self.incidents.close_incident(request_id="c1", actor_id="rv1",
                                          incident_id=first["incident_id"], conclusion="过早结案")

    def test_cannot_close_with_pending_notifications(self):
        first = self._report(request_id="r1", severity="medium")
        iid = first["incident_id"]
        self._complete_medium_plan(iid)
        with self.assertRaises(ConflictError):
            self.incidents.close_incident(request_id="c1", actor_id="rv1",
                                          incident_id=iid, conclusion="通报尚未送达")

    def test_full_flow_close_records_conclusion(self):
        first = self._report(request_id="r1", severity="medium")
        iid = first["incident_id"]
        self.incidents.assign_owner(request_id="own", actor_id="rv1",
                                    incident_id=iid, assignee_id="op1")
        self.incidents.deliver_pending_notifications()
        self._complete_medium_plan(iid)
        self.incidents.close_incident(request_id="c1", actor_id="rv1", incident_id=iid,
                                      conclusion="越权访问已阻断，凭据已轮换，无数据外泄")
        view = self.incidents.get_incident("rv1", iid)
        self.assertEqual("closed", view["status"])
        self.assertEqual("越权访问已阻断，凭据已轮换，无数据外泄", view["conclusion"])
        self.assertEqual("op1", view["owner"]["assignee"]["actor_id"])
        self.assertEqual([], view["pending_actions"])
        self.assertTrue(view["timeline"])

    # ------------------------------------------------------------------ 时间线

    def test_every_change_appends_ordered_timeline_tied_to_audit(self):
        first = self._report(request_id="r1", severity="medium")
        iid = first["incident_id"]
        self.incidents.assign_owner(request_id="own", actor_id="rv1",
                                    incident_id=iid, assignee_id="op1")
        self.incidents.withdraw_false_positive(request_id="w1", actor_id="rv1",
                                               incident_id=iid, reason="误判")
        view = self.incidents.get_incident("rv1", iid)
        kinds = [entry["kind"] for entry in view["timeline"]]
        self.assertEqual(["created", "owner_assigned", "withdrawn"], kinds)
        seqs = [entry["seq"] for entry in view["timeline"]]
        self.assertEqual([1, 2, 3], seqs)
        versions = [entry["version"] for entry in view["timeline"]]
        self.assertEqual([1, 2, 3], versions)
        for entry in view["timeline"]:
            self.assertTrue(entry["occurred_at"].endswith("Z") or "+" in entry["occurred_at"])
            self.assertEqual(64, len(entry["audit_event_hash"]))
            self.assertGreaterEqual(entry["audit_sequence"], 1)
        valid, _ = self.service.verify_audit()
        self.assertTrue(valid)

    def test_auditor_can_read_but_not_report(self):
        with self.assertRaises(PermissionDenied):
            self._report(request_id="r1", actor_id="au1")

    def test_unknown_incident_raises_not_found(self):
        with self.assertRaises(NotFoundError):
            self.incidents.get_incident("op1", "missing")


class NotificationRestartTest(unittest.TestCase):
    def test_pending_notifications_continue_after_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "restart.sqlite3"

            def open_stack(clock):
                database = Database(path)
                return database, DomainService(database, clock), IncidentService(database, clock)

            clock = FixedClock(datetime(2026, 10, 5, 2, 0, tzinfo=timezone.utc))
            database, service, incidents = open_stack(clock)
            service.register_organization(request_id="org", actor_id="bootstrap",
                                          organization_id="o1", name="机构")
            service.register_actor(request_id="admin", actor_id="bootstrap", new_actor_id="a1",
                                   display_name="管理员", role="admin", organization_id="o1")
            service.register_actor(request_id="op", actor_id="a1", new_actor_id="op1",
                                   display_name="值班员", role="operator", organization_id="o1")
            service.register_actor(request_id="rv", actor_id="a1", new_actor_id="rv1",
                                   display_name="复核员", role="reviewer", organization_id="o1")
            result = incidents.report_incident(
                request_id="r1", actor_id="op1", source="agent-gateway", severity="high",
                source_ref="evt-001", impact_scope={"systems": ["x"]}, evidence_summary="证据")
            iid = result["incident_id"]
            self.assertEqual(4, incidents.pending_notification_summary("op1")["pending_notifications"])
            database.close()

            # 重新打开服务：通报不丢失，继续派发
            clock2 = FixedClock(datetime(2026, 10, 5, 4, 0, tzinfo=timezone.utc))
            database2, service2, incidents2 = open_stack(clock2)
            view = incidents2.get_incident("rv1", iid)
            self.assertEqual(4, len(view["pending_notifications"]))
            delivery = incidents2.deliver_pending_notifications()
            self.assertEqual(4, delivery["delivered"])
            self.assertEqual(0, incidents2.pending_notification_summary("rv1")["pending_notifications"])
            # 重启后产生的送达事件与此前审计链衔接
            valid, count = service2.verify_audit()
            self.assertTrue(valid)
            self.assertGreater(count, 4)
            view = incidents2.get_incident("rv1", iid)
            self.assertEqual(4, len([t for t in view["timeline"]
                                     if t["kind"] == "notification_delivered"]))
            database2.close()

    def test_failed_delivery_is_retried_without_duplicates(self):
        database = Database()
        clock = FixedClock(datetime(2026, 10, 5, 2, 0, tzinfo=timezone.utc))
        service = DomainService(database, clock)
        attempts = {"n": 0}

        def flaky_sender(notification, incident):
            attempts["n"] += 1
            if attempts["n"] == 1:
                raise RuntimeError("通道暂时不可用")

        incidents = IncidentService(database, clock, sender=flaky_sender)
        service.register_organization(request_id="org", actor_id="bootstrap",
                                      organization_id="o1", name="机构")
        service.register_actor(request_id="op", actor_id="bootstrap", new_actor_id="op1",
                               display_name="值班员", role="operator", organization_id="o1")
        incidents.report_incident(request_id="r1", actor_id="op1", source="gateway",
                                  severity="low", source_ref="e1",
                                  impact_scope={"k": 1}, evidence_summary="证据")
        first = incidents.deliver_pending_notifications()
        self.assertEqual(0, first["delivered"])
        self.assertEqual(1, first["failed"])
        second = incidents.deliver_pending_notifications()
        self.assertEqual(1, second["delivered"])
        third = incidents.deliver_pending_notifications()
        self.assertEqual(0, third["delivered"])
        database.close()


if __name__ == "__main__":
    unittest.main()
