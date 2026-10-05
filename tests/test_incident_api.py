import unittest

from ai_governance_foundation.api import route
from ai_governance_foundation.incident_service import IncidentService
from ai_governance_foundation.service import DomainService
from ai_governance_foundation.storage import Database


class IncidentApiTest(unittest.TestCase):
    def setUp(self):
        self.database = Database()
        self.service = DomainService(self.database)
        self._bootstrap()

    def tearDown(self):
        self.database.close()

    def _call(self, method, path, body=None, actor="op1"):
        return route(self.service, method, path, body, {"X-Actor-Id": actor})

    def _bootstrap(self):
        self._call("POST", "/organizations", {
            "request_id": "org", "organization_id": "o1", "name": "机构"}, actor="bootstrap")
        self._call("POST", "/actors", {
            "request_id": "admin", "new_actor_id": "a1", "display_name": "管理员",
            "role": "admin", "organization_id": "o1"}, actor="bootstrap")
        self._call("POST", "/actors", {
            "request_id": "op", "new_actor_id": "op1", "display_name": "值班员",
            "role": "operator", "organization_id": "o1"}, actor="a1")
        self._call("POST", "/actors", {
            "request_id": "rv", "new_actor_id": "rv1", "display_name": "复核员",
            "role": "reviewer", "organization_id": "o1"}, actor="a1")

    def _report(self, severity="medium", request_id="r1", **overrides):
        body = {"request_id": request_id, "source": "agent-gateway", "severity": severity,
                "source_ref": "evt-1", "impact_scope": {"systems": ["billing"]},
                "evidence_summary": "智能体越权访问外部工单系统"}
        body.update(overrides)
        status, payload = self._call("POST", "/incidents", body)
        return status, payload

    def test_report_missing_information_quarantines(self):
        status, payload = self._call("POST", "/incidents", {
            "request_id": "r1", "source": "agent-gateway", "severity": "high",
            "source_ref": "evt-1"}, )
        self.assertEqual(201, status)
        self.assertEqual("quarantined", payload["status"])
        status, view = self._call("GET", f"/incidents/{payload['incident_id']}")
        self.assertEqual(200, status)
        self.assertEqual("containment", view["current_stage"])
        self.assertIn("pending_actions", view)
        self.assertIn("notifications", view)
        self.assertIn("timeline", view)

    def test_report_and_merge_via_http(self):
        _, first = self._report(request_id="r1")
        status, second = self._report(request_id="r2", severity="critical",
                                      evidence_summary="发现数据外泄")
        self.assertEqual(201, status)
        self.assertTrue(second["merged"])
        self.assertEqual(first["incident_id"], second["incident_id"])
        status, items = self._call("GET", "/incidents")
        self.assertEqual(200, status)
        self.assertEqual(1, len(items["items"]))

    def test_supplement_escalate_withdraw_flow(self):
        _, payload = self._call("POST", "/incidents", {
            "request_id": "r1", "source": "dlp", "severity": "low", "source_ref": "e-9"})
        iid = payload["incident_id"]
        status, payload = self._call("POST", f"/incidents/{iid}/supplement", {
            "request_id": "s1", "impact_scope": {"f": 1}, "evidence_summary": "补齐"})
        self.assertEqual(200, status)
        self.assertEqual("active", payload["status"])
        status, payload = self._call("POST", f"/incidents/{iid}/escalate", {
            "request_id": "e1", "severity": "high", "reason": "影响扩大"}, actor="rv1")
        self.assertEqual(200, status)
        self.assertIn("legal", payload["new_notifications"])
        status, payload = self._call("POST", f"/incidents/{iid}/withdraw", {
            "request_id": "w1", "reason": "规则误判"}, actor="rv1")
        self.assertEqual(200, status)
        self.assertEqual("false_positive", payload["status"])
        status, view = self._call("GET", f"/incidents/{iid}")
        self.assertEqual(200, status)
        self.assertTrue(all(a["status"] == "canceled" for a in view["actions"]))

    def test_action_completion_and_close_requires_work(self):
        _, payload = self._report()
        iid = payload["incident_id"]
        self._call("POST", "/incident-notifications/deliver", {})
        status, view = self._call("GET", f"/incidents/{iid}")
        for action in view["actions"]:
            actor = "op1" if action["owner_role"] == "operator" else "rv1"
            status, result = self._call("POST", f"/incidents/{iid}/actions/complete", {
                "request_id": f"d-{action['code']}", "code": action["code"]}, actor=actor)
            self.assertEqual(200, status)
        status, payload = self._call("POST", f"/incidents/{iid}/close", {
            "request_id": "c1", "conclusion": "处置完成，无残留风险"}, actor="rv1")
        self.assertEqual(200, status)
        self.assertEqual("closed", payload["status"])

    def test_invalid_severity_returns_400(self):
        status, payload = self._call("POST", "/incidents", {
            "request_id": "r1", "source": "x", "severity": "urgent"})
        self.assertEqual(400, status)
        self.assertEqual("validation_error", payload["error"])

    def test_deliver_endpoint_reports_progress(self):
        self._report()
        status, payload = self._call("POST", "/incident-notifications/deliver", {})
        self.assertEqual(200, status)
        self.assertGreaterEqual(payload["delivered"], 1)
        status, payload = self._call("GET", "/incident-notifications/pending")
        self.assertEqual(200, status)
        self.assertEqual(0, payload["pending_notifications"])


if __name__ == "__main__":
    unittest.main()
