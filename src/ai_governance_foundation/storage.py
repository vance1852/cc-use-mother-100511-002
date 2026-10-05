"""封装 SQLite 连接、建表和事务边界。"""

from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS organizations (
    organization_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS actors (
    actor_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    role TEXT NOT NULL,
    organization_id TEXT NOT NULL REFERENCES organizations(organization_id),
    active INTEGER NOT NULL CHECK(active IN (0, 1)),
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sites (
    site_id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL REFERENCES organizations(organization_id),
    name TEXT NOT NULL,
    timezone_name TEXT NOT NULL,
    version INTEGER NOT NULL CHECK(version >= 1),
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS domain_records (
    record_id TEXT PRIMARY KEY,
    site_id TEXT NOT NULL REFERENCES sites(site_id),
    category TEXT NOT NULL,
    external_key TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    created_by TEXT NOT NULL REFERENCES actors(actor_id),
    created_at TEXT NOT NULL,
    UNIQUE(site_id, category, external_key)
);
CREATE TABLE IF NOT EXISTS request_receipts (
    request_id TEXT PRIMARY KEY,
    action TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    response_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_events (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE,
    actor_id TEXT NOT NULL,
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    detail_json TEXT NOT NULL,
    previous_hash TEXT NOT NULL,
    event_hash TEXT NOT NULL UNIQUE,
    occurred_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_events_resource
    ON audit_events(resource_type, resource_id, sequence);
CREATE TABLE IF NOT EXISTS incidents (
    incident_id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL REFERENCES organizations(organization_id),
    source TEXT NOT NULL,
    source_ref TEXT,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    impact_scope_json TEXT NOT NULL,
    evidence_summary TEXT,
    evidence_json TEXT NOT NULL,
    missing_fields_json TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('registered', 'quarantined', 'active',
                                          'false_positive', 'closed')),
    current_stage TEXT,
    owner_role TEXT,
    assignee_id TEXT REFERENCES actors(actor_id),
    version INTEGER NOT NULL CHECK(version >= 1),
    reopen_count INTEGER NOT NULL DEFAULT 0,
    conclusion TEXT,
    report_count INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    quarantined_at TEXT,
    closed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_incidents_org_status
    ON incidents(organization_id, status);
-- 同一指纹只允许存在一个未结案事件；结案/撤回后允许就同源问题重新登记。
CREATE UNIQUE INDEX IF NOT EXISTS idx_incidents_open_fingerprint
    ON incidents(fingerprint) WHERE status NOT IN ('false_positive', 'closed');
CREATE TABLE IF NOT EXISTS incident_actions (
    action_id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
    code TEXT NOT NULL,
    title TEXT NOT NULL,
    stage TEXT NOT NULL,
    owner_role TEXT NOT NULL,
    blocking INTEGER NOT NULL CHECK(blocking IN (0, 1)),
    sla_hours INTEGER,
    status TEXT NOT NULL CHECK(status IN ('pending', 'done', 'canceled')),
    sort_order INTEGER NOT NULL,
    assignee_id TEXT REFERENCES actors(actor_id),
    created_at TEXT NOT NULL,
    completed_at TEXT,
    UNIQUE(incident_id, code)
);
CREATE INDEX IF NOT EXISTS idx_incident_actions_incident
    ON incident_actions(incident_id, sort_order);
CREATE TABLE IF NOT EXISTS incident_notifications (
    notification_id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
    recipient TEXT NOT NULL,
    recipient_name TEXT NOT NULL,
    channel TEXT NOT NULL,
    sla_minutes INTEGER,
    status TEXT NOT NULL CHECK(status IN ('pending', 'delivered', 'canceled')),
    attempts INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    created_at TEXT NOT NULL,
    delivered_at TEXT,
    UNIQUE(incident_id, recipient)
);
CREATE INDEX IF NOT EXISTS idx_incident_notifications_status
    ON incident_notifications(status, created_at);
CREATE TABLE IF NOT EXISTS incident_timeline (
    incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
    seq INTEGER NOT NULL CHECK(seq >= 1),
    version INTEGER,
    event_id TEXT NOT NULL,
    event_hash TEXT NOT NULL,
    kind TEXT NOT NULL,
    from_status TEXT,
    to_status TEXT,
    from_stage TEXT,
    to_stage TEXT,
    actor_id TEXT NOT NULL,
    note TEXT,
    detail_json TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    PRIMARY KEY (incident_id, seq)
);
-- 事件每次版本修订只能对应一条时间线记录；通报送达等派生事件版本为空，不受此限。
CREATE UNIQUE INDEX IF NOT EXISTS idx_incident_timeline_version
    ON incident_timeline(incident_id, version) WHERE version IS NOT NULL;
"""


class Database:
    """管理 SQLite 数据库并为服务提供短事务。"""

    def __init__(self, path: str | Path = ":memory:") -> None:
        self.path = str(path)
        self.connection = sqlite3.connect(self.path, isolation_level=None, check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys = ON")
        self.connection.execute("PRAGMA busy_timeout = 5000")
        # HTTP 请求线程与后台通报线程共享同一连接，用锁串行化事务边界。
        self._tx_lock = threading.RLock()
        self.connection.executescript(SCHEMA)

    @contextmanager
    def transaction(self, immediate: bool = False) -> Iterator[sqlite3.Connection]:
        """在异常时回滚，在成功时提交。"""

        with self._tx_lock:
            self.connection.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
            try:
                yield self.connection
            except Exception:
                self.connection.rollback()
                raise
            else:
                self.connection.commit()

    def close(self) -> None:
        """关闭底层连接。"""

        self.connection.close()
