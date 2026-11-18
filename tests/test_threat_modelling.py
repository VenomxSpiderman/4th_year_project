"""
tests/test_threat_modelling.py
───────────────────────────────
Unit tests for threat_modelling.py.
Uses mock Neo4j sessions and a mock catalogue (no live services needed).
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import threat_modelling as tm


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_session_with_tasks(tasks_raw: list[dict]):
    """Return a mock session whose .run() yields the given task rows."""
    session = MagicMock()

    class _FakeRecord:
        def __init__(self, data):
            self._data = data
        def __getitem__(self, key):
            return self._data[key]
        def get(self, key, default=None):
            return self._data.get(key, default)

    class _FakeResult:
        def __init__(self, records):
            self._records = records
        def __iter__(self):
            return iter(self._records)

    records = [_FakeRecord(t) for t in tasks_raw]
    session.run = MagicMock(return_value=_FakeResult(records))
    return session


def _minimal_task_row(**overrides):
    base = {
        "task_id":           "T1",
        "name":              "Test Task",
        "type":              "Task",
        "subtype":           "ServiceTask",
        "annotation":        "Communication Type=Stateless; Audit=High",
        "is_data_centric":   True,
        "is_persistent":     False,
        "connected_data_raw": [],
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# select_agents
# ---------------------------------------------------------------------------

class TestSelectAgents:
    def test_external_agents_excluded_when_not_internet_exposed(self):
        context = {
            "internet_exposed": False,
            "personal_data": True,
            "internal_users": True,
            "financial_data": True,
            "critical_infra": False,
        }
        agents = tm.select_agents(context)
        for a in agents:
            assert a["access"] != "External", f"External agent {a['name']} should be excluded"

    def test_internal_agents_excluded_when_no_internal_users(self):
        context = {
            "internet_exposed": True,
            "personal_data": True,
            "internal_users": False,
            "financial_data": True,
            "critical_infra": False,
        }
        agents = tm.select_agents(context)
        for a in agents:
            assert a["access"] != "Internal", f"Internal agent {a['name']} should be excluded"

    def test_financial_agent_excluded_when_no_financial_data(self):
        context = {
            "internet_exposed": True,
            "personal_data": True,
            "internal_users": True,
            "financial_data": False,
            "critical_infra": False,
        }
        agents = tm.select_agents(context)
        for a in agents:
            assert a["motivation"] != "Financial"

    def test_critical_infra_keeps_only_high_skill(self):
        context = {
            "internet_exposed": True,
            "personal_data": True,
            "internal_users": True,
            "financial_data": True,
            "critical_infra": True,
        }
        agents = tm.select_agents(context)
        for a in agents:
            assert a["skill"] in ("High", "Very High")

    def test_all_agents_selected_for_full_context(self):
        context = {
            "internet_exposed": True,
            "personal_data": True,
            "internal_users": True,
            "financial_data": True,
            "critical_infra": False,
        }
        agents = tm.select_agents(context)
        assert len(agents) == len(tm.THREAT_AGENTS)

    def test_fallback_agent_when_all_filtered(self):
        # Impossible context — still returns at least one agent
        context = {
            "internet_exposed": False,
            "personal_data": False,
            "internal_users": False,
            "financial_data": False,
            "critical_infra": False,
        }
        agents = tm.select_agents(context)
        assert len(agents) >= 1


# ---------------------------------------------------------------------------
# detect_behaviours
# ---------------------------------------------------------------------------

class TestDetectBehaviours:
    def test_service_task_produces_service_exploitation_risk(self):
        task = {
            "subtype": "ServiceTask",
            "annotation": "Communication Type=Stateless; Audit=High",
            "operations": {"CREATE"},
            "connected_data": [],
        }
        behaviours = tm.detect_behaviours(task)
        threats = [b["threat"] for b in behaviours]
        assert "Service Exploitation Risk" in threats

    def test_user_task_produces_human_error_risk(self):
        task = {
            "subtype": "UserTask",
            "annotation": "Interaction Type=Online; Audit=Medium",
            "operations": {"READ"},
            "connected_data": [],
        }
        behaviours = tm.detect_behaviours(task)
        threats = [b["threat"] for b in behaviours]
        assert "Human Error Risk" in threats

    def test_delete_operation_produces_availability_risk(self):
        task = {
            "subtype": "Task",
            "annotation": "Audit=Low",
            "operations": {"DELETE"},
            "connected_data": [],
        }
        behaviours = tm.detect_behaviours(task)
        threats = [b["threat"] for b in behaviours]
        assert "Availability Risk" in threats

    def test_create_produces_integrity_violation_risk(self):
        task = {
            "subtype": "Task",
            "annotation": "Audit=High",
            "operations": {"CREATE"},
            "connected_data": [],
        }
        behaviours = tm.detect_behaviours(task)
        threats = [b["threat"] for b in behaviours]
        assert "Integrity Violation Risk" in threats

    def test_no_duplicate_threats(self):
        task = {
            "subtype": "ServiceTask",
            "annotation": "Communication Type=Stateful; Audit=High",
            "operations": {"READ", "CREATE"},
            "connected_data": [],
        }
        behaviours = tm.detect_behaviours(task)
        threat_names = [b["threat"] for b in behaviours]
        assert len(threat_names) == len(set(threat_names))

    def test_each_behaviour_has_required_keys(self):
        task = {
            "subtype": "SendTask",
            "annotation": "Communication Type=Mail; Audit=Medium",
            "operations": {"READ"},
            "connected_data": [],
        }
        behaviours = tm.detect_behaviours(task)
        for b in behaviours:
            assert "threat" in b
            assert "behaviour" in b
            assert "impact" in b
            assert "mitigation" in b

    def test_mitigation_is_string(self):
        task = {
            "subtype": "ServiceTask",
            "annotation": "Communication Type=Stateless; Audit=Low",
            "operations": {"CREATE"},
            "connected_data": [],
        }
        behaviours = tm.detect_behaviours(task)
        for b in behaviours:
            assert isinstance(b["mitigation"], str)


# ---------------------------------------------------------------------------
# build_tasks_with_annotations (mock session)
# ---------------------------------------------------------------------------

class TestBuildTasksWithAnnotations:
    def test_returns_task_list(self):
        session = _make_session_with_tasks([_minimal_task_row()])
        tasks = tm.build_tasks_with_annotations(session)
        assert len(tasks) == 1
        assert tasks[0]["id"] == "T1"

    def test_task_has_audit_level(self):
        row = _minimal_task_row(annotation="Audit=High")
        session = _make_session_with_tasks([row])
        tasks = tm.build_tasks_with_annotations(session)
        assert tasks[0]["_audit_level"] == 3

    def test_connected_data_enriched(self):
        row = _minimal_task_row(connected_data_raw=[{
            "id": "DO1", "name": "Profile",
            "annotation": "Personal=yes; Size=5; Order of Size=KB; Load Dependence=1",
            "is_persistent": True,
            "operation": "READ",
        }])
        session = _make_session_with_tasks([row])
        tasks = tm.build_tasks_with_annotations(session)
        obj = tasks[0]["connected_data"][0]
        assert obj["_is_personal"] is True
        assert obj["_size_kb"] == pytest.approx(5.0)

    def test_empty_result(self):
        session = _make_session_with_tasks([])
        tasks = tm.build_tasks_with_annotations(session)
        assert tasks == []


# ---------------------------------------------------------------------------
# generate_threat_model
# ---------------------------------------------------------------------------

class TestGenerateThreatModel:
    def _run(self, context=None):
        if context is None:
            context = {
                "internet_exposed": True, "personal_data": True,
                "internal_users": True, "financial_data": True,
                "critical_infra": False,
            }
        row = _minimal_task_row(
            annotation="Communication Type=Stateless; Audit=Low",
            connected_data_raw=[{
                "id": "DO1", "name": "Certificate",
                "annotation": "Personal=yes; Size=10; Order of Size=KB; Load Dependence=1",
                "is_persistent": True,
                "operation": "READ",
            }]
        )
        session = _make_session_with_tasks([row])
        return tm.generate_threat_model(session, context)

    def test_returns_list(self):
        threats = self._run()
        assert isinstance(threats, list)

    def test_entries_sorted_by_descending_score(self):
        threats = self._run()
        scores = [t["score"] for t in threats]
        assert scores == sorted(scores, reverse=True)

    def test_each_entry_has_required_keys(self):
        threats = self._run()
        required = {"agent_name", "task_id", "task_name", "threat", "behaviour",
                    "mitigation", "score", "level", "likelihood", "technical_impact"}
        for entry in threats:
            for key in required:
                assert key in entry, f"Missing key '{key}' in threat entry"

    def test_mitigation_is_string_in_all_entries(self):
        threats = self._run()
        for t in threats:
            assert isinstance(t["mitigation"], str)

    def test_threat_count_increases_with_more_agents(self):
        # Full context → more agents → more threats
        full_ctx = {
            "internet_exposed": True, "personal_data": True,
            "internal_users": True, "financial_data": True,
            "critical_infra": False,
        }
        limited_ctx = {
            "internet_exposed": False, "personal_data": False,
            "internal_users": True, "financial_data": False,
            "critical_infra": False,
        }
        row = _minimal_task_row()
        session = _make_session_with_tasks([row])
        full_threats    = tm.generate_threat_model(session, full_ctx)
        session2        = _make_session_with_tasks([row])
        limited_threats = tm.generate_threat_model(session2, limited_ctx)
        assert len(full_threats) >= len(limited_threats)


# ---------------------------------------------------------------------------
# Cross-pool flow detection (Phase 1 — §7.2.4)
# ---------------------------------------------------------------------------

class TestCrossPoolDetection:
    def test_cross_pool_flag_populated_when_true(self):
        row = _minimal_task_row(has_cross_pool_flow=True)
        session = _make_session_with_tasks([row])
        tasks = tm.build_tasks_with_annotations(session)
        assert tasks[0]["has_cross_pool_flow"] is True

    def test_cross_pool_flag_defaults_false(self):
        row = _minimal_task_row()
        session = _make_session_with_tasks([row])
        tasks = tm.build_tasks_with_annotations(session)
        assert tasks[0]["has_cross_pool_flow"] is False

    def test_cross_pool_read_triggers_confidentiality_threat_without_personal_data(self):
        """A task with READ + cross_pool should flag confidentiality risk
        even when no connected data object is personal."""
        task = {
            "subtype": "SendTask",
            "annotation": "Communication Type=PEC; Audit=High",
            "operations": {"READ"},
            "has_cross_pool_flow": True,
            "connected_data": [
                {"id": "DO1", "name": "Doc", "_is_personal": False,
                 "_size_kb": 5.0, "_load": 1},
            ],
        }
        behaviours = tm.detect_behaviours(task)
        threats = [b["threat"] for b in behaviours]
        assert "Loss of Confidentiality of Personal Data" in threats

    def test_no_cross_pool_no_personal_skips_confidentiality_threat(self):
        """Without cross_pool AND without personal data, the confidentiality
        threat should NOT be generated."""
        task = {
            "subtype": "ServiceTask",
            "annotation": "Communication Type=Stateless; Audit=High",
            "operations": {"READ"},
            "has_cross_pool_flow": False,
            "connected_data": [
                {"id": "DO1", "name": "Doc", "_is_personal": False,
                 "_size_kb": 5.0, "_load": 1},
            ],
        }
        behaviours = tm.detect_behaviours(task)
        threats = [b["threat"] for b in behaviours]
        assert "Loss of Confidentiality of Personal Data" not in threats


# ---------------------------------------------------------------------------
# Risk score write-back (Phase 1 — §7.2.3)
# ---------------------------------------------------------------------------

class TestWriteRiskScoresToGraph:
    def _make_threat_model(self):
        """Return a small synthetic threat model with 3 entries for 2 tasks."""
        return [
            {
                "task_id": "T1", "task_name": "Task A",
                "agent_name": "Nation State", "agent_severity": 5,
                "threat": "Service Exploitation Risk",
                "behaviour": "...", "mitigation": "...", "impact": 6.0,
                "score": 7.5, "level": "High",
                "likelihood": 9.0, "technical_impact": 6.0,
                "loc": 7.0, "loi": 7.0, "loa": 7.0, "loac": 3.67,
            },
            {
                "task_id": "T1", "task_name": "Task A",
                "agent_name": "Script Kiddie", "agent_severity": 1,
                "threat": "Human Error Risk",
                "behaviour": "...", "mitigation": "...", "impact": 3.0,
                "score": 3.0, "level": "Low",
                "likelihood": 1.8, "technical_impact": 4.2,
                "loc": 2.0, "loi": 1.0, "loa": 1.0, "loac": 3.67,
            },
            {
                "task_id": "T2", "task_name": "Task B",
                "agent_name": "Cybercriminal", "agent_severity": 3,
                "threat": "Integrity Violation Risk",
                "behaviour": "...", "mitigation": "...", "impact": 6.0,
                "score": 5.5, "level": "Medium",
                "likelihood": 5.4, "technical_impact": 5.6,
                "loc": 6.0, "loi": 5.0, "loa": 5.0, "loac": 6.33,
            },
        ]

    def test_returns_correct_count(self):
        session = MagicMock()
        threat_model = self._make_threat_model()
        count = tm.write_risk_scores_to_graph(session, threat_model)
        assert count == 2  # T1 and T2

    def test_aggregates_max_score_per_task(self):
        session = MagicMock()
        threat_model = self._make_threat_model()
        tm.write_risk_scores_to_graph(session, threat_model)

        # Retrieve the batch that was passed to execute_write
        call_args = session.execute_write.call_args
        # The lambda receives tx; we call it with a mock to capture args
        tx_mock = MagicMock()
        callback = call_args[0][0]  # positional arg 0 is the lambda
        callback(tx_mock)
        cypher_call = tx_mock.run.call_args
        batch = cypher_call.kwargs.get("batch") or cypher_call[1].get("batch")

        t1 = next(item for item in batch if item["task_id"] == "T1")
        t2 = next(item for item in batch if item["task_id"] == "T2")

        # T1 should have max score = 7.5, from "Nation State" / "Service Exploitation Risk"
        assert t1["risk_score"] == 7.5
        assert t1["risk_level"] == "High"
        assert t1["top_threat"] == "Service Exploitation Risk"
        assert t1["top_agent"] == "Nation State"
        assert t1["threat_count"] == 2
        # Max LoC should be 7.0 (from the first entry)
        assert t1["loc"] == 7.0
        assert t1["loi"] == 7.0
        assert t1["loa"] == 7.0

        # T2 has only one entry
        assert t2["risk_score"] == 5.5
        assert t2["risk_level"] == "Medium"
        assert t2["threat_count"] == 1

    def test_empty_threat_model_returns_zero(self):
        session = MagicMock()
        count = tm.write_risk_scores_to_graph(session, [])
        assert count == 0
        session.execute_write.assert_not_called()

    def test_entries_without_task_id_are_skipped(self):
        session = MagicMock()
        threat_model = [
            {
                "task_id": "", "task_name": "",
                "agent_name": "X", "agent_severity": 1,
                "threat": "Y", "behaviour": "...", "mitigation": "",
                "impact": 1.0, "score": 1.0, "level": "Low",
                "likelihood": 1.0, "technical_impact": 1.0,
                "loc": 1.0, "loi": 1.0, "loa": 1.0, "loac": 1.0,
            }
        ]
        count = tm.write_risk_scores_to_graph(session, threat_model)
        assert count == 0
        session.execute_write.assert_not_called()
