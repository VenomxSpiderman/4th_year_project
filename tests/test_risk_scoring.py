"""
tests/test_risk_scoring.py
──────────────────────────
Unit tests for risk_scoring.py.

Includes a regression test for the worked example in §5.7.6 of the project
report (Cybercriminal → ServiceTask → Risk = 6.12, level = Medium).
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from risk_scoring import (
    compute_likelihood,
    compute_tim,
    compute_loac,
    compute_risk,
    _compute_r_personal,
    _compute_r_size,
)


# ---------------------------------------------------------------------------
# Fixtures matching §5.7.6 worked example
# ---------------------------------------------------------------------------
# Process: 4 data objects, total size 30 KB (sizes: 10, 10, 5, 5 KB), load = 1
# Task touches 1 data object: 10 KB, personal=yes, load=1
# Agent: Cybercriminal, severity=3
# Audit: Low (L_task=1)

def _make_data_objects():
    return [
        {"id": "D1", "_size_kb": 10.0, "_load": 1.0, "_is_personal": True},
        {"id": "D2", "_size_kb": 10.0, "_load": 1.0, "_is_personal": False},
        {"id": "D3", "_size_kb":  5.0, "_load": 1.0, "_is_personal": False},
        {"id": "D4", "_size_kb":  5.0, "_load": 1.0, "_is_personal": False},
    ]


def _make_task():
    return {
        "id": "Task1",
        "name": "Process Payment",
        "_audit_level": 1,   # Low
        "connected_data": [{"id": "D1"}],
    }


def _make_agent_cybercriminal():
    return {"name": "Cybercriminal", "severity": 3}


def _make_behaviour():
    return {"threat": "Service Exploitation Risk", "impact": 6.0}


# ---------------------------------------------------------------------------
# compute_likelihood
# ---------------------------------------------------------------------------

class TestComputeLikelihood:
    def test_cybercriminal_severity_3(self):
        # (3/5) × 9 = 5.4
        assert compute_likelihood(3) == pytest.approx(5.4)

    def test_nation_state_severity_5(self):
        # (5/5) × 9 = 9.0
        assert compute_likelihood(5) == pytest.approx(9.0)

    def test_script_kiddie_severity_1(self):
        # (1/5) × 9 = 1.8
        assert compute_likelihood(1) == pytest.approx(1.8)

    def test_insider_severity_2(self):
        # (2/5) × 9 = 3.6
        assert compute_likelihood(2) == pytest.approx(3.6)


# ---------------------------------------------------------------------------
# r_personal and r_size helpers
# ---------------------------------------------------------------------------

class TestRateHelpers:
    def test_r_personal_worked_example(self):
        """§5.7.6: 1 personal obj, load=1, 4 total → 25%"""
        task = {"connected_data": [{"id": "D1"}]}
        dos  = _make_data_objects()
        r = _compute_r_personal(task, dos)
        assert r == pytest.approx(25.0)

    def test_r_size_worked_example(self):
        """§5.7.6: task obj = 10 KB·1, total = 30 KB·1 → 33.33%"""
        task = {"connected_data": [{"id": "D1"}]}
        dos  = _make_data_objects()
        r = _compute_r_size(task, dos)
        assert r == pytest.approx(100.0 * 10.0 / 30.0)

    def test_r_personal_no_personal_data(self):
        dos  = [{"id": "D1", "_size_kb": 5.0, "_load": 1.0, "_is_personal": False}]
        task = {"connected_data": [{"id": "D1"}]}
        assert _compute_r_personal(task, dos) == pytest.approx(0.0)

    def test_r_size_empty_process(self):
        task = {"connected_data": []}
        assert _compute_r_size(task, []) == pytest.approx(0.0)

    def test_r_personal_empty_process(self):
        task = {"connected_data": []}
        assert _compute_r_personal(task, []) == pytest.approx(0.0)


# ---------------------------------------------------------------------------
# compute_tim
# ---------------------------------------------------------------------------

class TestComputeTim:
    def test_worked_example_critical_extensive(self):
        """§5.7.6: r_personal=25% (critical), r_size=33% (extensive) → (7,7,7)"""
        task = _make_task()
        dos  = _make_data_objects()
        loc, loi, loa = compute_tim(task, dos)
        assert (loc, loi, loa) == pytest.approx((7.0, 7.0, 7.0))

    def test_not_critical_minimal(self):
        """No personal data, small task → (2,1,1)"""
        dos  = [
            {"id": "D1", "_size_kb": 1.0, "_load": 1.0, "_is_personal": False},
            {"id": "D2", "_size_kb": 100.0, "_load": 1.0, "_is_personal": False},
        ]
        task = {"connected_data": [{"id": "D1"}], "_audit_level": 3}
        loc, loi, loa = compute_tim(task, dos)
        assert (loc, loi, loa) == pytest.approx((2.0, 1.0, 1.0))

    def test_not_critical_all(self):
        """Task holds 100% of process data, not personal → (9,9,9)"""
        dos  = [{"id": "D1", "_size_kb": 10.0, "_load": 1.0, "_is_personal": False}]
        task = {"connected_data": [{"id": "D1"}], "_audit_level": 3}
        loc, loi, loa = compute_tim(task, dos)
        assert (loc, loi, loa) == pytest.approx((9.0, 9.0, 9.0))

    def test_critical_all(self):
        """≥25% personal, ≥90% size → (9,9,9)"""
        dos  = [{"id": "D1", "_size_kb": 10.0, "_load": 1.0, "_is_personal": True}]
        task = {"connected_data": [{"id": "D1"}], "_audit_level": 1}
        loc, loi, loa = compute_tim(task, dos)
        assert (loc, loi, loa) == pytest.approx((9.0, 9.0, 9.0))

    def test_critical_minimal(self):
        """≥25% personal, <25% size → (6,3,5)"""
        dos  = [
            {"id": "D1", "_size_kb": 1.0,  "_load": 1.0, "_is_personal": True},
            {"id": "D2", "_size_kb": 99.0, "_load": 1.0, "_is_personal": False},
            {"id": "D3", "_size_kb": 99.0, "_load": 1.0, "_is_personal": False},
            {"id": "D4", "_size_kb": 99.0, "_load": 1.0, "_is_personal": False},
        ]
        # D1 is personal; task has D1 only
        # r_personal = (1×1/4) × 100 = 25% → critical
        # r_size     = (1/298) × 100 ≈ 0.3% → minimal
        task = {"connected_data": [{"id": "D1"}], "_audit_level": 1}
        loc, loi, loa = compute_tim(task, dos)
        assert (loc, loi, loa) == pytest.approx((6.0, 3.0, 5.0))


# ---------------------------------------------------------------------------
# compute_loac
# ---------------------------------------------------------------------------

class TestComputeLoac:
    def test_low_audit(self):
        """L_task=1 → ((3-1)/3)×8+1 = 6.333..."""
        task = {"_audit_level": 1}
        assert compute_loac(task) == pytest.approx(6.3333, rel=1e-3)

    def test_medium_audit(self):
        """L_task=2 → ((3-2)/3)×8+1 = 3.666..."""
        task = {"_audit_level": 2}
        assert compute_loac(task) == pytest.approx(3.6667, rel=1e-3)

    def test_high_audit(self):
        """L_task=3 → ((3-3)/3)×8+1 = 1.0"""
        task = {"_audit_level": 3}
        assert compute_loac(task) == pytest.approx(1.0)

    def test_none_audit(self):
        """L_task=0 → ((3-0)/3)×8+1 = 9.0"""
        task = {"_audit_level": 0}
        assert compute_loac(task) == pytest.approx(9.0)

    def test_missing_audit_level_defaults_to_1(self):
        task = {}
        assert compute_loac(task) == pytest.approx(6.3333, rel=1e-3)


# ---------------------------------------------------------------------------
# compute_risk — worked example §5.7.6
# ---------------------------------------------------------------------------

class TestComputeRisk:
    def test_worked_example_score(self):
        """§5.7.6: Cybercriminal × ServiceTask → Risk ≈ 6.12, level = Medium"""
        task     = _make_task()
        dos      = _make_data_objects()
        agent    = _make_agent_cybercriminal()
        behaviour = _make_behaviour()

        result = compute_risk(agent, behaviour, task, dos)

        assert result["likelihood"] == pytest.approx(5.4)
        assert result["loc"] == pytest.approx(7.0)
        assert result["loi"] == pytest.approx(7.0)
        assert result["loa"] == pytest.approx(7.0)
        assert result["loac"] == pytest.approx(6.3333, rel=1e-3)
        # technical_impact = (7+7+7+6.333)/4 ≈ 6.833
        assert result["technical_impact"] == pytest.approx(6.8333, rel=1e-3)
        # score = (5.4 + 6.833) / 2 ≈ 6.117
        assert result["score"] == pytest.approx(6.1167, rel=1e-3)
        assert result["level"] == "Medium"

    def test_low_risk(self):
        """Script kiddie (severity=1), low-impact task → Low risk"""
        dos  = [{"id": "D1", "_size_kb": 1.0, "_load": 1.0, "_is_personal": False}]
        task = {"_audit_level": 3, "connected_data": []}
        agent = {"severity": 1}
        result = compute_risk(agent, {}, task, dos)
        assert result["level"] == "Low"

    def test_high_risk(self):
        """Nation state (severity=5), personal data, no audit → High risk"""
        dos  = [{"id": "D1", "_size_kb": 10.0, "_load": 1.0, "_is_personal": True}]
        task = {"_audit_level": 0, "connected_data": [{"id": "D1"}]}
        agent = {"severity": 5}
        result = compute_risk(agent, {}, task, dos)
        assert result["level"] == "High"

    def test_result_has_all_required_keys(self):
        task    = _make_task()
        dos     = _make_data_objects()
        agent   = _make_agent_cybercriminal()
        result  = compute_risk(agent, {}, task, dos)
        for key in ("likelihood", "loc", "loi", "loa", "loac",
                    "technical_impact", "score", "level"):
            assert key in result

    def test_score_is_float(self):
        task   = _make_task()
        dos    = _make_data_objects()
        agent  = _make_agent_cybercriminal()
        result = compute_risk(agent, {}, task, dos)
        assert isinstance(result["score"], float)
