"""
tests/test_model_refinement.py
───────────────────────────────
Unit tests for model_refinement.py using mock Neo4j sessions.
No live Neo4j instance is required.
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import bpmn_security.graph.model_refinement as mr


# ---------------------------------------------------------------------------
# Session mock helpers
# ---------------------------------------------------------------------------

class _MockResult:
    """Minimal mock of a Neo4j query result."""
    def __init__(self, records):
        self._records = records

    def __iter__(self):
        return iter(self._records)

    def single(self):
        return self._records[0] if self._records else None


def _make_record(**kwargs):
    rec = MagicMock()
    rec.__getitem__ = lambda self, key: kwargs[key]
    rec.get = lambda key, default=None: kwargs.get(key, default)
    return rec


def _make_session(query_results: dict[str, list]):
    """Return a mock session whose .run() returns configured result lists.

    *query_results* maps a substring of the Cypher query to a list of mock
    records.  The first matching key wins.
    """
    session = MagicMock()

    def _run(query, **kwargs):
        for key, records in query_results.items():
            if key.lower() in query.lower():
                return _MockResult(records)
        return _MockResult([])

    session.run = MagicMock(side_effect=_run)
    return session


# ---------------------------------------------------------------------------
# _parse_annotation_keys
# ---------------------------------------------------------------------------

class TestParseAnnotationKeys:
    def test_parses_keys(self):
        keys = mr._parse_annotation_keys("Personal=yes; Size=10; Audit=High")
        assert "Personal" in keys
        assert "Size" in keys
        assert "Audit" in keys

    def test_empty_string(self):
        assert mr._parse_annotation_keys("") == set()

    def test_none(self):
        assert mr._parse_annotation_keys(None) == set()


# ---------------------------------------------------------------------------
# Structural requirement checks
# ---------------------------------------------------------------------------

class TestReq1DataCentricTasks:
    def test_violation_when_task_has_no_data_association(self):
        bad_task = _make_record(id="T1", name="Bad Task", subtype="ServiceTask")
        session = _make_session({"subtype in": [bad_task]})
        violations = mr._check_req1_data_centric_tasks(session)
        assert len(violations) == 1
        assert violations[0]["requirement"] == 1
        assert violations[0]["node_id"] == "T1"

    def test_no_violations_when_all_tasks_have_data(self):
        session = _make_session({"is_data_centric": []})
        violations = mr._check_req1_data_centric_tasks(session)
        assert violations == []


class TestReq2TasksInLanes:
    def test_violation_when_task_not_in_lane(self):
        orphan = _make_record(id="T2", name="Orphan Task")
        session = _make_session({"belongs_to": [orphan]})
        violations = mr._check_req2_tasks_in_lanes(session)
        assert len(violations) == 1
        assert violations[0]["requirement"] == 2

    def test_no_violations_when_all_tasks_assigned(self):
        session = _make_session({"belongs_to": []})
        violations = mr._check_req2_tasks_in_lanes(session)
        assert violations == []


class TestReq3PersistentDataObjects:
    def test_violation_when_persistent_object_unconnected(self):
        unconnected = _make_record(id="DO1", name="Certificate")
        session = _make_session({"d.name in": [unconnected]})
        violations = mr._check_req3_persistent_data_objects(session)
        assert len(violations) == 1
        assert violations[0]["requirement"] == 3

    def test_no_violations_when_all_connected(self):
        session = _make_session({"persistent": []})
        violations = mr._check_req3_persistent_data_objects(session)
        assert violations == []


# ---------------------------------------------------------------------------
# Annotation checks
# ---------------------------------------------------------------------------

class TestTaskAnnotations:
    def test_missing_audit_annotation_is_violation(self):
        task = _make_record(
            id="T3", name="Task",
            subtype="UserTask",
            annotation="Interaction Type=Online",  # missing Audit
        )
        session = _make_session({"return t.id": [task]})
        violations = mr._check_task_annotations(session)
        missing = [v["missing"] for v in violations]
        assert "Audit" in missing

    def test_missing_interaction_type_for_user_task(self):
        task = _make_record(
            id="T4", name="UserTask",
            subtype="UserTask",
            annotation="Audit=High",  # missing Interaction Type
        )
        session = _make_session({"return t.id": [task]})
        violations = mr._check_task_annotations(session)
        missing = [v["missing"] for v in violations]
        assert "Interaction Type" in missing

    def test_no_violations_for_fully_annotated_task(self):
        task = _make_record(
            id="T5", name="Send",
            subtype="SendTask",
            annotation="Communication Type=Mail; Audit=High",
        )
        session = _make_session({"return t.id": [task]})
        violations = mr._check_task_annotations(session)
        assert violations == []


class TestDataObjectAnnotations:
    def test_missing_personal_field_is_violation(self):
        do = _make_record(
            id="DO2", name="AppRequest",
            annotation="Size=10; Order of Size=KB; Load Dependence=1",
        )
        session = _make_session({"return d.id": [do]})
        violations = mr._check_data_object_annotations(session)
        missing = [v["missing"] for v in violations]
        assert "Personal" in missing

    def test_no_violations_when_all_fields_present(self):
        do = _make_record(
            id="DO3", name="AppRequest",
            annotation="Personal=yes; Size=5; Order of Size=KB; Load Dependence=2",
        )
        session = _make_session({"return d.id": [do]})
        violations = mr._check_data_object_annotations(session)
        assert violations == []


# ---------------------------------------------------------------------------
# run_refinement — combined integration
# ---------------------------------------------------------------------------

class TestRunRefinement:
    def _fully_compliant_session(self):
        """Mock session that returns no violations and some node counts."""
        session = MagicMock()

        def _run(query, **kwargs):
            q = query.lower()
            if "count(t)" in q:
                return _MockResult([_make_record(c=2)])
            if "count(d)" in q:
                return _MockResult([_make_record(c=1)])
            # All structural and annotation queries return empty (no violations)
            return _MockResult([])

        session.run = MagicMock(side_effect=_run)
        return session

    def test_passed_when_no_violations(self):
        session = self._fully_compliant_session()
        result = mr.run_refinement(session)
        assert result["passed"] is True
        assert result["score"] == 100.0
        assert result["violations"] == []

    def test_result_has_required_keys(self):
        session = self._fully_compliant_session()
        result = mr.run_refinement(session)
        assert "score" in result
        assert "violations" in result
        assert "passed" in result

    def test_score_decreases_with_violations(self):
        session = MagicMock()

        # Req1 returns one violation; everything else empty
        def _run(query, **kwargs):
            q = query.lower()
            if "count(t)" in q:
                return _MockResult([_make_record(c=1)])
            if "count(d)" in q:
                return _MockResult([_make_record(c=0)])
            if "is_data_centric" in q or "subtype in" in q:
                bad = _make_record(id="T1", name="Bad", subtype="ServiceTask")
                return _MockResult([bad])
            return _MockResult([])

        session.run = MagicMock(side_effect=_run)
        result = mr.run_refinement(session)
        assert result["passed"] is False
        assert result["score"] < 100.0
        assert len(result["violations"]) >= 1
