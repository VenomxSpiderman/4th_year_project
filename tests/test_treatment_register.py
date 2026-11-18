"""
tests/test_treatment_register.py
──────────────────────────────────
Tests for treatment_register.py.
"""

import csv
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from treatment_register import generate_register, _is_personal_or_persistent, _crud_operation_from_entry


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _personal_threat():
    return {
        "agent_name":      "Cybercriminal",
        "task_id":         "T1",
        "task_name":       "Verify Identity",
        "task_subtype":    "UserTask",
        "task_annotation": "Interaction Type=Offline; Audit=High",
        "threat":          "Information leakage / disclosure",
        "behaviour":       "Personal data exposed to unauthorised parties.",
        "mitigation":      "Apply RBAC and encryption at rest.",
        "impact":          5.0,
        "score":           4.5,
        "level":           "Medium",
        "connected_data":  [
            {"id": "DO1", "name": "ApplicationRequest",
             "_is_personal": True, "is_persistent": True},
        ],
    }


def _non_personal_threat():
    return {
        "agent_name":      "Script Kiddie",
        "task_id":         "T2",
        "task_name":       "Compute Hash",
        "task_subtype":    "ServiceTask",
        "task_annotation": "Communication Type=Stateless; Audit=High",
        "threat":          "Denial of service",
        "behaviour":       "Flood of requests.",
        "mitigation":      "Rate limiting.",
        "impact":          6.0,
        "score":           3.0,
        "level":           "Low",
        "connected_data":  [],
    }


# ---------------------------------------------------------------------------
# _is_personal_or_persistent
# ---------------------------------------------------------------------------

class TestIsPersonalOrPersistent:
    def test_personal_data_object_returns_true(self):
        entry = {"connected_data": [{"_is_personal": True, "is_persistent": False}]}
        assert _is_personal_or_persistent(entry) is True

    def test_persistent_data_object_returns_true(self):
        entry = {"connected_data": [{"_is_personal": False, "is_persistent": True}]}
        assert _is_personal_or_persistent(entry) is True

    def test_no_personal_no_persistent_returns_false_unless_threat_keywords(self):
        entry = {
            "connected_data": [],
            "task_annotation": "",
            "threat": "Denial of service",
        }
        assert _is_personal_or_persistent(entry) is False

    def test_annotation_personal_yes_returns_true(self):
        entry = {"connected_data": [], "task_annotation": "Personal=yes", "threat": "x"}
        assert _is_personal_or_persistent(entry) is True

    def test_gdpr_threat_keyword_returns_true(self):
        entry = {"connected_data": [], "task_annotation": "", "threat": "GDPR violation"}
        assert _is_personal_or_persistent(entry) is True


# ---------------------------------------------------------------------------
# _crud_operation_from_entry
# ---------------------------------------------------------------------------

class TestCrudOperationFromEntry:
    def test_delete_in_threat(self):
        entry = {"threat": "Destruction of records", "behaviour": "Records deleted."}
        assert _crud_operation_from_entry(entry) == "DELETE"

    def test_create_in_behaviour(self):
        entry = {"threat": "Integrity risk", "behaviour": "Attacker creates fake record."}
        assert _crud_operation_from_entry(entry) == "CREATE"

    def test_default_to_read(self):
        entry = {"threat": "Interception", "behaviour": "Data captured in transit."}
        assert _crud_operation_from_entry(entry) == "READ"


# ---------------------------------------------------------------------------
# generate_register
# ---------------------------------------------------------------------------

class TestGenerateRegister:
    def test_file_created(self, tmp_path):
        path = tmp_path / "register.csv"
        generate_register([_personal_threat()], path)
        assert path.exists()

    def test_has_expected_columns(self, tmp_path):
        path = tmp_path / "register.csv"
        generate_register([_personal_threat()], path)
        with open(path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            assert "Task" in reader.fieldnames
            assert "Data Object" in reader.fieldnames
            assert "CRUD Operation" in reader.fieldnames
            assert "Personal" in reader.fieldnames
            assert "Persistent" in reader.fieldnames
            assert "Risk Level" in reader.fieldnames
            assert "Risk Score" in reader.fieldnames
            assert "Mitigation" in reader.fieldnames

    def test_mitigation_column_has_value(self, tmp_path):
        path = tmp_path / "register.csv"
        generate_register([_personal_threat()], path)
        with open(path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        assert len(rows) >= 1
        assert rows[0]["Mitigation"] != ""

    def test_non_personal_threats_excluded(self, tmp_path):
        path = tmp_path / "register.csv"
        generate_register([_non_personal_threat()], path)
        with open(path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        assert len(rows) == 0

    def test_personal_threats_included(self, tmp_path):
        path = tmp_path / "register.csv"
        generate_register([_personal_threat()], path)
        with open(path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        assert len(rows) == 1

    def test_mixed_threats_filters_correctly(self, tmp_path):
        path = tmp_path / "register.csv"
        generate_register([_personal_threat(), _non_personal_threat()], path)
        with open(path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        assert len(rows) == 1
        assert rows[0]["Task"] == "Verify Identity"

    def test_deduplication_same_key(self, tmp_path):
        """Duplicate (task, threat, agent) triples should appear only once."""
        path = tmp_path / "register.csv"
        t = _personal_threat()
        generate_register([t, t], path)
        with open(path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        assert len(rows) == 1

    def test_personal_column_yes_for_personal_data(self, tmp_path):
        path = tmp_path / "register.csv"
        generate_register([_personal_threat()], path)
        with open(path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        assert rows[0]["Personal"] == "yes"

    def test_empty_threat_list_produces_only_header(self, tmp_path):
        path = tmp_path / "register.csv"
        generate_register([], path)
        with open(path, newline="", encoding="utf-8") as f:
            content = f.read()
        lines = [l for l in content.splitlines() if l.strip()]
        assert len(lines) == 1  # header only

    def test_score_is_numeric(self, tmp_path):
        path = tmp_path / "register.csv"
        generate_register([_personal_threat()], path)
        with open(path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        float(rows[0]["Risk Score"])  # must not raise
