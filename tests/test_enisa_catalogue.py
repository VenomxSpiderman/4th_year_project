"""
tests/test_enisa_catalogue.py
─────────────────────────────
Pytest test suite for enisa_catalogue.py and scripts/import_catalogue.py.

Each test creates its own isolated SQLite database using pytest's ``tmp_path``
fixture, so tests are fully independent and leave no side effects.
"""

import json
import os
import sqlite3
import sys
from pathlib import Path

import pytest

# Make sure the project root is importable regardless of how pytest is invoked
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import enisa_catalogue
from scripts.import_catalogue import (
    main as import_main,
    validate_catalogue,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_db(path: Path, entries: list[dict]) -> None:
    """Create a minimal catalogue database at *path* from *entries*."""
    json_path = path.parent / "catalogue.json"
    json_path.write_text(json.dumps(entries), encoding="utf-8")
    rc = import_main(["--json", str(json_path), "--db", str(path)])
    assert rc == 0, "import_main failed during test setup"


def _minimal_entry(**overrides) -> dict:
    """Return a valid catalogue entry, with optional field overrides."""
    base = {
        "task_type":        "SendTask",
        "annotation_type":  "Communication Type",
        "annotation_value": "Mail",
        "threat":           "Test Threat",
        "behaviour":        "Test behaviour description.",
        "impact":           5,
        "mitigation":       "Apply recommended controls to mitigate this test threat.",
        "exclude_if":       [],
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# Test group 1: RuntimeError when the database is absent or malformed
# ---------------------------------------------------------------------------

class TestMissingDatabase:
    def test_raises_runtime_error_when_db_absent(self, tmp_path, monkeypatch):
        """get_enisa_threats() must raise RuntimeError when the DB file does not exist."""
        nonexistent = tmp_path / "no_such_file.db"
        monkeypatch.setenv("ENISA_CATALOGUE_DB", str(nonexistent))
        with pytest.raises(RuntimeError, match="not found"):
            enisa_catalogue.get_enisa_threats("Task", {}, False)

    def test_error_message_includes_db_path(self, tmp_path, monkeypatch):
        """The RuntimeError message must include the resolved database path."""
        db_path = tmp_path / "missing.db"
        monkeypatch.setenv("ENISA_CATALOGUE_DB", str(db_path))
        with pytest.raises(RuntimeError) as exc_info:
            enisa_catalogue.get_enisa_threats("SendTask", {}, False)
        assert str(db_path) in str(exc_info.value)

    def test_error_message_includes_import_instructions(self, tmp_path, monkeypatch):
        """The RuntimeError message must mention the import script."""
        db_path = tmp_path / "missing.db"
        monkeypatch.setenv("ENISA_CATALOGUE_DB", str(db_path))
        with pytest.raises(RuntimeError) as exc_info:
            enisa_catalogue.get_enisa_threats("Task", {}, False)
        assert "import_catalogue" in str(exc_info.value)

    def test_raises_when_table_missing(self, tmp_path, monkeypatch):
        """get_enisa_threats() must raise RuntimeError when the table is absent."""
        db_path = tmp_path / "empty.db"
        # Create a valid SQLite file but with no tables
        conn = sqlite3.connect(str(db_path))
        conn.close()
        monkeypatch.setenv("ENISA_CATALOGUE_DB", str(db_path))
        with pytest.raises(RuntimeError, match="enisa_threats"):
            enisa_catalogue.get_enisa_threats("Task", {}, False)


# ---------------------------------------------------------------------------
# Test group 2: Correct threat list returned for known (task_type, ann_dict)
# ---------------------------------------------------------------------------

class TestThreatLookup:
    def test_returns_threat_for_matching_entry(self, tmp_path, monkeypatch):
        """get_enisa_threats() returns the expected threat for a known lookup triple."""
        db_path = tmp_path / "cat.db"
        _make_db(db_path, [_minimal_entry()])
        monkeypatch.setenv("ENISA_CATALOGUE_DB", str(db_path))

        ann = {"Communication Type": "Mail"}
        results = enisa_catalogue.get_enisa_threats("SendTask", ann, False)
        threats = [r["threat"] for r in results]
        assert "Test Threat" in threats

    def test_returns_empty_for_no_matching_entry(self, tmp_path, monkeypatch):
        """get_enisa_threats() returns an empty list when no entry matches and
        the generic Task/__any__/__any__ group is also absent."""
        db_path = tmp_path / "cat.db"
        _make_db(db_path, [_minimal_entry()])  # only Mail entry exists
        monkeypatch.setenv("ENISA_CATALOGUE_DB", str(db_path))

        ann = {"Communication Type": "FTP"}   # no entry for FTP
        results = enisa_catalogue.get_enisa_threats("SendTask", ann, False)
        # Only generic Task/__any__/__any__ entries would fire, and we have none
        assert results == []

    def test_result_has_required_keys(self, tmp_path, monkeypatch):
        """Each returned dict must contain 'threat', 'behaviour', and 'impact'."""
        db_path = tmp_path / "cat.db"
        _make_db(db_path, [_minimal_entry()])
        monkeypatch.setenv("ENISA_CATALOGUE_DB", str(db_path))

        ann = {"Communication Type": "Mail"}
        results = enisa_catalogue.get_enisa_threats("SendTask", ann, False)
        assert len(results) >= 1
        for r in results:
            assert "threat" in r
            assert "behaviour" in r
            assert "impact" in r
            assert "mitigation" in r
            # exclude_if is consumed internally — must NOT be in the returned dict
            assert "exclude_if" not in r

    def test_impact_is_float(self, tmp_path, monkeypatch):
        """The 'impact' value must be a float (not a string)."""
        db_path = tmp_path / "cat.db"
        _make_db(db_path, [_minimal_entry(impact=7)])
        monkeypatch.setenv("ENISA_CATALOGUE_DB", str(db_path))

        ann = {"Communication Type": "Mail"}
        results = enisa_catalogue.get_enisa_threats("SendTask", ann, False)
        matching = [r for r in results if r["threat"] == "Test Threat"]
        assert matching, "Expected entry not found"
        assert isinstance(matching[0]["impact"], float)
        assert matching[0]["impact"] == 7.0

    def test_personal_data_group_appended_when_has_personal_data_true(
        self, tmp_path, monkeypatch
    ):
        """The personal-data threat group must be included when has_personal_data=True."""
        personal_entry = _minimal_entry(
            task_type="__personal__",
            annotation_type="__any__",
            annotation_value="__any__",
            threat="Information leakage / disclosure",
            behaviour="Personal data exposed.",
            impact=5,
        )
        db_path = tmp_path / "cat.db"
        _make_db(db_path, [personal_entry])
        monkeypatch.setenv("ENISA_CATALOGUE_DB", str(db_path))

        results = enisa_catalogue.get_enisa_threats("ServiceTask", {}, True)
        threats = [r["threat"] for r in results]
        assert "Information leakage / disclosure" in threats

    def test_personal_data_group_absent_when_has_personal_data_false(
        self, tmp_path, monkeypatch
    ):
        """The personal-data threat group must NOT be included when has_personal_data=False."""
        personal_entry = _minimal_entry(
            task_type="__personal__",
            annotation_type="__any__",
            annotation_value="__any__",
            threat="Information leakage / disclosure",
            behaviour="Personal data exposed.",
            impact=5,
        )
        db_path = tmp_path / "cat.db"
        _make_db(db_path, [personal_entry])
        monkeypatch.setenv("ENISA_CATALOGUE_DB", str(db_path))

        results = enisa_catalogue.get_enisa_threats("ServiceTask", {}, False)
        threats = [r["threat"] for r in results]
        assert "Information leakage / disclosure" not in threats

    def test_no_duplicate_threats_returned(self, tmp_path, monkeypatch):
        """Duplicate threat names must not appear in the output."""
        entry1 = _minimal_entry(threat="Duplicate Threat")
        entry2 = _minimal_entry(
            annotation_value="Post-Office",
            threat="Duplicate Threat",  # same threat name, different key
        )
        db_path = tmp_path / "cat.db"
        _make_db(db_path, [entry1, entry2])
        monkeypatch.setenv("ENISA_CATALOGUE_DB", str(db_path))

        ann = {"Communication Type": "Mail"}
        results = enisa_catalogue.get_enisa_threats("SendTask", ann, False)
        threat_names = [r["threat"] for r in results]
        assert threat_names.count("Duplicate Threat") == 1


# ---------------------------------------------------------------------------
# Test group 3: exclude_if suppression logic
# ---------------------------------------------------------------------------

class TestExcludeIf:
    def test_threat_suppressed_when_annotation_value_in_exclude_if(
        self, tmp_path, monkeypatch
    ):
        """A threat must be suppressed when the annotation value matches exclude_if."""
        entry = _minimal_entry(
            annotation_value="Mail",
            threat="Integrity Threat",
            exclude_if=["PEC"],
        )
        pec_entry = _minimal_entry(
            annotation_value="PEC",
            threat="Integrity Threat",
            exclude_if=["PEC"],   # same entry, different annotation_value key
        )
        db_path = tmp_path / "cat.db"
        _make_db(db_path, [entry, pec_entry])
        monkeypatch.setenv("ENISA_CATALOGUE_DB", str(db_path))

        ann = {"Communication Type": "PEC"}
        results = enisa_catalogue.get_enisa_threats("SendTask", ann, False)
        threats = [r["threat"] for r in results]
        assert "Integrity Threat" not in threats, (
            "Integrity Threat should be excluded when Communication Type = PEC"
        )

    def test_threat_present_when_annotation_value_not_in_exclude_if(
        self, tmp_path, monkeypatch
    ):
        """A threat must appear when the annotation value does NOT match exclude_if."""
        entry = _minimal_entry(
            annotation_value="Mail",
            threat="Integrity Threat",
            exclude_if=["PEC"],
        )
        db_path = tmp_path / "cat.db"
        _make_db(db_path, [entry])
        monkeypatch.setenv("ENISA_CATALOGUE_DB", str(db_path))

        ann = {"Communication Type": "Mail"}
        results = enisa_catalogue.get_enisa_threats("SendTask", ann, False)
        threats = [r["threat"] for r in results]
        assert "Integrity Threat" in threats, (
            "Integrity Threat should be present when Communication Type = Mail"
        )

    def test_null_exclude_if_never_suppresses(self, tmp_path, monkeypatch):
        """An entry with no exclude_if must always be included."""
        entry = _minimal_entry(threat="Always Present Threat")
        # Deliberately omit exclude_if entirely
        del entry["exclude_if"]
        db_path = tmp_path / "cat.db"
        _make_db(db_path, [entry])
        monkeypatch.setenv("ENISA_CATALOGUE_DB", str(db_path))

        ann = {"Communication Type": "Mail"}
        results = enisa_catalogue.get_enisa_threats("SendTask", ann, False)
        threats = [r["threat"] for r in results]
        assert "Always Present Threat" in threats


# ---------------------------------------------------------------------------
# Test group 4: import_catalogue.py validation
# ---------------------------------------------------------------------------

class TestImportCatalogue:
    def test_validate_only_does_not_create_db(self, tmp_path):
        """--validate-only must not create any database file."""
        json_path = tmp_path / "catalogue.json"
        json_path.write_text(json.dumps([_minimal_entry()]), encoding="utf-8")
        db_path = tmp_path / "should_not_exist.db"

        rc = import_main([
            "--json", str(json_path),
            "--db",   str(db_path),
            "--validate-only",
        ])
        assert rc == 0
        assert not db_path.exists()

    def test_idempotent_second_run(self, tmp_path):
        """Running import twice must produce the same row count (no duplicates)."""
        json_path = tmp_path / "catalogue.json"
        json_path.write_text(json.dumps([_minimal_entry()]), encoding="utf-8")
        db_path = tmp_path / "cat.db"

        import_main(["--json", str(json_path), "--db", str(db_path)])
        import_main(["--json", str(json_path), "--db", str(db_path)])

        conn = sqlite3.connect(str(db_path))
        count = conn.execute("SELECT COUNT(*) FROM enisa_threats").fetchone()[0]
        conn.close()
        assert count == 1, f"Expected 1 row after two imports, got {count}"

    def test_missing_required_field_returns_error(self):
        """validate_catalogue must report an error when a required field is missing."""
        bad_entry = {"task_type": "SendTask"}  # missing most fields
        errors = validate_catalogue([bad_entry])
        assert len(errors) > 0

    def test_impact_out_of_range_returns_error(self):
        """validate_catalogue must report an error when impact is outside 1–9."""
        bad_entry = _minimal_entry(impact=10)
        errors = validate_catalogue([bad_entry])
        assert any("impact" in e for e in errors)

    def test_exclude_if_not_list_returns_error(self):
        """validate_catalogue must report an error when exclude_if is not a list."""
        bad_entry = _minimal_entry(exclude_if="PEC")  # string instead of list
        errors = validate_catalogue([bad_entry])
        assert any("exclude_if" in e for e in errors)

    def test_valid_entry_produces_no_errors(self):
        """validate_catalogue must return no errors for a fully valid entry."""
        errors = validate_catalogue([_minimal_entry()])
        assert errors == []

    def test_full_catalogue_json_is_valid(self):
        """The production data/enisa_catalogue.json must pass validation with zero errors."""
        json_path = Path("data") / "enisa_catalogue.json"
        if not json_path.exists():
            pytest.skip("data/enisa_catalogue.json not found — run from project root.")
        entries = json.loads(json_path.read_text(encoding="utf-8"))
        errors = validate_catalogue(entries)
        assert errors == [], f"Production catalogue has validation errors:\n" + "\n".join(errors)

    def test_import_creates_db_with_correct_row_count(self, tmp_path):
        """import_main must create a database with exactly as many rows as JSON entries."""
        entries = [_minimal_entry(), _minimal_entry(annotation_value="PEC")]
        json_path = tmp_path / "catalogue.json"
        json_path.write_text(json.dumps(entries), encoding="utf-8")
        db_path = tmp_path / "cat.db"

        rc = import_main(["--json", str(json_path), "--db", str(db_path)])
        assert rc == 0

        conn = sqlite3.connect(str(db_path))
        count = conn.execute("SELECT COUNT(*) FROM enisa_threats").fetchone()[0]
        conn.close()
        assert count == 2
