#!/usr/bin/env python3
"""
scripts/import_catalogue.py
───────────────────────────
Seed (or rebuild) the ENISA threat catalogue SQLite database from a versioned
JSON source file.

Usage
-----
  python scripts/import_catalogue.py                        # use defaults
  python scripts/import_catalogue.py --json path/to/file.json --db path/to/out.db
  python scripts/import_catalogue.py --validate-only        # check JSON, no DB write

The script is fully idempotent: it drops and recreates the `enisa_threats` table
on every run, so repeated imports always produce a clean, consistent database.

Exit codes
----------
  0  success
  1  JSON validation error or I/O error
"""

import argparse
import json
import os
import sqlite3
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_JSON = Path("data") / "enisa_catalogue.json"
DEFAULT_DB   = Path("data") / "enisa_catalogue.db"

REQUIRED_FIELDS = {"task_type", "annotation_type", "annotation_value",
                   "threat", "behaviour", "impact"}

DDL_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS enisa_threats (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    task_type        TEXT    NOT NULL,
    annotation_type  TEXT    NOT NULL,
    annotation_value TEXT    NOT NULL,
    threat           TEXT    NOT NULL,
    behaviour        TEXT    NOT NULL,
    impact           REAL    NOT NULL,
    exclude_if       TEXT,           -- JSON array string, nullable
    mitigation       TEXT            -- concrete remediation recommendation, nullable
);
"""

DDL_CREATE_INDEX = """
CREATE INDEX IF NOT EXISTS idx_enisa_lookup
    ON enisa_threats (task_type, annotation_type, annotation_value);
"""

INSERT_SQL = """
INSERT INTO enisa_threats
    (task_type, annotation_type, annotation_value, threat, behaviour, impact, exclude_if, mitigation)
VALUES (?, ?, ?, ?, ?, ?, ?, ?);
"""

# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

def _validate_entry(entry: dict, index: int) -> list[str]:
    """Return a list of validation error strings for *entry* at *index*.

    An empty list means the entry is valid.
    """
    errors: list[str] = []
    loc = f"Entry [{index}]"

    # --- required fields present and non-empty strings ----------------------
    for field in REQUIRED_FIELDS - {"impact"}:
        value = entry.get(field)
        if value is None:
            errors.append(f"{loc}: missing required field '{field}'.")
        elif not isinstance(value, str) or not value.strip():
            errors.append(
                f"{loc}: '{field}' must be a non-empty string, got {value!r}."
            )

    # --- impact: number in [1, 9] -------------------------------------------
    impact = entry.get("impact")
    if impact is None:
        errors.append(f"{loc}: missing required field 'impact'.")
    elif not isinstance(impact, (int, float)):
        errors.append(
            f"{loc}: 'impact' must be a number, got {impact!r} ({type(impact).__name__})."
        )
    elif not (1 <= float(impact) <= 9):
        errors.append(
            f"{loc}: 'impact' must be between 1 and 9, got {impact}."
        )

    # --- exclude_if: optional list of non-empty strings ---------------------
    exclude_if = entry.get("exclude_if")
    if exclude_if is not None:
        if not isinstance(exclude_if, list):
            errors.append(
                f"{loc}: 'exclude_if' must be a list, got {type(exclude_if).__name__}."
            )
        else:
            for i, val in enumerate(exclude_if):
                if not isinstance(val, str) or not val.strip():
                    errors.append(
                        f"{loc}: 'exclude_if[{i}]' must be a non-empty string, got {val!r}."
                    )

    # --- mitigation: required non-empty string ------------------------------
    mitigation = entry.get("mitigation")
    if mitigation is None:
        errors.append(f"{loc}: missing required field 'mitigation'.")
    elif not isinstance(mitigation, str) or not mitigation.strip():
        errors.append(
            f"{loc}: 'mitigation' must be a non-empty string, got {mitigation!r}."
        )

    return errors


def validate_catalogue(entries: list) -> list[str]:
    """Validate all entries; return a flat list of all error messages."""
    if not isinstance(entries, list):
        return ["Top-level JSON value must be an array."]

    all_errors: list[str] = []
    for idx, entry in enumerate(entries):
        # Skip comment-only objects (keys starting with '_')
        if all(k.startswith("_") for k in entry.keys()):
            continue
        # Strip comment keys before validating
        clean_entry = {k: v for k, v in entry.items() if not k.startswith("_")}
        all_errors.extend(_validate_entry(clean_entry, idx))

    return all_errors


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

def _create_schema(conn: sqlite3.Connection) -> None:
    conn.execute("DROP TABLE IF EXISTS enisa_threats;")
    conn.execute(DDL_CREATE_TABLE)
    conn.execute(DDL_CREATE_INDEX)


def _insert_entries(conn: sqlite3.Connection, entries: list) -> int:
    """Insert all *entries* in a single transaction; return inserted row count."""
    rows = []
    for entry in entries:
        # Skip comment-only objects
        if all(k.startswith("_") for k in entry.keys()):
            continue
        clean = {k: v for k, v in entry.items() if not k.startswith("_")}
        exclude_if_raw = clean.get("exclude_if")
        exclude_if_str = json.dumps(exclude_if_raw) if exclude_if_raw else None
        rows.append((
            clean["task_type"],
            clean["annotation_type"],
            clean["annotation_value"],
            clean["threat"],
            clean["behaviour"],
            float(clean["impact"]),
            exclude_if_str,
            clean.get("mitigation") or None,
        ))

    with conn:          # context manager commits or rolls back
        conn.executemany(INSERT_SQL, rows)

    return len(rows)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="import_catalogue",
        description="Seed the ENISA catalogue SQLite database from a JSON source file.",
    )
    parser.add_argument(
        "--json",
        dest="json_path",
        default=str(DEFAULT_JSON),
        metavar="PATH",
        help=f"Path to the catalogue JSON file (default: {DEFAULT_JSON}).",
    )
    parser.add_argument(
        "--db",
        dest="db_path",
        default=str(DEFAULT_DB),
        metavar="PATH",
        help=f"Path for the output SQLite database (default: {DEFAULT_DB}).",
    )
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="Validate the JSON file without writing to the database.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    json_path = Path(args.json_path)
    db_path   = Path(args.db_path)

    # --- Load JSON ----------------------------------------------------------
    if not json_path.exists():
        print(f"ERROR: JSON file not found: {json_path}", file=sys.stderr)
        return 1

    try:
        raw = json_path.read_text(encoding="utf-8")
        entries = json.loads(raw)
    except json.JSONDecodeError as exc:
        print(f"ERROR: Failed to parse JSON from {json_path}:\n  {exc}", file=sys.stderr)
        return 1

    # --- Validate -----------------------------------------------------------
    errors = validate_catalogue(entries)
    if errors:
        print(f"ERROR: {len(errors)} validation error(s) in {json_path}:", file=sys.stderr)
        for err in errors:
            print(f"  {err}", file=sys.stderr)
        return 1

    # Non-comment entries count
    real_entries = [e for e in entries if not all(k.startswith("_") for k in e.keys())]
    print(f"Validated {len(real_entries)} entries in {json_path}.")

    if args.validate_only:
        print("--validate-only requested; database not modified.")
        return 0

    # --- Write database -----------------------------------------------------
    db_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        conn = sqlite3.connect(str(db_path))
    except sqlite3.Error as exc:
        print(f"ERROR: Cannot open database at {db_path}:\n  {exc}", file=sys.stderr)
        return 1

    try:
        _create_schema(conn)
        count = _insert_entries(conn, entries)
    except sqlite3.Error as exc:
        print(f"ERROR: Database write failed:\n  {exc}", file=sys.stderr)
        conn.close()
        return 1
    finally:
        conn.close()

    print(f"Imported {count} entries into {db_path}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
