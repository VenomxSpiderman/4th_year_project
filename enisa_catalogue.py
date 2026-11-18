"""
enisa_catalogue.py
──────────────────
ENISA threat catalogue loader backed by a SQLite database.

Database path resolution (in order of precedence):
  1. The ``ENISA_CATALOGUE_DB`` environment variable.
  2. The default path ``data/enisa_catalogue.db`` relative to the working directory.

If the resolved path does not exist, or the ``enisa_threats`` table is absent,
a ``RuntimeError`` is raised immediately with instructions to run the import script.

To rebuild the database from the versioned JSON source::

    python scripts/import_catalogue.py

Public API
──────────
The only public symbol is ``get_enisa_threats``, whose signature and return-value
structure are identical to the previous hardcoded-dict implementation so that
``threat_modelling.py`` requires zero changes.
"""

import json
import os
import sqlite3
from pathlib import Path

# ---------------------------------------------------------------------------
# Path resolution
# ---------------------------------------------------------------------------

_DEFAULT_DB_PATH = Path("data") / "enisa_catalogue.db"


def _resolve_db_path() -> Path:
    """Return the catalogue database path, preferring ``ENISA_CATALOGUE_DB``."""
    env_val = os.environ.get("ENISA_CATALOGUE_DB")
    return Path(env_val) if env_val else _DEFAULT_DB_PATH


# ---------------------------------------------------------------------------
# Low-level loader
# ---------------------------------------------------------------------------

def _load_catalogue(
    task_type: str,
    annotation_type: str,
    annotation_value: str,
) -> list[dict]:
    """Query the SQLite catalogue for a specific (task_type, annotation_type, annotation_value)
    triple and return a list of threat-entry dicts.

    Each returned dict has keys:
        ``threat``      – high-level ENISA threat category name.
        ``behaviour``   – detailed description of the specific malicious action.
        ``impact``      – base impact score (float, 1–9 OWASP scale).
        ``exclude_if``  – list of annotation values that suppress this threat (may be empty).
        ``mitigation``  – concrete remediation recommendation (may be empty string).

    Raises
    ------
    RuntimeError
        If the database file does not exist or the ``enisa_threats`` table is missing.
    """
    db_path = _resolve_db_path()

    if not db_path.exists():
        raise RuntimeError(
            f"ENISA catalogue database not found at: {db_path}\n"
            f"Run the import script to create it:\n"
            f"    python scripts/import_catalogue.py\n"
            f"To use a custom path set the ENISA_CATALOGUE_DB environment variable."
        )

    try:
        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row
    except sqlite3.Error as exc:
        raise RuntimeError(
            f"Cannot open ENISA catalogue database at {db_path}: {exc}"
        ) from exc

    try:
        # Verify the table exists
        table_check = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='enisa_threats';"
        ).fetchone()
        if table_check is None:
            raise RuntimeError(
                f"The 'enisa_threats' table is missing in {db_path}.\n"
                f"Rebuild the database by running:\n"
                f"    python scripts/import_catalogue.py"
            )

        rows = conn.execute(
            """
            SELECT threat, behaviour, impact, exclude_if, mitigation
            FROM   enisa_threats
            WHERE  task_type        = ?
              AND  annotation_type  = ?
              AND  annotation_value = ?
            """,
            (task_type, annotation_type, annotation_value),
        ).fetchall()

    except sqlite3.Error as exc:
        raise RuntimeError(
            f"Query failed on ENISA catalogue database {db_path}: {exc}"
        ) from exc
    finally:
        conn.close()

    results: list[dict] = []
    for row in rows:
        exclude_if_raw = row["exclude_if"]
        exclude_if: list[str] = json.loads(exclude_if_raw) if exclude_if_raw else []
        results.append({
            "threat":      row["threat"],
            "behaviour":   row["behaviour"],
            "impact":      float(row["impact"]),
            "exclude_if":  exclude_if,
            "mitigation":  row["mitigation"] or "",
        })
    return results


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_enisa_threats(
    task_type: str,
    ann_dict: dict,
    has_personal_data: bool,
) -> list[dict]:
    """Return all applicable ENISA threat entries for a given task.

    This function preserves the original hardcoded-dict API exactly.

    Parameters
    ----------
    task_type:
        BPMN task subtype string, e.g. ``"SendTask"``, ``"UserTask"``,
        ``"ServiceTask"``, ``"ReceiveTask"``, or ``"Task"``.
    ann_dict:
        Parsed annotation dictionary for the task, as produced by
        ``annotation_parser.parse_annotation()``.  Keys include
        ``"Communication Type"``, ``"Interaction Type"``, ``"Audit"``, etc.
    has_personal_data:
        ``True`` if the task is connected to at least one data object whose
        ``Personal`` annotation field is ``"yes"``.

    Returns
    -------
    list[dict]
        Each dict has keys: ``threat``, ``behaviour``, ``impact``,
        ``mitigation``.
        (``exclude_if`` is consumed internally and not forwarded.)

    Raises
    ------
    RuntimeError
        If the catalogue database is missing or malformed.
        See module docstring for how to resolve this.
    """
    threats: list[dict] = []
    seen_threats: set[str] = set()

    def _add_if_applicable(entries: list[dict], active_ann_value: str) -> None:
        """Apply exclusion logic and accumulate non-duplicate threat entries."""
        for entry in entries:
            # Exclusion: skip this threat if the active annotation value is in exclude_if
            if active_ann_value in entry["exclude_if"]:
                continue
            key = entry["threat"]
            if key not in seen_threats:
                seen_threats.add(key)
                threats.append({
                    "threat":      entry["threat"],
                    "behaviour":   entry["behaviour"],
                    "impact":      entry["impact"],
                    "mitigation":  entry.get("mitigation", ""),
                })

    # ------------------------------------------------------------------
    # 1. Annotation-keyed lookup: check every annotation field present
    #    in ann_dict against the catalogue.
    # ------------------------------------------------------------------
    for ann_type, ann_value in ann_dict.items():
        # Normalise to string for comparison
        ann_value_str = str(ann_value).strip()
        entries = _load_catalogue(task_type, ann_type, ann_value_str)
        _add_if_applicable(entries, ann_value_str)

    # ------------------------------------------------------------------
    # 2. Generic (wildcard) lookup: Task / __any__ / __any__
    #    Covers the "erroneous use" and similar always-on threats.
    # ------------------------------------------------------------------
    generic_entries = _load_catalogue("Task", "__any__", "__any__")
    _add_if_applicable(generic_entries, "__any__")

    # ------------------------------------------------------------------
    # 3. Personal-data threat group (§6.3.2)
    #    Appended whenever the task touches personal data, regardless of
    #    task type or annotation value.
    # ------------------------------------------------------------------
    if has_personal_data:
        personal_entries = _load_catalogue("__personal__", "__any__", "__any__")
        _add_if_applicable(personal_entries, "__any__")

    return threats
