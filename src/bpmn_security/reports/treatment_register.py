"""
treatment_register.py
─────────────────────
Generate a GDPR Article 30 treatment register (CSV) from a threat model.

Implements Algorithm 4 of Granata et al. as described in §6.5 of the project
report.  Only tasks processing personal or persistent data objects are included.

Columns: Task, Data Object, CRUD Operation, Personal, Persistent, Risk Level,
         Risk Score, Mitigation.

Public API
──────────
``generate_register(threats, output_path)``

CLI
───
    python treatment_register.py <threats.json> <output.csv>
"""

from __future__ import annotations

import csv
import json
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# Column definitions
# ---------------------------------------------------------------------------

_COLUMNS = [
    "Task",
    "Data Object",
    "CRUD Operation",
    "Personal",
    "Persistent",
    "Risk Level",
    "Risk Score",
    "Mitigation",
]

# ---------------------------------------------------------------------------
# Filter helpers
# ---------------------------------------------------------------------------


def _is_personal_or_persistent(entry: dict) -> bool:
    """Return True if the threat entry relates to a personal or persistent data object."""
    # Check connected_data if present
    for obj in entry.get("connected_data", []):
        if obj.get("_is_personal") or obj.get("is_persistent"):
            return True

    # Fall back: check whether any annotation key indicates personal=yes
    annotation = entry.get("task_annotation", "")
    if "personal=yes" in annotation.lower():
        return True

    # Also include __personal__ threats from the catalogue
    threat = entry.get("threat", "").lower()
    personal_keywords = (
        "personal", "gdpr", "data subject", "privacy", "disclosure",
        "data protection", "consent", "data retention",
    )
    if any(kw in threat for kw in personal_keywords):
        return True

    return False


def _crud_operation_from_entry(entry: dict) -> str:
    """Infer the primary CRUD operation from a threat entry."""
    threat = entry.get("threat", "").lower()
    behaviour = entry.get("behaviour", "").lower()

    if any(kw in threat for kw in ("delete", "destroy", "deletion", "destruction")):
        return "DELETE"
    if "create" in behaviour or "generate" in behaviour:
        return "CREATE"
    if "modif" in behaviour or "alter" in behaviour or "update" in behaviour:
        return "UPDATE"
    return "READ"   # default


# ---------------------------------------------------------------------------
# De-duplication key
# ---------------------------------------------------------------------------


def _entry_key(entry: dict) -> tuple:
    return (
        entry.get("task_name", "") or entry.get("task_id", ""),
        entry.get("threat", ""),
        entry.get("agent_name", ""),
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def generate_register(
    threats: list[dict],
    output_path: str | Path,
) -> None:
    """Write a GDPR Article 30 treatment register CSV to *output_path*.

    Only threat entries relating to personal or persistent data are included.
    One row per unique (task, threat, agent) triple.

    Parameters
    ----------
    threats:
        List of threat entry dicts (output of
        ``threat_modelling.generate_threat_model()``).
    output_path:
        Destination CSV file path.
    """
    output_path = Path(output_path)
    seen_keys: set[tuple] = set()
    rows: list[dict] = []

    for entry in threats:
        if not _is_personal_or_persistent(entry):
            continue

        key = _entry_key(entry)
        if key in seen_keys:
            continue
        seen_keys.add(key)

        # Determine personal / persistent flags
        personal   = False
        persistent = False
        for obj in entry.get("connected_data", []):
            if obj.get("_is_personal"):
                personal = True
            if obj.get("is_persistent"):
                persistent = True

        # Also check annotation string
        ann = entry.get("task_annotation", "").lower()
        if "personal=yes" in ann:
            personal = True

        crud = _crud_operation_from_entry(entry)
        mitigation = entry.get("mitigation", "")

        rows.append({
            "Task":           entry.get("task_name") or entry.get("task_id", ""),
            "Data Object":    ", ".join(
                obj.get("name", obj.get("id", ""))
                for obj in entry.get("connected_data", [])
            ) or "—",
            "CRUD Operation": crud,
            "Personal":       "yes" if personal else "no",
            "Persistent":     "yes" if persistent else "no",
            "Risk Level":     entry.get("level", ""),
            "Risk Score":     round(entry.get("score", 0.0), 2),
            "Mitigation":     mitigation,
        })

    with output_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python treatment_register.py <threats.json> <output.csv>",
              file=sys.stderr)
        sys.exit(1)

    threats_path = Path(sys.argv[1])
    output_path  = Path(sys.argv[2])

    threats = json.loads(threats_path.read_text(encoding="utf-8"))
    generate_register(threats, output_path)
    print(f"Register written to {output_path}.")
