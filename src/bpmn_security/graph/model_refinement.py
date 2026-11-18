"""
model_refinement.py
───────────────────
Validate a BPMN graph stored in Neo4j against structural and annotation
requirements before threat modelling proceeds.

Implements §5.3 of the project report.

Public API
──────────
``run_refinement(session) -> dict``
    Returns ``{"score": float, "violations": list[dict], "passed": bool}``.

CLI
───
    python model_refinement.py
    Reads Neo4j credentials from NEO4J_URI / NEO4J_USER / NEO4J_PASSWORD.
    Prints the result JSON to stdout.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Persistent data-object names (must match bpmn_reader._PERSISTENT_NAMES)
# ---------------------------------------------------------------------------

_PERSISTENT_NAMES: frozenset[str] = frozenset({
    "Profile",
    "Certificate",
    "ApplicationRequest",
    "PaymentRecord",
    "AuditLog",
    "StoredDocument",
})

# ---------------------------------------------------------------------------
# Annotation requirement definitions
# ---------------------------------------------------------------------------

# Task annotation requirements: task subtype → required annotation keys
_TASK_ANNOTATION_REQS: dict[str, list[str]] = {
    "SendTask":    ["Communication Type"],
    "ReceiveTask": ["Communication Type"],
    "UserTask":    ["Interaction Type"],
}

# All tasks must carry an Audit annotation
_TASK_AUDIT_REQ = "Audit"

# Data object annotation requirements
_DATA_OBJ_ANNOTATION_REQS: list[str] = [
    "Personal", "Size", "Order of Size", "Load Dependence",
]

# ---------------------------------------------------------------------------
# Requirement checkers (each returns a list of violation dicts)
# ---------------------------------------------------------------------------


def _check_req1_data_centric_tasks(session) -> list[dict]:
    """Req 1: data-centric tasks (UserTask, ServiceTask, ScriptTask) must have
    at least one READ/CREATE/UPDATE/DELETE edge to a DataObject node.
    """
    query = """
    MATCH (t:Task)
    WHERE t.subtype IN ['UserTask', 'ServiceTask', 'ScriptTask']
    AND NOT EXISTS {
        MATCH (t)-[:READ|CREATE|UPDATE|DELETE]->(:DataObject)
    }
    RETURN t.id AS id, t.name AS name, t.subtype AS subtype
    """
    violations = []
    result = session.run(query)
    for record in result:
        violations.append({
            "requirement": 1,
            "description": "Data-centric task has no data-object association",
            "node_id":   record["id"],
            "node_name": record["name"],
            "subtype":   record["subtype"],
        })
    return violations


def _check_req2_tasks_in_lanes(session) -> list[dict]:
    """Req 2: every task node must have a BELONGS_TO edge to a Lane or Process."""
    query = """
    MATCH (t:Task)
    WHERE NOT EXISTS {
        MATCH (t)-[:BELONGS_TO]->(:Lane)
    }
    AND NOT EXISTS {
        MATCH (t)-[:BELONGS_TO]->(:Process)
    }
    RETURN t.id AS id, t.name AS name
    """
    violations = []
    result = session.run(query)
    for record in result:
        violations.append({
            "requirement": 2,
            "description": "Task is not connected to any Lane or Process",
            "node_id":   record["id"],
            "node_name": record["name"],
        })
    return violations


def _check_req3_persistent_data_objects(session) -> list[dict]:
    """Req 3: persistent data objects must have at least one data-association edge."""
    persistent_list = list(_PERSISTENT_NAMES)
    query = """
    MATCH (d:DataObject)
    WHERE d.name IN $names
    AND NOT EXISTS {
        MATCH (:Task)-[:READ|CREATE|UPDATE|DELETE]->(d)
    }
    RETURN d.id AS id, d.name AS name
    """
    violations = []
    result = session.run(query, names=persistent_list)
    for record in result:
        violations.append({
            "requirement": 3,
            "description": "Persistent data object has no data-association edge",
            "node_id":   record["id"],
            "node_name": record["name"],
        })
    return violations


def _parse_annotation_keys(annotation: str | None) -> set[str]:
    """Return the set of annotation key names present in the raw annotation string."""
    if not annotation:
        return set()
    keys = set()
    for token in annotation.split(";"):
        token = token.strip()
        if "=" in token:
            key, _, _ = token.partition("=")
            keys.add(key.strip())
    return keys


def _check_task_annotations(session) -> list[dict]:
    """Check that each task carries the annotation fields required for its subtype."""
    query = """
    MATCH (t:Task)
    RETURN t.id AS id, t.name AS name, t.subtype AS subtype,
           t.annotation AS annotation
    """
    violations = []
    result = session.run(query)
    for record in result:
        ann_keys    = _parse_annotation_keys(record["annotation"])
        subtype     = record.get("subtype") or ""
        required    = _TASK_ANNOTATION_REQS.get(subtype, []) + [_TASK_AUDIT_REQ]
        for req_key in required:
            if req_key not in ann_keys:
                violations.append({
                    "requirement": "annotation_task",
                    "description": f"Task missing required annotation '{req_key}'",
                    "node_id":   record["id"],
                    "node_name": record["name"],
                    "subtype":   subtype,
                    "missing":   req_key,
                })
    return violations


def _check_data_object_annotations(session) -> list[dict]:
    """Check that each DataObject carries all four privacy-relevant annotation fields."""
    query = """
    MATCH (d:DataObject)
    RETURN d.id AS id, d.name AS name, d.annotation AS annotation
    """
    violations = []
    result = session.run(query)
    for record in result:
        ann_keys = _parse_annotation_keys(record["annotation"])
        for req_key in _DATA_OBJ_ANNOTATION_REQS:
            if req_key not in ann_keys:
                violations.append({
                    "requirement": "annotation_data_object",
                    "description": f"DataObject missing required annotation '{req_key}'",
                    "node_id":   record["id"],
                    "node_name": record["name"],
                    "missing":   req_key,
                })
    return violations


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def run_refinement(session) -> dict:
    """Run all structural and annotation refinement checks.

    Parameters
    ----------
    session:
        An open Neo4j driver session.

    Returns
    -------
    dict with keys:
        ``score``      – float 0.0–100.0  (percentage of requirements satisfied).
        ``violations`` – list of violation dicts.
        ``passed``     – bool (True iff score == 100.0).
    """
    all_violations: list[dict] = []

    # --- Structural requirements (§5.3.1) ---
    all_violations.extend(_check_req1_data_centric_tasks(session))
    all_violations.extend(_check_req2_tasks_in_lanes(session))
    all_violations.extend(_check_req3_persistent_data_objects(session))

    # --- Annotation requirements (§5.3.2) ---
    all_violations.extend(_check_task_annotations(session))
    all_violations.extend(_check_data_object_annotations(session))

    # --- Compute score (§5.3.3) ---
    # Each structural requirement is one unit; each annotation violation is one
    # unit.  Total requirements = 3 structural + number of annotation checks
    # across all nodes.  Score = (satisfied / total) × 100.
    total      = 3 + len(all_violations) + _count_annotation_checks(session)
    satisfied  = total - len(all_violations)
    score      = (satisfied / total * 100.0) if total > 0 else 100.0

    return {
        "score":      round(score, 2),
        "violations": all_violations,
        "passed":     len(all_violations) == 0,
    }


def _count_annotation_checks(session) -> int:
    """Count the total number of annotation requirement checks that were made."""
    task_count = session.run("MATCH (t:Task) RETURN count(t) AS c").single()["c"]
    data_count = session.run("MATCH (d:DataObject) RETURN count(d) AS c").single()["c"]
    return int(task_count) * (1 + 1) + int(data_count) * len(_DATA_OBJ_ANNOTATION_REQS)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    neo4j_uri  = os.environ.get("NEO4J_URI",      "bolt://localhost:7687")
    neo4j_user = os.environ.get("NEO4J_USER",     "neo4j")
    neo4j_pw   = os.environ.get("NEO4J_PASSWORD", "")
    if not neo4j_pw:
        sys.exit(
            "ERROR: NEO4J_PASSWORD environment variable is not set."
        )

    from neo4j import GraphDatabase  # type: ignore
    driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_pw))
    try:
        with driver.session() as session:
            result = run_refinement(session)
    finally:
        driver.close()

    print(json.dumps(result, indent=2))
    if result["passed"]:
        print("\n✓ Model is fully refined (score = 100.0%)")
    else:
        print(f"\n✗ Refinement score: {result['score']}% — "
              f"{len(result['violations'])} violation(s) found.")
