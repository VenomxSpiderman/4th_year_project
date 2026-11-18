"""
threat_modelling.py
───────────────────
Context-aware threat modelling engine for BPMN process graphs.

Implements §5.5 and §5.6 of the project report.

Pipeline:
  1. Query Neo4j for all task nodes with connected data objects.
  2. Select relevant threat agents based on deployment context (§5.5.1).
  3. For each task, detect risky behaviours (Table 5.3, three-layer model).
  4. Enumerate agent × behaviour × task threat triples.
  5. Compute OWASP risk scores (delegated to ``risk_scoring``).
  6. Sort by descending score and return.

Public API
──────────
``THREAT_AGENTS``     – dict of all five archetypal agents (Table 5.2).
``select_agents(context)``   – filter agents for a deployment context.
``build_tasks_with_annotations(session)`` – Cypher query → enriched task list.
``detect_behaviours(task)``  – three-layer behaviour detection.
``generate_threat_model(session, context)`` – full threat model list.

CLI
───
    python threat_modelling.py
    Prompts for deployment context; prints a CLI summary.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

from bpmn_security.parsers.annotation_parser import enrich_data_object, enrich_task, parse_annotation
from bpmn_security.catalogue.enisa_catalogue import get_enisa_threats
from bpmn_security.analysis.risk_scoring import compute_risk

# ---------------------------------------------------------------------------
# Threat Agent Catalogue (Table 5.2)
# ---------------------------------------------------------------------------

THREAT_AGENTS: dict[str, dict[str, Any]] = {
    "Insider Employee": {
        "name":       "Insider Employee",
        "access":     "Internal",
        "skill":      "Medium",
        "motivation": "Opportunistic",
        "resources":  "Low",
        "severity":   2,
    },
    "Malicious Admin": {
        "name":       "Malicious Admin",
        "access":     "Internal",
        "skill":      "High",
        "motivation": "Malicious",
        "resources":  "Medium",
        "severity":   4,
    },
    "Script Kiddie": {
        "name":       "Script Kiddie",
        "access":     "External",
        "skill":      "Low",
        "motivation": "Curiosity",
        "resources":  "Low",
        "severity":   1,
    },
    "Cybercriminal": {
        "name":       "Cybercriminal",
        "access":     "External",
        "skill":      "High",
        "motivation": "Financial",
        "resources":  "Medium",
        "severity":   3,
    },
    "Nation State": {
        "name":       "Nation State",
        "access":     "External",
        "skill":      "Very High",
        "motivation": "Political",
        "resources":  "Very High",
        "severity":   5,
    },
}

# ---------------------------------------------------------------------------
# Agent selection (§5.5.1)
# ---------------------------------------------------------------------------

def select_agents(context: dict) -> list[dict]:
    """Filter the agent catalogue based on five binary deployment-context flags.

    Parameters
    ----------
    context : dict
        Expected boolean keys:
        ``internet_exposed``  – system is reachable from the public internet.
        ``personal_data``     – process handles personal data.
        ``internal_users``    – internal employees interact with the process.
        ``financial_data``    – process involves financial transactions or data.
        ``critical_infra``    – system is classified as critical infrastructure.

    Returns
    -------
    list[dict]
        Filtered list of agent dicts.
    """
    selected: list[dict] = []

    internet_exposed = context.get("internet_exposed", True)
    personal_data    = context.get("personal_data", True)
    internal_users   = context.get("internal_users", True)
    financial_data   = context.get("financial_data", True)
    critical_infra   = context.get("critical_infra", False)

    for agent in THREAT_AGENTS.values():
        access = agent["access"]

        # External agents only relevant when internet-exposed
        if access == "External" and not internet_exposed:
            continue

        # Internal agents only relevant when there are internal users
        if access == "Internal" and not internal_users:
            continue

        # Financially motivated agents excluded when no financial data
        if agent["motivation"] == "Financial" and not financial_data:
            continue

        # For critical infrastructure, only high-skill, well-resourced agents
        if critical_infra and agent["skill"] not in ("High", "Very High"):
            continue

        selected.append(agent)

    # Always include at least one agent as a fallback
    if not selected:
        selected = [THREAT_AGENTS["Insider Employee"]]

    return selected


# ---------------------------------------------------------------------------
# Neo4j query — build_tasks_with_annotations (§5.6.1)
# ---------------------------------------------------------------------------

def build_tasks_with_annotations(session) -> list[dict]:
    """Query Neo4j for all task nodes with per-object connected data.

    Each returned task dict includes:
    - Standard task node properties (id, name, type, subtype, annotation, …).
    - ``connected_data``: list of per-object dicts, each enriched by
      ``annotation_parser.enrich_data_object()``.
    - ``operations``: set of CRUD operation types the task performs.
    - Enrichment keys from ``annotation_parser.enrich_task()``.

    Returns
    -------
    list[dict]
        One dict per task node.
    """
    query = """
    MATCH (t:Task)
    OPTIONAL MATCH (t)-[r:READ|CREATE|UPDATE|DELETE]->(d:DataObject)
    OPTIONAL MATCH (t)-[:BELONGS_TO*]->(tp:Process)
    WITH t, r, d, collect(DISTINCT tp.id) AS task_procs
    RETURN
        t.id                AS task_id,
        t.name              AS name,
        t.type              AS type,
        t.subtype           AS subtype,
        t.annotation        AS annotation,
        t.is_data_centric   AS is_data_centric,
        t.is_persistent     AS is_persistent,
        collect(DISTINCT {
            id:            d.id,
            name:          d.name,
            annotation:    d.annotation,
            is_persistent: d.is_persistent,
            operation:     type(r)
        }) AS connected_data_raw,
        EXISTS {
            MATCH (t)-[:MESSAGE_FLOW]-(other)
            OPTIONAL MATCH (other)-[:BELONGS_TO*]->(op:Process)
            WHERE NOT op.id IN task_procs
        } AS has_cross_pool_flow
    """
    result = session.run(query)

    tasks: list[dict] = []
    for record in result:
        task: dict = {
            "id":             record["task_id"],
            "name":           record["name"] or "",
            "type":           record["type"] or "Task",
            "subtype":        record["subtype"] or "Task",
            "annotation":     record["annotation"] or "",
            "is_data_centric": record["is_data_centric"] or False,
            "is_persistent":  record["is_persistent"] or False,
            "has_cross_pool_flow": bool(record.get("has_cross_pool_flow", False)),
        }

        # Enrich task with audit level
        enrich_task(task)

        # Enrich each connected data object
        raw_data: list[dict] = []
        operations: set[str] = set()
        for obj_raw in (record["connected_data_raw"] or []):
            if obj_raw.get("id") is None:
                continue
            obj = dict(obj_raw)
            enrich_data_object(obj)
            raw_data.append(obj)
            if obj.get("operation"):
                operations.add(obj["operation"])

        task["connected_data"] = raw_data
        task["operations"]     = operations
        tasks.append(task)

    return tasks


# ---------------------------------------------------------------------------
# Behaviour detection — three layers (Table 5.3)
# ---------------------------------------------------------------------------

def detect_behaviours(task: dict) -> list[dict]:
    """Detect risky behaviours for a single task using a three-layer model.

    Layer 1 — Operation-based detection.
    Layer 2 — Annotation-based detection.
    Layer 3 — ENISA catalogue lookup.

    Returns
    -------
    list[dict]
        Each dict has ``threat``, ``behaviour``, ``impact``, ``mitigation``.
    """
    behaviours: list[dict] = []
    seen_threats: set[str] = set()
    subtype    = task.get("subtype", "Task")
    operations = task.get("operations", set())
    ann_dict   = parse_annotation(task.get("annotation", ""))
    has_personal = any(
        obj.get("_is_personal", False) for obj in task.get("connected_data", [])
    )

    def _add(threat: str, behaviour: str, impact: float, mitigation: str = "") -> None:
        if threat not in seen_threats:
            seen_threats.add(threat)
            behaviours.append({
                "threat":     threat,
                "behaviour":  behaviour,
                "impact":     impact,
                "mitigation": mitigation,
            })

    # -- Layer 1: Operation-based ----------------------------------------
    cross_pool = bool(task.get("has_cross_pool_flow", False))

    if "READ" in operations and (has_personal or cross_pool):
        _add(
            "Loss of Confidentiality of Personal Data",
            "Task reads personal data that may be exposed to unauthorised parties "
            "via cross-pool flows or insufficient access controls.",
            7.0,
            "Apply field-level encryption and role-based access control; audit all "
            "cross-pool data reads."
        )

    if operations & {"CREATE", "UPDATE"}:
        _add(
            "Integrity Violation Risk",
            "Task creates or modifies data, opening the possibility of unauthorised "
            "alteration or injection of incorrect records.",
            6.0,
            "Enforce input validation, schema constraints, and four-eyes approval "
            "for sensitive data writes."
        )

    if "DELETE" in operations:
        _add(
            "Availability Risk",
            "Task deletes data; premature or unauthorised deletion reduces process "
            "data availability.",
            5.0,
            "Implement soft-delete with retention policies and require dual-approval "
            "before permanent record removal."
        )

    if subtype == "ServiceTask":
        _add(
            "Service Exploitation Risk",
            "Automated service task is a target for service exploitation, injection, "
            "or abuse of service interfaces.",
            6.0,
            "Apply API gateway policies, rate limiting, input sanitisation, and "
            "regular SAST/DAST scanning."
        )

    if subtype == "UserTask":
        _add(
            "Human Error Risk",
            "Manual user task is prone to erroneous data entry, skipped steps, or "
            "process deviations.",
            3.0,
            "Provide UI validation, mandatory field checks, and user training; "
            "implement audit logging for all user actions."
        )

    # -- Layer 2: Annotation-based ----------------------------------------
    comm_type = str(ann_dict.get("Communication Type", "")).strip()
    inter_type = str(ann_dict.get("Interaction Type", "")).strip()

    if subtype in ("SendTask", "ReceiveTask") and comm_type.lower() in ("mail", "post-office"):
        _add(
            "Loss of integrity via unencrypted channel",
            f"Data sent/received over {comm_type} without end-to-end encryption is "
            f"vulnerable to interception and modification.",
            6.0,
            "Enforce S/MIME or PGP for email; use tamper-evident packaging for "
            "physical mail."
        )

    if subtype == "ReceiveTask" and comm_type.lower() == "mail":
        _add(
            "Social Engineering",
            "Attacker sends a crafted email impersonating a trusted party to manipulate "
            "the recipient.",
            5.0,
            "Deploy anti-phishing controls (DMARC, DKIM, SPF) and provide regular "
            "phishing awareness training."
        )

    if subtype == "UserTask" and inter_type.lower() == "online":
        _add(
            "Identity theft via online interface",
            "Attacker exploits the online user interface to steal credentials or "
            "impersonate the legitimate user.",
            7.0,
            "Enforce MFA; apply HTTPS with HSTS and implement session timeout and "
            "account lockout policies."
        )

    if subtype == "UserTask" and inter_type.lower() == "offline":
        _add(
            "Insecure offline interaction",
            "Data exchanged through offline channels bypasses digital access controls.",
            5.0,
            "Apply DLP controls on removable media; require dual-signature for "
            "offline data handling procedures."
        )

    # -- Layer 3: ENISA catalogue ----------------------------------------
    catalogue_threats = get_enisa_threats(subtype, ann_dict, has_personal)
    for ct in catalogue_threats:
        _add(
            ct["threat"],
            ct["behaviour"],
            float(ct.get("impact", 3.0)),
            ct.get("mitigation", ""),
        )

    return behaviours


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def generate_threat_model(session, context: dict) -> list[dict]:
    """Generate the full threat model for a BPMN process graph.

    Parameters
    ----------
    session:
        Open Neo4j driver session.
    context:
        Deployment context dict (see ``select_agents()`` for keys).

    Returns
    -------
    list[dict]
        Threat entries sorted by descending ``score``.  Each entry includes:
        agent, task, threat, behaviour, mitigation, and all OWASP scoring keys.
    """
    tasks      = build_tasks_with_annotations(session)
    agents     = select_agents(context)

    # Collect all data objects across the process for TIM denominator
    all_data_objects: list[dict] = []
    seen_obj_ids: set[str] = set()
    for task in tasks:
        for obj in task.get("connected_data", []):
            if obj.get("id") and obj["id"] not in seen_obj_ids:
                seen_obj_ids.add(obj["id"])
                all_data_objects.append(obj)

    threat_model: list[dict] = []

    for task in tasks:
        behaviours = detect_behaviours(task)

        for behaviour in behaviours:
            for agent in agents:
                risk = compute_risk(agent, behaviour, task, all_data_objects)

                threat_model.append({
                    # Agent info
                    "agent_name":      agent["name"],
                    "agent_severity":  agent["severity"],
                    "agent_access":    agent.get("access", ""),
                    # Task info
                    "task_id":         task.get("id", ""),
                    "task_name":       task.get("name", ""),
                    "task_subtype":    task.get("subtype", "Task"),
                    "task_annotation": task.get("annotation", ""),
                    # Threat info
                    "threat":          behaviour["threat"],
                    "behaviour":       behaviour["behaviour"],
                    "impact":          behaviour.get("impact", 3.0),
                    "mitigation":      behaviour.get("mitigation", ""),
                    # OWASP scoring
                    **risk,
                })

    # Sort by descending score
    threat_model.sort(key=lambda e: e["score"], reverse=True)
    return threat_model


# ---------------------------------------------------------------------------
# Risk score write-back to Neo4j (§7.2.3)
# ---------------------------------------------------------------------------

def write_risk_scores_to_graph(session, threat_model: list[dict]) -> int:
    """Aggregate threat scores per task and write them back to Neo4j.

    For each task, the **maximum** composite risk score, its level, the
    worst-case LoC/LoI/LoA values, the LoAc, the top threat name, the
    top agent name, and the total threat count are persisted as properties
    on the ``Task`` node. This enables downstream risk-aware Cypher queries
    such as ``MATCH (t:Task) WHERE t.risk_level = 'High' RETURN t``.

    Parameters
    ----------
    session:
        Open Neo4j driver session.
    threat_model:
        The list returned by ``generate_threat_model()``.

    Returns
    -------
    int
        Number of Task nodes updated.
    """
    # 1. Aggregate by task_id — keep worst-case values
    task_summaries: dict[str, dict] = {}
    for entry in threat_model:
        tid = entry.get("task_id", "")
        if not tid:
            continue
        if tid not in task_summaries:
            task_summaries[tid] = {
                "task_id":      tid,
                "risk_score":   entry["score"],
                "risk_level":   entry["level"],
                "loc":          entry.get("loc", 1.0),
                "loi":          entry.get("loi", 1.0),
                "loa":          entry.get("loa", 1.0),
                "loac":         entry.get("loac", 1.0),
                "top_threat":   entry["threat"],
                "top_agent":    entry["agent_name"],
                "threat_count": 1,
            }
        else:
            ts = task_summaries[tid]
            ts["threat_count"] += 1
            if entry["score"] > ts["risk_score"]:
                ts["risk_score"] = entry["score"]
                ts["risk_level"] = entry["level"]
                ts["top_threat"] = entry["threat"]
                ts["top_agent"]  = entry["agent_name"]
            ts["loc"]  = max(ts["loc"],  entry.get("loc", 1.0))
            ts["loi"]  = max(ts["loi"],  entry.get("loi", 1.0))
            ts["loa"]  = max(ts["loa"],  entry.get("loa", 1.0))

    if not task_summaries:
        return 0

    # 2. Batch write via UNWIND
    cypher = """
    UNWIND $batch AS item
    MATCH (t:Task {id: item.task_id})
    SET t.risk_score   = item.risk_score,
        t.risk_level   = item.risk_level,
        t.loc          = item.loc,
        t.loi          = item.loi,
        t.loa          = item.loa,
        t.loac         = item.loac,
        t.top_threat   = item.top_threat,
        t.top_agent    = item.top_agent,
        t.threat_count = item.threat_count
    """
    batch = list(task_summaries.values())
    session.execute_write(lambda tx: tx.run(cypher, batch=batch))
    return len(batch)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _prompt_context() -> dict:
    """Interactive prompt for the five deployment context flags."""
    def _yn(prompt: str) -> bool:
        while True:
            ans = input(f"{prompt} [y/n]: ").strip().lower()
            if ans in ("y", "yes"):
                return True
            if ans in ("n", "no"):
                return False

    print("\n── Deployment Context ─────────────────────────────────")
    return {
        "internet_exposed": _yn("Is the system internet-exposed?"),
        "personal_data":    _yn("Does the process handle personal data?"),
        "internal_users":   _yn("Are internal employees involved?"),
        "financial_data":   _yn("Does the process involve financial data?"),
        "critical_infra":   _yn("Is this critical infrastructure?"),
    }


def _print_threats(threats: list[dict]) -> None:
    print(f"\n── Threat Model ({len(threats)} entries) ─────────────────────────────")
    for i, t in enumerate(threats[:20], 1):
        print(
            f"[{i:2d}] [{t['level']:6s}] score={t['score']:.2f}  "
            f"agent={t['agent_name']:<18}  task={t['task_name']:<30}  "
            f"threat={t['threat']}"
        )
        if t.get("mitigation"):
            print(f"       → {t['mitigation'][:100]}")
    if len(threats) > 20:
        print(f"     … and {len(threats)-20} more.")


if __name__ == "__main__":
    uri      = os.environ.get("NEO4J_URI",      "bolt://localhost:7687")
    user     = os.environ.get("NEO4J_USER",     "neo4j")
    password = os.environ.get("NEO4J_PASSWORD", "")
    if not password:
        sys.exit("ERROR: NEO4J_PASSWORD environment variable is not set.")

    from neo4j import GraphDatabase  # type: ignore
    driver = GraphDatabase.driver(uri, auth=(user, password))

    context = _prompt_context()

    try:
        with driver.session() as session:
            threats = generate_threat_model(session, context)
    finally:
        driver.close()

    _print_threats(threats)
