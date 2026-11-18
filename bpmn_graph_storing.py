"""
bpmn_graph_storing.py
─────────────────────
Write a parsed BPMN model (output of ``bpmn_reader.bpmn_extract``) into a
Neo4j graph database.

Neo4j connection is configured via environment variables:

    NEO4J_URI      (default: bolt://localhost:7687)
    NEO4J_USER     (default: neo4j)
    NEO4J_PASSWORD (required — raises SystemExit if absent)

Public API
──────────
``store_bpmn(processes, message_flows, data_associations)``
    Clear the graph and write the full BPMN model.

CLI
───
    python bpmn_graph_storing.py <path-to-bpmn-file-or-directory>
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Neo4j driver import (deferred so unit tests can mock without the driver)
# ---------------------------------------------------------------------------

def _get_driver(uri: str, user: str, password: str):
    from neo4j import GraphDatabase  # type: ignore
    return GraphDatabase.driver(uri, auth=(user, password))


# ---------------------------------------------------------------------------
# Credential resolution
# ---------------------------------------------------------------------------

def _resolve_credentials() -> tuple[str, str, str]:
    """Return (uri, user, password) from environment variables.

    Raises SystemExit if NEO4J_PASSWORD is not set.
    """
    uri      = os.environ.get("NEO4J_URI",      "bolt://localhost:7687")
    user     = os.environ.get("NEO4J_USER",     "neo4j")
    password = os.environ.get("NEO4J_PASSWORD", "")
    if not password:
        sys.exit(
            "ERROR: NEO4J_PASSWORD environment variable is not set.\n"
            "Set it before running:\n"
            "    export NEO4J_PASSWORD=<your-password>"
        )
    return uri, user, password


# ---------------------------------------------------------------------------
# Graph clear
# ---------------------------------------------------------------------------

def _delete_all(tx) -> None:
    tx.run("MATCH (n) DETACH DELETE n")


# ---------------------------------------------------------------------------
# Node / edge creation helpers
# ---------------------------------------------------------------------------

def _safe_props(props: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of *props* with only Neo4j-safe scalar values."""
    return {
        k: v for k, v in props.items()
        if isinstance(v, (str, int, float, bool)) and k not in ("elements", "lanes", "refs")
    }


def _create_node(tx, node_id: str, label: str, props: dict[str, Any]) -> None:
    safe = _safe_props(props)
    safe["id"] = node_id
    tx.run(
        f"MERGE (n:{label} {{id: $id}}) SET n += $props",
        id=node_id,
        props=safe,
    )


def _create_rel(tx, src_id: str, tgt_id: str, rel_type: str, props: dict | None = None) -> None:
    tx.run(
        f"MATCH (a {{id: $src}}), (b {{id: $tgt}}) "
        f"MERGE (a)-[r:{rel_type}]->(b)",
        src=src_id,
        tgt=tgt_id,
    )


# ---------------------------------------------------------------------------
# Algorithm 5 — Recursive Lane Creation
# ---------------------------------------------------------------------------

def _create_lane_recursive(tx, lane: dict, parent_id: str) -> None:
    lane_id = lane["id"]
    props   = _safe_props(lane)
    props["type"] = "Lane"
    _create_node(tx, lane_id, "Lane", props)

    # Recurse into nested child lanes
    for child_lane in lane.get("elements", []):
        if isinstance(child_lane, dict) and child_lane.get("type") == "Lane":
            _create_lane_recursive(tx, child_lane, lane_id)

    # BELONGS_TO edge: lane → parent lane or process
    _create_rel(tx, lane_id, parent_id, "BELONGS_TO")


# ---------------------------------------------------------------------------
# Algorithm 6 — Recursive Process Creation
# ---------------------------------------------------------------------------

# Relationship types for data associations
_OP_TO_REL: dict[str, str] = {
    "READ":   "READ",
    "CREATE": "CREATE",
    "UPDATE": "UPDATE",
    "DELETE": "DELETE",
}

# Node labels by element type
_TYPE_TO_LABEL: dict[str, str] = {
    "Task":                   "Task",
    "CallActivity":           "CallActivity",
    "StartEvent":             "Event",
    "EndEvent":               "Event",
    "ErrorEndEvent":          "Event",
    "IntermediateCatchEvent": "Event",
    "IntermediateThrowEvent": "Event",
    "BoundaryEvent":          "Event",
    "TerminateEvent":         "Event",
    "ExclusiveGateway":       "Gateway",
    "ParallelGateway":        "Gateway",
    "InclusiveGateway":       "Gateway",
    "EventBasedGateway":      "Gateway",
    "DataObject":             "DataObject",
    "Lane":                   "Lane",
    "Process":                "Process",
    "SubProcess":             "Process",
    "MessageFlow":            "MessageFlow",
}


def _create_process_recursive(
    tx,
    proc:     dict,
    parent_id: str | None,
    message_flows: list[dict],
    data_associations: list[dict],
) -> None:
    """Implement Algorithm 6 from the project report."""
    proc_id = proc["id"]

    # Create process node
    proc_props = _safe_props(proc)
    proc_props["type"] = proc.get("type", "Process")
    _create_node(tx, proc_id, "Process", proc_props)

    # Create lane hierarchy (Algorithm 5)
    for lane in proc.get("lanes", []):
        _create_lane_recursive(tx, lane, proc_id)

    # Build lane-membership index: element_id → lane_id
    lane_members: dict[str, str] = {}
    for lane in proc.get("lanes", []):
        for ref_id in lane.get("refs", []):
            lane_members[ref_id] = lane["id"]

    # Create element nodes (skip sequence flows and subprocesses — handled later)
    skip_types = {"sequenceFlow", "triggers", "SubProcess"}
    elements = proc.get("elements", [])

    for el in elements:
        el_type = el.get("type", "")
        if el_type in skip_types:
            continue
        label = _TYPE_TO_LABEL.get(el_type, "Element")
        el_id = el.get("id", "")
        if not el_id:
            continue
        _create_node(tx, el_id, label, el)

    # Create BELONGS_TO edges for all non-subprocess elements
    for el in elements:
        el_type = el.get("type", "")
        if el_type in skip_types:
            continue
        el_id = el.get("id", "")
        if not el_id:
            continue
        parent_lane = lane_members.get(el_id)
        if parent_lane:
            _create_rel(tx, el_id, parent_lane, "BELONGS_TO")
        else:
            _create_rel(tx, el_id, proc_id, "BELONGS_TO")

    # Create sequence flow and trigger edges
    for el in elements:
        el_type = el.get("type", "")
        if el_type not in {"sequenceFlow", "triggers"}:
            continue
        src = el.get("source", el.get("sourceRef", ""))
        tgt = el.get("target", el.get("targetRef", ""))
        if not src or not tgt:
            continue
        rel = "TRIGGERS" if el_type == "triggers" else "SEQUENCEFLOW"
        _create_rel(tx, src, tgt, rel)

    # Create message flow edges (globally scoped)
    for mf in message_flows:
        src = mf.get("sourceRef", "")
        tgt = mf.get("targetRef", "")
        if src and tgt:
            _create_rel(tx, src, tgt, "MESSAGE_FLOW")

    # Recurse into subprocesses
    for el in elements:
        if el.get("type") == "SubProcess":
            _create_process_recursive(tx, el, proc_id, message_flows, data_associations)

    # BELONGS_TO edge: subprocess → parent process
    if parent_id:
        _create_rel(tx, proc_id, parent_id, "BELONGS_TO")

    # ATTACHES_TO edges for boundary events
    for el in elements:
        if el.get("type") == "BoundaryEvent":
            attached_to = el.get("attachedToRef", "")
            if attached_to:
                _create_rel(tx, el["id"], attached_to, "ATTACHES_TO")

    # Data association edges (READ / CREATE / UPDATE / DELETE)
    proc_task_ids: set[str] = {
        el["id"] for el in elements
        if el.get("type") == "Task" and el.get("id")
    }
    for da in data_associations:
        if da["task_id"] in proc_task_ids:
            rel_type = _OP_TO_REL.get(da["operation"], da["operation"])
            _create_rel(tx, da["task_id"], da["data_object_id"], rel_type)


# ---------------------------------------------------------------------------
# Algorithm 7 — Call Activity Linking (deferred pass)
# ---------------------------------------------------------------------------

def _link_call_activities(tx, root: dict) -> None:
    """Recurse through process / subprocess / lane and create CALL_FLOW edges."""
    proc_id = root.get("id", "")
    for el in root.get("elements", []):
        if el.get("type") == "CallActivity":
            called = el.get("calledElement_processId") or el.get("calledElement", "")
            if called:
                _create_rel(tx, proc_id, called, "CALL_FLOW")
        elif el.get("type") in {"SubProcess", "Lane"}:
            _link_call_activities(tx, el)


# ---------------------------------------------------------------------------
# Public API — Algorithm 4: Main Driver
# ---------------------------------------------------------------------------

def store_bpmn(
    processes: list[dict],
    message_flows: list[dict],
    data_associations: list[dict],
    *,
    uri: str | None = None,
    user: str | None = None,
    password: str | None = None,
) -> None:
    """Clear the Neo4j graph and write the full BPMN model.

    Parameters
    ----------
    processes, message_flows, data_associations:
        Output of ``bpmn_reader.bpmn_extract()`` or
        ``bpmn_reader.multi_file_extract()``.
    uri, user, password:
        Override the environment-variable defaults (useful for testing).
    """
    if uri is None or user is None or password is None:
        _uri, _user, _password = _resolve_credentials()
        uri      = uri      or _uri
        user     = user     or _user
        password = password or _password

    driver = _get_driver(uri, user, password)

    try:
        with driver.session() as session:
            # Clear the graph
            session.execute_write(_delete_all)

            # Create all process trees
            for proc in processes:
                session.execute_write(
                    _create_process_recursive,
                    proc,
                    None,
                    message_flows,
                    data_associations,
                )

            # Deferred CALL_FLOW linking
            for proc in processes:
                session.execute_write(_link_call_activities, proc)
    finally:
        driver.close()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    from bpmn_reader import bpmn_extract, multi_file_extract

    if len(sys.argv) < 2:
        print("Usage: python bpmn_graph_storing.py <bpmn-file-or-directory>",
              file=sys.stderr)
        sys.exit(1)

    input_path = Path(sys.argv[1])
    if input_path.is_dir():
        procs, mfs, das = multi_file_extract(input_path)
    else:
        procs, mfs, das = bpmn_extract(input_path)

    print(f"Parsed {len(procs)} process(es), "
          f"{len(mfs)} message flow(s), "
          f"{len(das)} data association(s).")
    print("Storing to Neo4j…")
    store_bpmn(procs, mfs, das)
    print("Done.")
