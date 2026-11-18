"""
bpmn_reader.py
──────────────
Parse a BPMN 2.0 XML file (or a directory of .bpmn files) and return a
structured Python representation ready for graph storage.

Public API
──────────
``bpmn_extract(filepath)``
    Parse one BPMN file → ``(processes, message_flows, data_associations)``.

``multi_file_extract(dir_path)``
    Merge results from every ``.bpmn`` file in a directory.

Data shapes
───────────
*processes*
    List of process dicts, each with keys:
    ``id``, ``name``, ``type`` (= "Process"), flat XML attributes,
    ``elements`` (list of element dicts),
    ``lanes``    (list of lane dicts).

*message_flows*
    List of edge dicts with ``id``, ``type`` (= "MessageFlow"),
    ``sourceRef``, ``targetRef``, ``isEdge`` (= True).

*data_associations*
    List of dicts with ``task_id``, ``data_object_id``,
    ``operation`` (READ | CREATE | UPDATE | DELETE).

Each element dict (task, event, gateway, etc.) has at minimum:
    ``id``, ``type``, ``name`` (may be empty), ``annotation`` (str),
    ``is_data_centric`` (bool), ``is_persistent`` (bool).

Edge dicts (sequence flows, triggers) additionally carry:
    ``source``, ``target``, ``isEdge`` (= True).

Subprocess dicts carry a nested ``elements`` key (list) from recursion.
Lane dicts carry ``refs`` (list of flowNodeRef IDs) and ``elements``
(child lanes from recursion).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from lxml import etree

# ---------------------------------------------------------------------------
# Namespace map
# ---------------------------------------------------------------------------

_NS = {
    "bpmn":     "http://www.omg.org/spec/BPMN/20100524/MODEL",
    "activiti": "http://activiti.org/bpmn",
}

# Convenience: strip the BPMN namespace prefix from a tag string.
_BPMN_NS = "{http://www.omg.org/spec/BPMN/20100524/MODEL}"

# ---------------------------------------------------------------------------
# Persistent data-object names (§4.3.1)
# ---------------------------------------------------------------------------

_PERSISTENT_NAMES: frozenset[str] = frozenset({
    "Profile",
    "Certificate",
    "ApplicationRequest",
    "PaymentRecord",
    "AuditLog",
    "StoredDocument",
})

# Task subtypes that are "data-centric" (§4.3.1)
_DATA_CENTRIC_SUBTYPES: frozenset[str] = frozenset({
    "UserTask", "ServiceTask", "ScriptTask",
})

# ---------------------------------------------------------------------------
# Property extraction helpers
# ---------------------------------------------------------------------------

def _local(tag: str) -> str:
    """Strip namespace URI from an lxml tag string."""
    if tag.startswith("{"):
        return tag.split("}", 1)[1]
    return tag


def _extract_all_props(
    element: etree._Element,
    type_label: str,
    subtype: str | None = None,
) -> dict[str, Any]:
    """Convert an XML element into a flat property dict for Neo4j storage.

    Implements the universal property extractor described in §4.3.1.

    Steps:
    1. Copy all XML attributes of the element.
    2. Promote attributes and text content of all descendants (including
       ``extensionElements`` children) using a ``tag_attribute`` naming
       convention.
    3. Add ``type``, ``subtype``, ``is_data_centric``, ``is_persistent`` flags.
    """
    props: dict[str, Any] = {}

    # Step 1 — XML attributes of the element itself.
    props.update(element.attrib)

    # Step 2 — descendants (extension properties, Camunda/Activiti headers, etc.)
    # Guard: lxml may yield PIs/comments whose .tag is a callable, not a string.
    for desc in element.iter():
        if desc is element:
            continue
        if not isinstance(desc.tag, str):
            continue
        local_tag = _local(desc.tag)
        # Promote attributes
        for attr_name, attr_val in desc.attrib.items():
            key = f"{local_tag}_{attr_name}"
            props[key] = attr_val
        # Promote text content
        if desc.text and desc.text.strip():
            key = f"{local_tag}_text"
            existing = props.get(key)
            if existing:
                props[key] = f"{existing}; {desc.text.strip()}"
            else:
                props[key] = desc.text.strip()

    # Step 3 — type labels and flags.
    props["type"] = type_label
    if subtype:
        props["subtype"] = subtype

    name = props.get("name", "")
    props["is_data_centric"] = (subtype or type_label) in _DATA_CENTRIC_SUBTYPES
    props["is_persistent"]   = name in _PERSISTENT_NAMES

    # Ensure id is always present
    props.setdefault("id", "")
    props.setdefault("name", "")

    return props


def _extract_flat_props(element: etree._Element) -> dict[str, Any]:
    """Return a reduced property dict containing only primitive values.

    Used for Process and Lane nodes (§4.3.1).
    """
    full = _extract_all_props(element, "")
    return {
        k: v for k, v in full.items()
        if isinstance(v, (str, int, float, bool))
    }


# ---------------------------------------------------------------------------
# Annotation attachment helpers
# ---------------------------------------------------------------------------

def _build_annotation_map(root: etree._Element) -> dict[str, str]:
    """Map textAnnotation id → text content from the entire document."""
    ann_map: dict[str, str] = {}
    for ann in root.iter(f"{_BPMN_NS}textAnnotation"):
        ann_id = ann.get("id", "")
        text_el = ann.find(f"{_BPMN_NS}text")
        if text_el is not None and text_el.text:
            ann_map[ann_id] = text_el.text.strip()
        else:
            # Also try the Activiti property path
            for prop in ann.iter(f"{{http://activiti.org/bpmn}}property"):
                if prop.get("name") == "annotation":
                    ann_map[ann_id] = prop.get("value", "")
                    break
    return ann_map


def _attach_annotations(
    elements_by_id: dict[str, dict],
    root: etree._Element,
    ann_map: dict[str, str],
) -> None:
    """Walk all ``association`` elements and attach annotation text to their
    source element (task or dataObjectReference).

    Implements §4.3.5 — Algorithm 1 steps 12–21.
    """
    for assoc in root.iter(f"{_BPMN_NS}association"):
        src_id = assoc.get("sourceRef", "")
        tgt_id = assoc.get("targetRef", "")
        if tgt_id in ann_map:
            text = ann_map[tgt_id]
            node = elements_by_id.get(src_id)
            if node is not None:
                existing = node.get("annotation", "")
                if existing:
                    node["annotation"] = f"{existing}; {text}"
                else:
                    node["annotation"] = text


# ---------------------------------------------------------------------------
# Data object reference resolution
# ---------------------------------------------------------------------------

def _build_data_ref_maps(
    root: etree._Element,
) -> tuple[dict[str, str], dict[str, dict]]:
    """Build lookup maps for dataObjectReference resolution (§4.3.2).

    Returns
    -------
    data_ref_to_obj : dict[ref_id → obj_id]
    data_ref_info   : dict[obj_id → props_dict]
    """
    data_ref_to_obj: dict[str, str] = {}
    data_ref_info:   dict[str, dict] = {}

    for ref_el in root.iter(f"{_BPMN_NS}dataObjectReference"):
        ref_id = ref_el.get("id", "")
        obj_id = ref_el.get("dataObjectRef", ref_id)
        data_ref_to_obj[ref_id] = obj_id

        # Extract annotation from child extensionElements / property
        annotation = ""
        for prop in ref_el.iter(f"{{http://activiti.org/bpmn}}property"):
            if prop.get("name") == "annotation":
                annotation = prop.get("value", "")
                break
        # Also look for property_text promoted by _extract_all_props
        data_ref_info[ref_id] = {
            "ref_id":     ref_id,
            "obj_id":     obj_id,
            "name":       ref_el.get("name", ""),
            "annotation": annotation,
        }

    return data_ref_to_obj, data_ref_info


# ---------------------------------------------------------------------------
# Recursive process parser (Algorithm 2)
# ---------------------------------------------------------------------------

# Task tag local-names → (type_label, subtype)
_TASK_TYPES: dict[str, tuple[str, str]] = {
    "task":        ("Task",        "Task"),
    "userTask":    ("Task",        "UserTask"),
    "sendTask":    ("Task",        "SendTask"),
    "receiveTask": ("Task",        "ReceiveTask"),
    "serviceTask": ("Task",        "ServiceTask"),
    "scriptTask":  ("Task",        "ScriptTask"),
    "callActivity": ("CallActivity", "CallActivity"),
}

_EVENT_TYPES: set[str] = {
    "startEvent", "endEvent", "errorEndEvent",
    "intermediateCatchEvent", "intermediateThrowEvent",
    "boundaryEvent", "terminateEventDefinition",
}

_GATEWAY_TYPES: set[str] = {
    "exclusiveGateway", "parallelGateway",
    "inclusiveGateway", "eventBasedGateway",
}


def _recursive_parser(
    node: etree._Element,
    data_ref_to_obj: dict[str, str],
    data_ref_info: dict[str, dict],
    task_map: dict[str, dict],
) -> list[dict]:
    """Parse all processes reachable under *node*, recursively.

    Implements Algorithm 2 of the project report.

    Returns a list of process dicts (may be a single subprocess dict).
    """
    processes: list[dict] = []

    for proc_el in node.findall(f"{_BPMN_NS}process"):
        elements: list[dict] = []
        lanes:    list[dict] = []

        # ── Tasks (all variants) ────────────────────────────────────────────
        for tag_local, (type_label, subtype) in _TASK_TYPES.items():
            for el in proc_el.findall(f"{_BPMN_NS}{tag_local}"):
                props = _extract_all_props(el, type_label, subtype)
                task_map[props["id"]] = props
                elements.append(props)

        # ── Events ──────────────────────────────────────────────────────────
        for tag_local in _EVENT_TYPES:
            for el in proc_el.findall(f"{_BPMN_NS}{tag_local}"):
                local_tag = _local(el.tag)
                type_label = _event_type_label(local_tag)
                props = _extract_all_props(el, type_label)
                elements.append(props)

        # ── Gateways ────────────────────────────────────────────────────────
        for tag_local in _GATEWAY_TYPES:
            for el in proc_el.findall(f"{_BPMN_NS}{tag_local}"):
                local_tag = _local(el.tag)
                props = _extract_all_props(el, _gateway_type_label(local_tag))
                elements.append(props)

        # Collect intermediate catch event IDs for trigger reclassification
        int_catch_ids: set[str] = {
            p["id"] for p in elements
            if p.get("type") == "IntermediateCatchEvent"
        }

        # ── Sequence flows (with trigger reclassification §4.3.4) ───────────
        for sf in proc_el.findall(f"{_BPMN_NS}sequenceFlow"):
            props = _extract_all_props(sf, "sequenceFlow")
            props["source"]  = sf.get("sourceRef", "")
            props["target"]  = sf.get("targetRef", "")
            props["isEdge"]  = True
            if props["source"] in int_catch_ids:
                props["type"] = "triggers"
            elements.append(props)

        # ── SubProcesses (recursive) ─────────────────────────────────────────
        for sp_el in proc_el.findall(f"{_BPMN_NS}subProcess"):
            sp_props = _extract_all_props(sp_el, "SubProcess")
            # Recurse: treat the subprocess element as a mini-process container
            sp_props["elements"] = _recursive_parser_sub(
                sp_el, data_ref_to_obj, data_ref_info, task_map
            )
            task_map[sp_props["id"]] = sp_props
            elements.append(sp_props)

        # ── Lanes ────────────────────────────────────────────────────────────
        for lane_set in proc_el.findall(f"{_BPMN_NS}laneSet"):
            for lane_el in lane_set.findall(f"{_BPMN_NS}lane"):
                lane_props = _extract_all_props(lane_el, "Lane")
                lane_props["refs"] = [
                    ref.text.strip()
                    for ref in lane_el.findall(f"{_BPMN_NS}flowNodeRef")
                    if ref.text
                ]
                lane_props["elements"] = _recursive_parser_lane(
                    lane_el, data_ref_to_obj, data_ref_info, task_map
                )
                lanes.append(lane_props)

        # ── Data objects ──────────────────────────────────────────────────────
        for do_el in proc_el.findall(f"{_BPMN_NS}dataObject"):
            obj_props = _extract_all_props(do_el, "DataObject")
            # Merge reference metadata (annotation) from data_ref_info
            for ref_id, info in data_ref_info.items():
                if info["obj_id"] == obj_props["id"]:
                    if info.get("annotation"):
                        obj_props["annotation"] = info["annotation"]
                    obj_props.setdefault("name", info.get("name", ""))
                    # Re-evaluate is_persistent with the resolved name
                    obj_props["is_persistent"] = obj_props["name"] in _PERSISTENT_NAMES
                    break
            elements.append(obj_props)

        proc_props = _extract_flat_props(proc_el)
        proc_props["type"] = "Process"
        proc_props.setdefault("id", proc_el.get("id", ""))
        proc_props.setdefault("name", proc_el.get("name", ""))

        processes.append({
            **proc_props,
            "elements": elements,
            "lanes":    lanes,
        })

    return processes


def _recursive_parser_sub(
    sp_el: etree._Element,
    data_ref_to_obj: dict[str, str],
    data_ref_info:   dict[str, dict],
    task_map:        dict[str, dict],
) -> list[dict]:
    """Recursively parse the element list inside a SubProcess."""
    elements: list[dict] = []
    for tag_local, (type_label, subtype) in _TASK_TYPES.items():
        for el in sp_el.findall(f"{_BPMN_NS}{tag_local}"):
            props = _extract_all_props(el, type_label, subtype)
            task_map[props["id"]] = props
            elements.append(props)
    for tag_local in _EVENT_TYPES:
        for el in sp_el.findall(f"{_BPMN_NS}{tag_local}"):
            props = _extract_all_props(el, _event_type_label(_local(el.tag)))
            elements.append(props)
    for sf in sp_el.findall(f"{_BPMN_NS}sequenceFlow"):
        props = _extract_all_props(sf, "sequenceFlow")
        props["source"] = sf.get("sourceRef", "")
        props["target"] = sf.get("targetRef", "")
        props["isEdge"] = True
        elements.append(props)
    return elements


def _recursive_parser_lane(
    lane_el: etree._Element,
    data_ref_to_obj: dict[str, str],
    data_ref_info:   dict[str, dict],
    task_map:        dict[str, dict],
) -> list[dict]:
    """Recursively parse nested child lanes."""
    child_lanes: list[dict] = []
    for child in lane_el.findall(f"{_BPMN_NS}lane"):
        props = _extract_all_props(child, "Lane")
        props["refs"] = [
            ref.text.strip()
            for ref in child.findall(f"{_BPMN_NS}flowNodeRef")
            if ref.text
        ]
        props["elements"] = _recursive_parser_lane(
            child, data_ref_to_obj, data_ref_info, task_map
        )
        child_lanes.append(props)
    return child_lanes


# ---------------------------------------------------------------------------
# CRUD enrichment (Algorithm 1, steps 10–11)
# ---------------------------------------------------------------------------

def _extract_raw_associations(
    root: etree._Element,
    task_map: dict[str, dict],
    data_ref_to_obj: dict[str, str],
) -> list[dict]:
    """Extract raw data associations from all task elements.

    Returns a list of dicts: ``{task_id, data_object_id, operation}``
    where operation is initially ``READ`` or ``WRITES``.
    """
    raw: list[dict] = []
    task_tag_locals = set(_TASK_TYPES.keys())

    for tag_local in task_tag_locals:
        for task_el in root.iter(f"{_BPMN_NS}{tag_local}"):
            task_id = task_el.get("id", "")

            # Input associations → READ
            for assoc in task_el.findall(f"{_BPMN_NS}dataInputAssociation"):
                for src in assoc.findall(f"{_BPMN_NS}sourceRef"):
                    ref_id = src.text.strip() if src.text else ""
                    obj_id = data_ref_to_obj.get(ref_id, ref_id)
                    raw.append({"task_id": task_id, "data_object_id": obj_id, "operation": "READ"})

            # Output associations → WRITES (refined later)
            for assoc in task_el.findall(f"{_BPMN_NS}dataOutputAssociation"):
                for tgt in assoc.findall(f"{_BPMN_NS}targetRef"):
                    ref_id = tgt.text.strip() if tgt.text else ""
                    obj_id = data_ref_to_obj.get(ref_id, ref_id)
                    raw.append({"task_id": task_id, "data_object_id": obj_id, "operation": "WRITES"})

    return raw


def _enrich_crud(
    raw: list[dict],
    task_map: dict[str, dict],
) -> list[dict]:
    """Refine WRITES → CREATE / UPDATE / DELETE using §4.3.3 heuristics.

    First WRITES to an object_id → CREATE.
    Subsequent WRITES → UPDATE.
    Task name contains "delete" → DELETE (overrides READ/CREATE/UPDATE).
    This covers tasks that read an object *in order to delete it* — they use
    a dataInputAssociation but semantically perform a DELETE.
    """
    seen: set[str] = set()
    result: list[dict] = []

    for item in raw:
        op        = item["operation"]
        task_id   = item["task_id"]
        obj_id    = item["data_object_id"]
        task_name = (task_map.get(task_id, {}).get("name") or "").lower()

        if "delete" in task_name:
            op = "DELETE"
        elif op == "READ":
            pass  # keep as READ
        elif obj_id not in seen:
            seen.add(obj_id)
            op = "CREATE"
        else:
            op = "UPDATE"

        result.append({**item, "operation": op})

    return result


# ---------------------------------------------------------------------------
# Type-label helpers
# ---------------------------------------------------------------------------

def _event_type_label(local_tag: str) -> str:
    mapping = {
        "startEvent":               "StartEvent",
        "endEvent":                 "EndEvent",
        "errorEndEvent":            "ErrorEndEvent",
        "intermediateCatchEvent":   "IntermediateCatchEvent",
        "intermediateThrowEvent":   "IntermediateThrowEvent",
        "boundaryEvent":            "BoundaryEvent",
        "terminateEventDefinition": "TerminateEvent",
    }
    return mapping.get(local_tag, local_tag.capitalize())


def _gateway_type_label(local_tag: str) -> str:
    mapping = {
        "exclusiveGateway":   "ExclusiveGateway",
        "parallelGateway":    "ParallelGateway",
        "inclusiveGateway":   "InclusiveGateway",
        "eventBasedGateway":  "EventBasedGateway",
    }
    return mapping.get(local_tag, local_tag.capitalize())


# ---------------------------------------------------------------------------
# Message-flow extraction
# ---------------------------------------------------------------------------

def _extract_message_flows(root: etree._Element) -> list[dict]:
    """Extract message flows from the collaboration element."""
    flows: list[dict] = []
    for mf in root.iter(f"{_BPMN_NS}messageFlow"):
        props = _extract_all_props(mf, "MessageFlow")
        props["sourceRef"] = mf.get("sourceRef", "")
        props["targetRef"] = mf.get("targetRef", "")
        props["isEdge"]    = True
        flows.append(props)
    return flows


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------

def bpmn_extract(
    filepath: str | Path,
) -> tuple[list[dict], list[dict], list[dict]]:
    """Parse a single BPMN 2.0 XML file.

    Implements Algorithm 1 (BPMN Model Extraction) from the project report.

    Parameters
    ----------
    filepath:
        Path to a ``.bpmn`` or ``.xml`` file.

    Returns
    -------
    processes : list[dict]
    message_flows : list[dict]
    data_associations : list[dict]
    """
    tree = etree.parse(str(filepath))
    root = tree.getroot()

    # Build lookup maps before recursion (§4.3.2)
    data_ref_to_obj, data_ref_info = _build_data_ref_maps(root)

    # Build annotation map (§4.3.5)
    ann_map = _build_annotation_map(root)

    # Mutable task registry (for CRUD enrichment and annotation attachment)
    task_map: dict[str, dict] = {}

    # Recursive parse (Algorithm 2)
    processes = _recursive_parser(root, data_ref_to_obj, data_ref_info, task_map)

    # Message flows (collaboration level)
    message_flows = _extract_message_flows(root)

    # Raw data associations
    raw_da = _extract_raw_associations(root, task_map, data_ref_to_obj)

    # CRUD enrichment (Algorithm 1, steps 10–11)
    data_associations = _enrich_crud(raw_da, task_map)

    # Build element-by-id index for annotation attachment
    elements_by_id: dict[str, dict] = {**task_map}
    # Also index data-object references
    for ref_id, info in data_ref_info.items():
        elements_by_id[ref_id] = info

    # Attach annotations (Algorithm 1, steps 12–21)
    _attach_annotations(elements_by_id, root, ann_map)

    return processes, message_flows, data_associations


def multi_file_extract(
    dir_path: str | Path,
) -> tuple[list[dict], list[dict], list[dict]]:
    """Merge extraction results from all ``.bpmn`` files in a directory.

    Implements Algorithm 3 (Multi-File BPMN Extraction) from the project report.

    Parameters
    ----------
    dir_path:
        Path to a directory containing one or more ``.bpmn`` files.

    Returns
    -------
    processes : list[dict]
    message_flows : list[dict]
    data_associations : list[dict]
    """
    dir_path = Path(dir_path)
    all_processes:    list[dict] = []
    all_msg_flows:    list[dict] = []
    all_data_assocs:  list[dict] = []

    for bpmn_file in sorted(dir_path.glob("*.bpmn")):
        procs, mfs, das = bpmn_extract(bpmn_file)
        all_processes.extend(procs)
        all_msg_flows.extend(mfs)
        all_data_assocs.extend(das)

    return all_processes, all_msg_flows, all_data_assocs


# ---------------------------------------------------------------------------
# CLI smoke-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    path = sys.argv[1] if len(sys.argv) > 1 else "data/certificate_request.bpmn"
    p = Path(path)
    if p.is_dir():
        procs, mfs, das = multi_file_extract(p)
    else:
        procs, mfs, das = bpmn_extract(p)

    total_elements = sum(len(proc.get("elements", [])) for proc in procs)
    print(f"Processes:         {len(procs)}")
    print(f"Total elements:    {total_elements}")
    print(f"Message flows:     {len(mfs)}")
    print(f"Data associations: {len(das)}")
    for da in das:
        print(f"  {da['operation']:6}  task={da['task_id'][:30]}  obj={da['data_object_id'][:30]}")
