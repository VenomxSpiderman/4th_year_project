"""
annotation_parser.py
────────────────────
Parse and enrich the plain-text annotation strings attached to BPMN task and
data-object nodes.

Annotation strings have the form::

    Key=Value; Key=Value; ...

Values are type-coerced: integers → ``int``, floats → ``float``, everything
else → lowercase ``str``.

Public API
──────────
``parse_annotation(text)``
    Parse an annotation string into a typed dict.

``get_size_kb(ann_dict)``
    Combine ``Size`` and ``Order of Size`` into a single kilobyte float.

``enrich_data_object(node)``
    Attach ``_size_kb``, ``_is_personal``, ``_load`` to a node dict in-place.

``enrich_task(node)``
    Attach ``_audit_level`` (int 1–3) to a node dict in-place.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Unit multipliers: converts a size value to kilobytes.
_UNIT_TO_KB: dict[str, float] = {
    "b":  1.0 / 1024.0,
    "kb": 1.0,
    "mb": 1024.0,
    "gb": 1024.0 * 1024.0,
}

# Audit level strings → numeric level (higher = better auditing → lower LoAc).
_AUDIT_LEVEL_MAP: dict[str, int] = {
    "high":   3,
    "medium": 2,
    "low":    1,
    "none":   0,   # treated as worst case (no logging at all)
}

# ---------------------------------------------------------------------------
# Core parser
# ---------------------------------------------------------------------------

def parse_annotation(text: str | None) -> dict:
    """Parse an annotation string into a typed dictionary.

    Parameters
    ----------
    text:
        Semicolon-separated ``Key=Value`` string, or ``None`` / empty string.

    Returns
    -------
    dict
        Keys are stripped strings; values are ``int``, ``float``, or lowercase
        ``str`` after type coercion.

    Examples
    --------
    >>> parse_annotation("Size=10; Order of Size=KB; Personal=yes")
    {'Size': 10, 'Order of Size': 'kb', 'Personal': 'yes'}
    """
    if not text:
        return {}

    result: dict = {}
    for token in text.split(";"):
        token = token.strip()
        if not token:
            continue
        if "=" not in token:
            continue
        key, _, raw_value = token.partition("=")
        key = key.strip()
        raw_value = raw_value.strip()

        # Type coercion: try int, then float, then lowercase str.
        coerced: int | float | str
        try:
            coerced = int(raw_value)
        except ValueError:
            try:
                coerced = float(raw_value)
            except ValueError:
                coerced = raw_value.lower()

        result[key] = coerced

    return result


# ---------------------------------------------------------------------------
# Size helper
# ---------------------------------------------------------------------------

def get_size_kb(ann_dict: dict) -> float:
    """Return the data-object size in kilobytes.

    Combines ``Size`` (numeric) and ``Order of Size`` (unit string: B, KB, MB,
    GB) from *ann_dict*.  Missing or unrecognised fields return ``0.0``.

    Parameters
    ----------
    ann_dict:
        Parsed annotation dict (output of :func:`parse_annotation`).

    Returns
    -------
    float
        Size converted to kilobytes.
    """
    size_raw = ann_dict.get("Size", 0)
    unit_raw = str(ann_dict.get("Order of Size", "kb")).strip().lower()

    try:
        size = float(size_raw)
    except (TypeError, ValueError):
        return 0.0

    multiplier = _UNIT_TO_KB.get(unit_raw, 1.0)   # default: treat as KB
    return size * multiplier


# ---------------------------------------------------------------------------
# Enrichment helpers
# ---------------------------------------------------------------------------

def enrich_data_object(node: dict) -> dict:
    """Parse the ``annotation`` property of *node* and attach typed private keys.

    Adds the following keys to *node* (in-place) and returns it:

    ``_size_kb`` (float)
        Size converted to kilobytes via :func:`get_size_kb`.
    ``_is_personal`` (bool)
        ``True`` when ``Personal == "yes"``.
    ``_load`` (float)
        ``Load Dependence`` value; defaults to ``1.0`` if absent.

    Parameters
    ----------
    node:
        Mutable dict representing a BPMN data-object node.
    """
    ann_dict = parse_annotation(node.get("annotation", ""))
    node["_size_kb"]      = get_size_kb(ann_dict)
    node["_is_personal"]  = str(ann_dict.get("Personal", "no")).strip().lower() == "yes"
    try:
        node["_load"]     = float(ann_dict.get("Load Dependence", 1))
    except (TypeError, ValueError):
        node["_load"]     = 1.0
    return node


def enrich_task(node: dict) -> dict:
    """Parse the ``annotation`` property of *node* and attach the audit level.

    Adds the following key to *node* (in-place) and returns it:

    ``_audit_level`` (int)
        Numeric audit level: High → 3, Medium → 2, Low → 1, None → 0.
        Used in the LoAc formula (§5.7.4 of the project report).

    Parameters
    ----------
    node:
        Mutable dict representing a BPMN task node.
    """
    ann_dict = parse_annotation(node.get("annotation", ""))
    audit_raw = str(ann_dict.get("Audit", "low")).strip().lower()
    node["_audit_level"] = _AUDIT_LEVEL_MAP.get(audit_raw, 1)
    return node
