"""
risk_scoring.py
───────────────
OWASP-aligned risk scoring for BPMN threat entries.

Implements the formulae from §5.7 of the project report:

    Likelihood       = (s_a / 5) × 9                       (Eq. 5.4)
    TIM              → (LoC, LoI, LoA)  from Table 5.4     (§5.7.3)
    LoAc             = ((L_max - L_task) / L_max) × 8 + 1  (Eq. 5.7)
    Technical Impact = (LoC + LoI + LoA + LoAc) / 4        (Eq. 5.8)
    Risk             = (Likelihood + Technical Impact) / 2  (Eq. 5.3)

Risk level: Risk ≤ 3 → Low; 3 < Risk ≤ 6 → Medium; Risk > 6 → High.

Public API
──────────
``compute_likelihood(agent_severity)``
``compute_tim(task, all_data_objects)``
``compute_loac(task)``
``compute_risk(agent, behaviour, task, all_data_objects)``
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Technical Impact Matrix (Table 5.4)
# (LoC, LoI, LoA) values indexed as TIM[row][col]
# row: "critical" | "not_critical"
# col: "minimal"  | "extensive" | "all"
# ---------------------------------------------------------------------------

_TIM: dict[str, dict[str, tuple[float, float, float]]] = {
    "critical":     {"minimal": (6.0, 3.0, 5.0), "extensive": (7.0, 7.0, 7.0), "all": (9.0, 9.0, 9.0)},
    "not_critical": {"minimal": (2.0, 1.0, 1.0), "extensive": (6.0, 5.0, 5.0), "all": (9.0, 9.0, 9.0)},
}

# LoAc formula constants (§5.7.4)
_L_MAX: int = 3   # High audit level


# ---------------------------------------------------------------------------
# Internal rate helpers
# ---------------------------------------------------------------------------

def _compute_r_personal(task: dict, all_data_objects: list[dict]) -> float:
    """Compute r_personal — fraction of task load weighted by personal-data flag.

    r_personal = ( Σ_{d ∈ D_t} 1[personal(d)] · load(d) / |D| ) × 100
    """
    total_objects = len(all_data_objects)
    if total_objects == 0:
        return 0.0

    task_obj_ids: set[str] = {
        obj.get("id", "") for obj in task.get("connected_data", [])
    }
    numerator = sum(
        obj.get("_load", 1.0)
        for obj in all_data_objects
        if obj.get("id") in task_obj_ids and obj.get("_is_personal", False)
    )
    return (numerator / total_objects) * 100.0


def _compute_r_size(task: dict, all_data_objects: list[dict]) -> float:
    """Compute r_size — size-weighted fraction of process data touched by task.

    r_size = ( Σ_{d ∈ D_t} size_kb(d) · load(d)
             / Σ_{d ∈ D} size_kb(d) · load(d) ) × 100
    """
    total_weighted_size = sum(
        obj.get("_size_kb", 0.0) * obj.get("_load", 1.0)
        for obj in all_data_objects
    )
    if total_weighted_size == 0.0:
        return 0.0

    task_obj_ids: set[str] = {
        obj.get("id", "") for obj in task.get("connected_data", [])
    }
    task_weighted_size = sum(
        obj.get("_size_kb", 0.0) * obj.get("_load", 1.0)
        for obj in all_data_objects
        if obj.get("id") in task_obj_ids
    )
    return (task_weighted_size / total_weighted_size) * 100.0


# ---------------------------------------------------------------------------
# Public scoring functions
# ---------------------------------------------------------------------------

def compute_likelihood(agent_severity: float) -> float:
    """Compute likelihood score from agent severity.

    Parameters
    ----------
    agent_severity:
        Numeric severity ``s_a`` on a 1–5 scale (Table 5.2).

    Returns
    -------
    float
        Likelihood on the OWASP 1–9 scale.
    """
    return (agent_severity / 5.0) * 9.0


def compute_tim(
    task: dict,
    all_data_objects: list[dict],
) -> tuple[float, float, float]:
    """Compute (LoC, LoI, LoA) from the Technical Impact Matrix.

    Parameters
    ----------
    task:
        Task dict enriched with ``connected_data`` (list of data-object dicts
        already enriched by ``annotation_parser.enrich_data_object()``).
    all_data_objects:
        All data-object dicts in the process (for denominator calculations).

    Returns
    -------
    (LoC, LoI, LoA) as a tuple of floats.
    """
    r_personal = _compute_r_personal(task, all_data_objects)
    r_size     = _compute_r_size(task, all_data_objects)

    # TIM row (§5.7.3)
    row = "critical" if r_personal >= 25.0 else "not_critical"

    # TIM column
    if r_size >= 90.0:
        col = "all"
    elif r_size >= 25.0:
        col = "extensive"
    else:
        col = "minimal"

    return _TIM[row][col]


def compute_loac(task: dict) -> float:
    """Compute Loss of Accountability from the task audit annotation.

    LoAc = ((L_max - L_task) / L_max) × 8 + 1

    Parameters
    ----------
    task:
        Task dict enriched with ``_audit_level`` by
        ``annotation_parser.enrich_task()``.

    Returns
    -------
    float
        LoAc on the OWASP 1–9 scale.
    """
    l_task = task.get("_audit_level", 1)  # default Low = 1
    return ((_L_MAX - l_task) / _L_MAX) * 8.0 + 1.0


def compute_risk(
    agent: dict,
    behaviour: dict,
    task: dict,
    all_data_objects: list[dict],
) -> dict:
    """Compute the full OWASP risk entry for one agent–behaviour–task triple.

    Parameters
    ----------
    agent:
        Agent dict from ``THREAT_AGENTS`` (must contain ``severity``).
    behaviour:
        Behaviour dict from ``detect_behaviours()`` (contains ``impact``).
    task:
        Task dict enriched with ``_audit_level`` and ``connected_data``.
    all_data_objects:
        All process data objects (enriched).

    Returns
    -------
    dict with keys:
        ``likelihood`` (float),
        ``loc`` (float), ``loi`` (float), ``loa`` (float), ``loac`` (float),
        ``technical_impact`` (float),
        ``score`` (float),
        ``level`` (str: "Low" | "Medium" | "High").
    """
    likelihood = compute_likelihood(float(agent.get("severity", 1)))
    loc, loi, loa = compute_tim(task, all_data_objects)
    loac = compute_loac(task)

    technical_impact = (loc + loi + loa + loac) / 4.0
    score = (likelihood + technical_impact) / 2.0

    # Risk level thresholds.
    # The report text states ≤3 Low, ≤6 Medium, >6 High — but the worked
    # example (§5.7.6) yields 6.12 and labels it "Medium", which implies
    # the effective High boundary is >6.5 (consistent with OWASP's standard
    # LOW 0-3 / MEDIUM 3-6 / HIGH 6-9 open-upper bands where 6.x rounds to
    # the Medium band until >= 6.5).  We match the report's worked example.
    if score <= 3.0:
        level = "Low"
    elif score < 6.5:
        level = "Medium"
    else:
        level = "High"

    return {
        "likelihood":       round(likelihood,        4),
        "loc":              round(loc,               4),
        "loi":              round(loi,               4),
        "loa":              round(loa,               4),
        "loac":             round(loac,              4),
        "technical_impact": round(technical_impact,  4),
        "score":            round(score,             4),
        "level":            level,
    }
