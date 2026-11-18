"""
tests/test_annotation_parser.py
────────────────────────────────
Unit tests for annotation_parser.py.
"""

import pytest

from bpmn_security.parsers.annotation_parser import (
    parse_annotation,
    get_size_kb,
    enrich_data_object,
    enrich_task,
)


# ---------------------------------------------------------------------------
# parse_annotation
# ---------------------------------------------------------------------------

class TestParseAnnotation:
    def test_basic_string_value(self):
        result = parse_annotation("Personal=yes")
        assert result == {"Personal": "yes"}

    def test_integer_coercion(self):
        result = parse_annotation("Size=10")
        assert result["Size"] == 10
        assert isinstance(result["Size"], int)

    def test_float_coercion(self):
        result = parse_annotation("Load Dependence=1.5")
        assert result["Load Dependence"] == 1.5
        assert isinstance(result["Load Dependence"], float)

    def test_string_lowercased(self):
        result = parse_annotation("Personal=YES")
        assert result["Personal"] == "yes"

    def test_multiple_fields(self):
        text = "Size=10; Order of Size=KB; Personal=yes; Load Dependence=2"
        result = parse_annotation(text)
        assert result["Size"] == 10
        assert result["Order of Size"] == "kb"
        assert result["Personal"] == "yes"
        assert result["Load Dependence"] == 2

    def test_none_returns_empty_dict(self):
        assert parse_annotation(None) == {}

    def test_empty_string_returns_empty_dict(self):
        assert parse_annotation("") == {}

    def test_whitespace_only_returns_empty_dict(self):
        assert parse_annotation("   ;  ; ") == {}

    def test_token_without_equals_is_skipped(self):
        result = parse_annotation("NoEqualsHere; Size=5")
        assert result == {"Size": 5}

    def test_extra_whitespace_stripped(self):
        result = parse_annotation("  Size  =  10  ;  Personal  =  yes  ")
        assert result["Size"] == 10
        assert result["Personal"] == "yes"

    def test_value_with_equals_sign_uses_first_partition(self):
        # "Key=a=b" → key="Key", value="a=b" → lowercased str "a=b"
        result = parse_annotation("Key=a=b")
        assert result["Key"] == "a=b"


# ---------------------------------------------------------------------------
# get_size_kb
# ---------------------------------------------------------------------------

class TestGetSizeKb:
    def test_kb_unit(self):
        ann = {"Size": 10, "Order of Size": "kb"}
        assert get_size_kb(ann) == pytest.approx(10.0)

    def test_mb_unit(self):
        ann = {"Size": 1, "Order of Size": "mb"}
        assert get_size_kb(ann) == pytest.approx(1024.0)

    def test_gb_unit(self):
        ann = {"Size": 1, "Order of Size": "gb"}
        assert get_size_kb(ann) == pytest.approx(1024.0 * 1024.0)

    def test_b_unit(self):
        ann = {"Size": 1024, "Order of Size": "b"}
        assert get_size_kb(ann) == pytest.approx(1.0)

    def test_uppercase_unit_string(self):
        ann = {"Size": 2, "Order of Size": "MB"}
        assert get_size_kb(ann) == pytest.approx(2 * 1024.0)

    def test_missing_size_returns_zero(self):
        ann = {"Order of Size": "kb"}
        assert get_size_kb(ann) == pytest.approx(0.0)

    def test_missing_unit_defaults_to_kb(self):
        ann = {"Size": 5}
        assert get_size_kb(ann) == pytest.approx(5.0)

    def test_unknown_unit_defaults_to_kb(self):
        ann = {"Size": 3, "Order of Size": "tb"}
        # Unknown unit defaults to 1.0 (KB) multiplier
        assert get_size_kb(ann) == pytest.approx(3.0)

    def test_bad_size_value_returns_zero(self):
        ann = {"Size": "not_a_number", "Order of Size": "kb"}
        assert get_size_kb(ann) == pytest.approx(0.0)


# ---------------------------------------------------------------------------
# enrich_data_object
# ---------------------------------------------------------------------------

class TestEnrichDataObject:
    def test_personal_yes(self):
        node = {"annotation": "Personal=yes; Size=10; Order of Size=KB; Load Dependence=2"}
        enrich_data_object(node)
        assert node["_is_personal"] is True

    def test_personal_no(self):
        node = {"annotation": "Personal=no; Size=1; Order of Size=KB; Load Dependence=1"}
        enrich_data_object(node)
        assert node["_is_personal"] is False

    def test_size_kb_computed(self):
        node = {"annotation": "Size=5; Order of Size=KB; Personal=no; Load Dependence=1"}
        enrich_data_object(node)
        assert node["_size_kb"] == pytest.approx(5.0)

    def test_load_dependence_set(self):
        node = {"annotation": "Personal=no; Size=1; Order of Size=KB; Load Dependence=3"}
        enrich_data_object(node)
        assert node["_load"] == pytest.approx(3.0)

    def test_missing_annotation_sets_defaults(self):
        node = {}
        enrich_data_object(node)
        assert node["_is_personal"] is False
        assert node["_size_kb"] == pytest.approx(0.0)
        assert node["_load"] == pytest.approx(1.0)

    def test_returns_same_node(self):
        node = {"annotation": "Personal=yes; Size=1; Order of Size=KB; Load Dependence=1"}
        result = enrich_data_object(node)
        assert result is node


# ---------------------------------------------------------------------------
# enrich_task
# ---------------------------------------------------------------------------

class TestEnrichTask:
    def test_high_audit(self):
        node = {"annotation": "Audit=High"}
        enrich_task(node)
        assert node["_audit_level"] == 3

    def test_medium_audit(self):
        node = {"annotation": "Audit=Medium"}
        enrich_task(node)
        assert node["_audit_level"] == 2

    def test_low_audit(self):
        node = {"annotation": "Audit=Low"}
        enrich_task(node)
        assert node["_audit_level"] == 1

    def test_none_audit(self):
        node = {"annotation": "Audit=None"}
        enrich_task(node)
        assert node["_audit_level"] == 0

    def test_case_insensitive(self):
        node = {"annotation": "Audit=HIGH"}
        enrich_task(node)
        assert node["_audit_level"] == 3

    def test_missing_audit_defaults_to_low(self):
        node = {"annotation": "Communication Type=Mail"}
        enrich_task(node)
        assert node["_audit_level"] == 1

    def test_no_annotation_defaults_to_low(self):
        node = {}
        enrich_task(node)
        assert node["_audit_level"] == 1

    def test_returns_same_node(self):
        node = {"annotation": "Audit=High"}
        result = enrich_task(node)
        assert result is node
