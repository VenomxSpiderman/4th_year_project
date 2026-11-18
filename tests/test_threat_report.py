"""
tests/test_threat_report.py
────────────────────────────
Tests for threat_report.py — parse generated HTML and assert structural elements.
"""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from threat_report import generate_html_report


# ---------------------------------------------------------------------------
# Minimal threat fixture
# ---------------------------------------------------------------------------

def _minimal_threats():
    return [
        {
            "agent_name":      "Cybercriminal",
            "agent_severity":  3,
            "agent_access":    "External",
            "task_id":         "T1",
            "task_name":       "Issue Certificate",
            "task_subtype":    "ServiceTask",
            "task_annotation": "Communication Type=Stateful; Audit=High",
            "threat":          "Service Exploitation Risk",
            "behaviour":       "Attacker exploits service interface.",
            "mitigation":      "Apply rate limiting and input sanitisation.",
            "impact":          6.0,
            "likelihood":      5.4,
            "loc":             7.0,
            "loi":             7.0,
            "loa":             7.0,
            "loac":            1.0,
            "technical_impact": 5.5,
            "score":           5.45,
            "level":           "Medium",
            "connected_data":  [],
        },
        {
            "agent_name":      "Nation State",
            "agent_severity":  5,
            "agent_access":    "External",
            "task_id":         "T1",
            "task_name":       "Issue Certificate",
            "task_subtype":    "ServiceTask",
            "task_annotation": "Communication Type=Stateful; Audit=High",
            "threat":          "Malicious code execution",
            "behaviour":       "Attacker injects code.",
            "mitigation":      "Use RASP and SAST tools.",
            "impact":          7.0,
            "likelihood":      9.0,
            "loc":             7.0,
            "loi":             7.0,
            "loa":             7.0,
            "loac":            1.0,
            "technical_impact": 5.5,
            "score":           7.25,
            "level":           "High",
            "connected_data":  [],
        },
    ]


class TestGenerateHtmlReport:
    @pytest.fixture
    def report_path(self, tmp_path):
        threats = _minimal_threats()
        path = tmp_path / "report.html"
        generate_html_report(threats, path)
        return path

    def test_file_created(self, report_path):
        assert report_path.exists()

    def test_file_is_non_empty(self, report_path):
        assert report_path.stat().st_size > 0

    def test_contains_doctype(self, report_path):
        content = report_path.read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in content

    def test_contains_threat_count(self, report_path):
        content = report_path.read_text(encoding="utf-8")
        assert "2" in content  # 2 threat entries

    def test_contains_mitigation_word(self, report_path):
        content = report_path.read_text(encoding="utf-8")
        assert "Mitigation" in content or "mitigation" in content

    def test_contains_mitigation_text(self, report_path):
        content = report_path.read_text(encoding="utf-8")
        assert "rate limiting" in content or "Apply rate limiting" in content

    def test_contains_task_name(self, report_path):
        content = report_path.read_text(encoding="utf-8")
        assert "Issue Certificate" in content

    def test_contains_agent_name(self, report_path):
        content = report_path.read_text(encoding="utf-8")
        assert "Cybercriminal" in content

    def test_contains_threat_name(self, report_path):
        content = report_path.read_text(encoding="utf-8")
        assert "Service Exploitation Risk" in content

    def test_contains_level_badges(self, report_path):
        content = report_path.read_text(encoding="utf-8")
        assert "badge-High" in content or "badge-Medium" in content

    def test_contains_made_with_footer(self, report_path):
        content = report_path.read_text(encoding="utf-8")
        assert "IBM Bob" in content

    def test_is_self_contained_no_external_links(self, report_path):
        content = report_path.read_text(encoding="utf-8")
        # Must not reference external CDN or stylesheets
        assert "cdn." not in content
        assert '<link' not in content
        assert "http://" not in content
        assert "https://" not in content

    def test_empty_threat_list_still_produces_valid_html(self, tmp_path):
        path = tmp_path / "empty.html"
        generate_html_report([], path)
        content = path.read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in content
        assert "0" in content  # 0 threat entries
