"""Report generation: HTML threat report and GDPR treatment register."""
from bpmn_security.reports.threat_report import generate_html_report
from bpmn_security.reports.treatment_register import generate_register
__all__ = ["generate_html_report", "generate_register"]
