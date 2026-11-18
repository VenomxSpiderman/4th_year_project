"""
cli.py
──────
Unified CLI entry point for the BPMN Security Analysis pipeline.

Commands:
  init-db   Seed the ENISA catalogue database from the JSON source.
  parse     Parse a BPMN file and print element counts.
  store     Parse a BPMN file and store it in Neo4j.
  refine    Run model-refinement checks against the Neo4j graph.
  analyze   Generate and print the threat model.
  report    Write an HTML threat report from a threats JSON file.
  register  Write a GDPR Article 30 CSV register from a threats JSON file.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

try:
    import click
    _HAS_CLICK = True
except ImportError:
    _HAS_CLICK = False


def _require_click() -> None:
    if not _HAS_CLICK:
        print("ERROR: 'click' is not installed. Run: uv add click", file=sys.stderr)
        sys.exit(1)


def main() -> None:
    """Entry point for the bpmn-security CLI."""
    _require_click()
    cli()  # type: ignore[name-defined]


if _HAS_CLICK:
    import click as _click  # noqa: E402  (re-import for decorator access)

    @_click.group()
    def cli() -> None:
        """BPMN Security Risk & Privacy Analysis Framework."""

    @cli.command("init-db")
    @_click.option("--json", "json_path", default="data/enisa_catalogue.json", show_default=True)
    @_click.option("--db", "db_path", default="data/enisa_catalogue.db", show_default=True)
    @_click.option("--validate-only", is_flag=True)
    def init_db(json_path: str, db_path: str, validate_only: bool) -> None:
        """Seed the ENISA catalogue SQLite database."""
        from bpmn_security.catalogue.import_catalogue import main as _main
        argv = ["--json", json_path, "--db", db_path]
        if validate_only:
            argv.append("--validate-only")
        sys.exit(_main(argv))

    @cli.command("parse")
    @_click.argument("path")
    def parse(path: str) -> None:
        """Parse a BPMN file or directory and print element counts."""
        from bpmn_security.parsers.bpmn_reader import bpmn_extract, multi_file_extract
        p = Path(path)
        if p.is_dir():
            procs, mfs, das = multi_file_extract(p)
        else:
            procs, mfs, das = bpmn_extract(p)
        total = sum(len(proc.get("elements", [])) for proc in procs)
        _click.echo(f"Processes:         {len(procs)}")
        _click.echo(f"Total elements:    {total}")
        _click.echo(f"Message flows:     {len(mfs)}")
        _click.echo(f"Data associations: {len(das)}")

    @cli.command("store")
    @_click.argument("path")
    def store(path: str) -> None:
        """Parse a BPMN file and store it in Neo4j."""
        from bpmn_security.parsers.bpmn_reader import bpmn_extract, multi_file_extract
        from bpmn_security.graph.bpmn_graph_storing import store_bpmn
        p = Path(path)
        if p.is_dir():
            procs, mfs, das = multi_file_extract(p)
        else:
            procs, mfs, das = bpmn_extract(p)
        store_bpmn(procs, mfs, das)
        _click.echo("Done.")

    @cli.command("refine")
    def refine() -> None:
        """Run model-refinement checks against the Neo4j graph."""
        import os
        from bpmn_security.graph.model_refinement import run_refinement
        from bpmn_security.config import get_neo4j_uri, get_neo4j_user, get_neo4j_password
        from neo4j import GraphDatabase  # type: ignore
        driver = GraphDatabase.driver(
            get_neo4j_uri(), auth=(get_neo4j_user(), get_neo4j_password())
        )
        try:
            with driver.session() as session:
                result = run_refinement(session)
        finally:
            driver.close()
        _click.echo(json.dumps(result, indent=2))

    @cli.command("analyze")
    @_click.option("--write-back/--no-write-back", default=False,
                   help="Write risk scores back to Neo4j Task nodes.")
    def analyze(write_back: bool) -> None:
        """Generate and print the threat model (interactive context prompt)."""
        import os
        from bpmn_security.analysis.threat_modelling import (
            generate_threat_model, write_risk_scores_to_graph,
            _prompt_context, _print_threats,
        )
        from bpmn_security.config import get_neo4j_uri, get_neo4j_user, get_neo4j_password
        from neo4j import GraphDatabase  # type: ignore
        driver = GraphDatabase.driver(
            get_neo4j_uri(), auth=(get_neo4j_user(), get_neo4j_password())
        )
        context = _prompt_context()
        try:
            with driver.session() as session:
                threats = generate_threat_model(session, context)
                if write_back:
                    count = write_risk_scores_to_graph(session, threats)
                    _click.echo(f"Wrote risk scores to {count} Task node(s).")
        finally:
            driver.close()
        _print_threats(threats)

    @cli.command("report")
    @_click.argument("threats_json")
    @_click.argument("output_html")
    def report(threats_json: str, output_html: str) -> None:
        """Write an HTML threat report from a threats JSON file."""
        from bpmn_security.reports.threat_report import generate_html_report
        threats = json.loads(Path(threats_json).read_text(encoding="utf-8"))
        generate_html_report(threats, output_html)
        _click.echo(f"Report written to {output_html}.")

    @cli.command("register")
    @_click.argument("threats_json")
    @_click.argument("output_csv")
    def register(threats_json: str, output_csv: str) -> None:
        """Write a GDPR Article 30 CSV register from a threats JSON file."""
        from bpmn_security.reports.treatment_register import generate_register
        threats = json.loads(Path(threats_json).read_text(encoding="utf-8"))
        generate_register(threats, output_csv)
        _click.echo(f"Register written to {output_csv}.")
