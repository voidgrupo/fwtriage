import argparse
import os
import sys
from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path

from fwtriage import app, config
from fwtriage.model import (
    CATALOG,
    BudgetExceeded,
    Confidence,
    FwtriageError,
    OnlineError,
    Policy,
    PolicyError,
    Severity,
)
from fwtriage.output import json_report, sarif, sbom, svg_map, terminal, write_filesystems, write_text
from fwtriage.output.meta import tool_version

EXIT_CLEAN, EXIT_FAILED, EXIT_USAGE, EXIT_ERROR = 0, 1, 2, 3
COMMANDS = {"scan", "unpack", "rules", "explain"}


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments and arguments[0] not in COMMANDS and not arguments[0].startswith("-"):
        arguments.insert(0, "scan")
    options = _parser().parse_args(arguments)
    try:
        return int(options.handler(options))
    except PolicyError as error:
        return _fail(f"policy: {error}", EXIT_USAGE)
    except OnlineError as error:
        return _fail(f"online lookup failed: {error}", EXIT_ERROR)
    except (FwtriageError, OSError) as error:
        return _fail(str(error), EXIT_ERROR)


def _fail(message: str, code: int) -> int:
    print(f"fwtriage: {message}", file=sys.stderr)
    return code


def _policy(options: argparse.Namespace) -> Policy:
    path = options.config or config.discover(Path.cwd())
    policy = config.load(path)
    if options.fail_on:
        policy = replace(policy, fail_on=Severity.parse(options.fail_on))
    if options.min_confidence:
        policy = replace(policy, min_confidence=Confidence.parse(options.min_confidence))
    return policy


def _scan(options: argparse.Namespace) -> int:
    image: Path = options.image
    if not image.exists():
        return _fail(f"{image}: no such file or directory", EXIT_USAGE)
    report = app.scan(image, _policy(options), online=options.online)
    color = not options.no_color and sys.stdout.isatty() and "NO_COLOR" not in os.environ
    print(terminal.render(report, color, Severity.parse(options.show)))
    writers = ((options.json, json_report.render), (options.sarif, sarif.render), (options.sbom, sbom.render))
    for path, render in writers:
        if path:
            write_text(path, render(report))
    if options.map and image.is_file():
        write_text(options.map, svg_map.render(image, report))
    return EXIT_FAILED if report.failed else EXIT_CLEAN


def _unpack(options: argparse.Namespace) -> int:
    try:
        result = app.extract(options.image, _policy(options))
    except BudgetExceeded as error:
        return _fail(str(error), EXIT_ERROR)
    filesystems = [(located.path, located.filesystem) for located in result.filesystems]
    written = write_filesystems(options.output, filesystems)
    print(
        f"{written.files} files and {written.links} links "
        f"from {len(filesystems)} filesystems written to {options.output}"
    )
    for path in written.skipped:
        print(f"skipped {path}", file=sys.stderr)
    for notice in result.notices:
        print(f"{notice.code}: {notice.message}  {notice.location}", file=sys.stderr)
    return EXIT_CLEAN


def _rules(_: argparse.Namespace) -> int:
    for rule in CATALOG:
        print(f"{rule.id}  {rule.severity.label:<8}  {rule.title}")
    return EXIT_CLEAN


def _explain(options: argparse.Namespace) -> int:
    rule = next((r for r in CATALOG if r.id == options.rule.upper()), None)
    if rule is None:
        return _fail(f"unknown rule {options.rule}; see 'fwtriage rules'", EXIT_USAGE)
    print(f"{rule.id}  {rule.title}\ndefault severity: {rule.severity.label}")
    if rule.reference:
        print(f"reference: CWE-{rule.cwe}  {rule.reference}")
    return EXIT_CLEAN


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fwtriage", description="Fast, evidence-first security triage for firmware images."
    )
    parser.add_argument("--version", action="version", version=f"fwtriage {tool_version()}")
    commands = parser.add_subparsers(required=True, metavar="COMMAND")
    _scan_parser(commands)
    _unpack_parser(commands)
    commands.add_parser("rules", help="list the rule catalog").set_defaults(handler=_rules)
    explain = commands.add_parser("explain", help="show one rule")
    explain.add_argument("rule")
    explain.set_defaults(handler=_explain)
    return parser


def _policy_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--config", type=Path, help="policy file (default: fwtriage.toml or [tool.fwtriage] found upward)"
    )
    parser.add_argument("--fail-on", choices=[s.label for s in Severity], help="lowest severity that fails the run")
    parser.add_argument(
        "--min-confidence", choices=[c.label for c in Confidence], help="lowest confidence that fails the run"
    )


def _scan_parser(commands: "argparse._SubParsersAction[argparse.ArgumentParser]") -> None:
    scan = commands.add_parser("scan", help="analyze an image or an extracted root filesystem")
    scan.add_argument("image", type=Path)
    scan.add_argument("--json", type=Path, metavar="FILE", help="write the full report as JSON")
    scan.add_argument("--sarif", type=Path, metavar="FILE", help="write SARIF 2.1.0 for code scanning")
    scan.add_argument("--sbom", type=Path, metavar="FILE", help="write a CycloneDX 1.5 SBOM")
    scan.add_argument("--map", type=Path, metavar="FILE", help="write the annotated entropy map as SVG")
    scan.add_argument(
        "--online", action="store_true", help="match components against NVD (set NVD_API_KEY to go faster)"
    )
    scan.add_argument("--show", default="info", choices=[s.label for s in Severity], help="lowest severity printed")
    scan.add_argument("--no-color", action="store_true", help="disable color (NO_COLOR is honored too)")
    _policy_options(scan)
    scan.set_defaults(handler=_scan)


def _unpack_parser(commands: "argparse._SubParsersAction[argparse.ArgumentParser]") -> None:
    unpack = commands.add_parser("unpack", help="write every unpacked filesystem to a directory")
    unpack.add_argument("image", type=Path)
    unpack.add_argument("-o", "--output", type=Path, required=True, metavar="DIR")
    _policy_options(unpack)
    unpack.set_defaults(handler=_unpack)
