from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from reconmind.nmap_import import NmapImportError, parse_nmap_xml, write_import_json
from reconmind.summarize import (
    SummaryError,
    build_summary,
    format_summary,
    write_summary_output,
)

LOGGER = logging.getLogger("reconmind")


def _configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level),
        format="%(asctime)s level=%(levelname)s logger=%(name)s event=%(message)s",
    )


def _positive_port(value: str) -> int:
    try:
        port = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("port must be an integer") from exc
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("port must be between 1 and 65535")
    return port


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="reconmind", description="RECONMIND CLI")
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging level",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    import_parser = subparsers.add_parser(
        "import-nmap", help="Import Nmap XML and write structured JSON"
    )
    import_parser.add_argument("--input", required=True, help="Path to Nmap XML input")
    import_parser.add_argument("--output", required=True, help="Path to JSON output")

    summarize_parser = subparsers.add_parser(
        "summarize", help="Summarize imported Nmap JSON service observations"
    )
    summarize_parser.add_argument("--input", required=True, help="Path to imported JSON input")
    summarize_parser.add_argument(
        "--format",
        choices=["text", "markdown", "json"],
        default="text",
        help="Report format (default: text)",
    )
    summarize_parser.add_argument(
        "--output",
        help="Optional report output path; defaults to stdout",
    )
    summarize_parser.add_argument(
        "--host",
        action="append",
        dest="hosts",
        metavar="ADDRESS",
        help="Include only hosts matching this address; may be repeated",
    )
    summarize_parser.add_argument(
        "--port",
        action="append",
        type=_positive_port,
        dest="ports",
        metavar="PORT",
        help="Include only hosts with this open port; may be repeated",
    )
    summarize_parser.add_argument(
        "--service",
        action="append",
        dest="services",
        metavar="NAME",
        help="Include only hosts with this service name; may be repeated",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    _configure_logging(args.log_level)

    if args.command == "import-nmap":
        input_path = Path(args.input)
        output_path = Path(args.output)

        LOGGER.info("import_nmap_started input=%s output=%s", input_path, output_path)
        try:
            result = parse_nmap_xml(input_path)
            write_import_json(result.payload, output_path)
        except NmapImportError as exc:
            LOGGER.error("import_nmap_failed error=%s", exc)
            print(f"Error: {exc}", file=sys.stderr)
            return 2
        LOGGER.info("import_nmap_completed output=%s", output_path)
        return 0

    if args.command == "summarize":
        input_path = Path(args.input)
        LOGGER.info("summarize_started input=%s", input_path)
        try:
            result = build_summary(
                input_path,
                host_filters=args.hosts,
                port_filters=args.ports,
                service_filters=args.services,
            )
            report = format_summary(result, args.format)
            if args.output:
                write_summary_output(report, Path(args.output))
            else:
                print(report)
        except SummaryError as exc:
            LOGGER.error("summarize_failed error=%s", exc)
            print(f"Error: {exc}", file=sys.stderr)
            return 2
        LOGGER.info("summarize_completed input=%s", input_path)
        return 0

    parser.print_help()
    return 1
