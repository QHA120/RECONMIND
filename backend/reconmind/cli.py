from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from reconmind.nmap_import import NmapImportError, parse_nmap_xml, write_import_json

LOGGER = logging.getLogger("reconmind")


def _configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level),
        format="%(asctime)s level=%(levelname)s logger=%(name)s event=%(message)s",
    )


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

    parser.print_help()
    return 1
