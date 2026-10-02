from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


class NmapImportError(Exception):
    """Base import error."""


class InputValidationError(NmapImportError):
    """Raised for missing/invalid input paths."""


class UnsupportedInputError(NmapImportError):
    """Raised for unsupported input files."""


class MalformedXMLError(NmapImportError):
    """Raised when XML cannot be parsed."""


class OutputWriteError(NmapImportError):
    """Raised when output paths cannot be created/written."""


@dataclass(frozen=True)
class ImportResult:
    payload: dict


def _clean_none(data: dict) -> dict:
    return {key: value for key, value in data.items() if value is not None}


def _require_xml_input(input_path: Path) -> Path:
    if not input_path.exists() or not input_path.is_file():
        raise InputValidationError(f"Input file does not exist: {input_path}")
    if input_path.suffix.lower() != ".xml":
        raise UnsupportedInputError(
            f"Unsupported input file type for {input_path.name}; expected .xml"
        )
    return input_path


def parse_nmap_xml(input_path: Path) -> ImportResult:
    input_path = _require_xml_input(input_path)

    try:
        tree = ET.parse(input_path)
    except ET.ParseError as exc:
        raise MalformedXMLError(f"Malformed XML in {input_path}: {exc}") from exc

    root = tree.getroot()
    if root.tag != "nmaprun":
        raise UnsupportedInputError(
            f"Unsupported XML root '{root.tag}' in {input_path}; expected 'nmaprun'"
        )

    runstats = root.find("runstats")
    finished = runstats.find("finished") if runstats is not None else None
    hosts_stats = runstats.find("hosts") if runstats is not None else None

    hosts: list[dict] = []
    for host in root.findall("host"):
        status_elem = host.find("status")
        addresses = [
            _clean_none(
                {
                    "address": address.get("addr"),
                    "type": address.get("addrtype"),
                    "vendor": address.get("vendor"),
                }
            )
            for address in host.findall("address")
        ]

        ports: list[dict] = []
        for port in host.findall("ports/port"):
            state_elem = port.find("state")
            service_elem = port.find("service")
            service = _clean_none(
                {
                    "name": service_elem.get("name") if service_elem is not None else None,
                    "product": service_elem.get("product") if service_elem is not None else None,
                    "version": service_elem.get("version") if service_elem is not None else None,
                    "extra_info": service_elem.get("extrainfo")
                    if service_elem is not None
                    else None,
                }
            )
            ports.append(
                _clean_none(
                    {
                        "port": int(port.get("portid")) if port.get("portid") else None,
                        "protocol": port.get("protocol"),
                        "state": state_elem.get("state") if state_elem is not None else None,
                        "reason": state_elem.get("reason") if state_elem is not None else None,
                        "service": service,
                    }
                )
            )

        hostnames = [
            _clean_none(
                {
                    "name": hostname.get("name"),
                    "type": hostname.get("type"),
                }
            )
            for hostname in host.findall("hostnames/hostname")
        ]

        hosts.append(
            _clean_none(
                {
                    "status": status_elem.get("state") if status_elem is not None else None,
                    "addresses": addresses,
                    "hostnames": hostnames,
                    "ports": ports,
                }
            )
        )

    payload = {
        "scan": _clean_none(
            {
                "scanner": root.get("scanner"),
                "args": root.get("args"),
                "start": root.get("start"),
                "start_human": root.get("startstr"),
                "version": root.get("version"),
                "xml_output_version": root.get("xmloutputversion"),
                "runstats": _clean_none(
                    {
                        "finished_time": finished.get("time") if finished is not None else None,
                        "summary": finished.get("summary") if finished is not None else None,
                        "exit": finished.get("exit") if finished is not None else None,
                        "hosts_up": hosts_stats.get("up") if hosts_stats is not None else None,
                        "hosts_down": hosts_stats.get("down") if hosts_stats is not None else None,
                        "hosts_total": hosts_stats.get("total")
                        if hosts_stats is not None
                        else None,
                    }
                ),
            }
        ),
        "hosts": hosts,
        "source": {
            "type": "nmap_xml",
            "input_path": str(input_path),
            "imported_at": datetime.now(timezone.utc).isoformat(),
            "evidence": {
                "root_tag": root.tag,
                "host_count": len(hosts),
            },
            "authorization_required": "Use only on explicitly authorized systems.",
        },
    }

    return ImportResult(payload=payload)


def write_import_json(payload: dict, output_path: Path) -> None:
    parent = output_path.parent
    try:
        if parent.exists() and not parent.is_dir():
            raise OutputWriteError(f"Output directory path is not a directory: {parent}")
        parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise OutputWriteError(f"Failed to create output directory '{parent}': {exc}") from exc

    try:
        output_path.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    except OSError as exc:
        raise OutputWriteError(f"Failed to write output file '{output_path}': {exc}") from exc
