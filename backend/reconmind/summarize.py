from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


class SummaryError(Exception):
    """Base summary error."""


class SummaryInputError(SummaryError):
    """Raised for missing/unreadable/invalid JSON input."""


@dataclass(frozen=True)
class HostSummary:
    addresses: list[str]
    open_ports: list[str]


@dataclass(frozen=True)
class SummaryResult:
    hosts: list[HostSummary]


def _read_json(input_path: Path) -> dict:
    if not input_path.exists() or not input_path.is_file():
        raise SummaryInputError(f"Input file does not exist: {input_path}")
    if input_path.suffix.lower() != ".json":
        raise SummaryInputError(
            f"Unsupported input file type for {input_path.name}; expected .json"
        )

    try:
        return json.loads(input_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise SummaryInputError(f"Failed to read input file '{input_path}': {exc}") from exc
    except json.JSONDecodeError as exc:
        raise SummaryInputError(f"Invalid JSON in {input_path}: {exc}") from exc


def build_summary(input_path: Path) -> SummaryResult:
    payload = _read_json(input_path)
    hosts_payload = payload.get("hosts")
    if not isinstance(hosts_payload, list):
        hosts_payload = []

    hosts: list[HostSummary] = []
    for host in hosts_payload:
        if not isinstance(host, dict):
            continue
        addresses = [
            address.get("address")
            for address in host.get("addresses", [])
            if isinstance(address, dict)
            and address.get("type") != "mac"
            and isinstance(address.get("address"), str)
            and address.get("address")
        ]

        open_ports_payload = [
            port
            for port in host.get("ports", [])
            if isinstance(port, dict) and port.get("state") == "open"
        ]
        open_ports_payload.sort(
            key=lambda port: (
                str(port.get("protocol", "")),
                int(port.get("port"))
                if isinstance(port.get("port"), int)
                else float("inf"),
                str(port.get("port", "")),
            )
        )

        open_ports: list[str] = []
        for port in open_ports_payload:
            port_number = port.get("port")
            protocol = port.get("protocol", "unknown")
            service = port.get("service")
            service_name = (
                service.get("name")
                if isinstance(service, dict) and isinstance(service.get("name"), str)
                else "unknown"
            )
            details = []
            if isinstance(service, dict):
                if isinstance(service.get("product"), str) and service.get("product"):
                    details.append(service["product"])
                if isinstance(service.get("version"), str) and service.get("version"):
                    details.append(service["version"])
            suffix = f" ({' '.join(details)})" if details else ""
            open_ports.append(f"{port_number}/{protocol}: {service_name}{suffix}")

        hosts.append(HostSummary(addresses=addresses, open_ports=open_ports))

    return SummaryResult(hosts=hosts)


def format_summary(result: SummaryResult) -> str:
    lines = [f"Hosts found: {len(result.hosts)}"]
    for index, host in enumerate(result.hosts, start=1):
        lines.append("")
        lines.append(f"Host {index}: {', '.join(host.addresses) or 'unknown'}")
        lines.append(f"Open ports: {len(host.open_ports)}")
        lines.extend(f"  {port_entry}" for port_entry in host.open_ports)
    lines.append("")
    lines.append("Note: These are observed Nmap service data, not confirmed vulnerabilities.")
    return "\n".join(lines)
