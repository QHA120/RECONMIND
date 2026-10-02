from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


class SummaryError(Exception):
    """Base summary error."""


class SummaryInputError(SummaryError):
    """Raised for missing/unreadable/invalid JSON input."""


class SummaryOutputError(SummaryError):
    """Raised for output path creation/write failures."""


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


def _matches_any(value: str, filters: Iterable[str] | None) -> bool:
    values = list(filters or [])
    return not values or value in values


def _service_name(port: dict) -> str:
    service = port.get("service")
    if isinstance(service, dict) and isinstance(service.get("name"), str):
        return service["name"]
    return "unknown"


def _host_matches(host: dict, host_filters: Iterable[str] | None) -> bool:
    if not host_filters:
        return True
    addresses = {
        address.get("address")
        for address in host.get("addresses", [])
        if isinstance(address, dict) and isinstance(address.get("address"), str)
    }
    return bool(addresses.intersection(host_filters))


def _port_matches(
    port: dict,
    port_filters: Iterable[int] | None,
    service_filters: Iterable[str] | None,
) -> bool:
    if port_filters and port.get("port") not in port_filters:
        return False
    if service_filters:
        wanted = {service.lower() for service in service_filters}
        if _service_name(port).lower() not in wanted:
            return False
    return True


def build_summary(
    input_path: Path,
    host_filters: Iterable[str] | None = None,
    port_filters: Iterable[int] | None = None,
    service_filters: Iterable[str] | None = None,
) -> SummaryResult:
    payload = _read_json(input_path)
    hosts_payload = payload.get("hosts")
    if not isinstance(hosts_payload, list):
        hosts_payload = []

    hosts: list[HostSummary] = []
    for host in hosts_payload:
        if not isinstance(host, dict) or not _host_matches(host, host_filters):
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
            if isinstance(port, dict)
            and port.get("state") == "open"
            and _port_matches(port, port_filters, service_filters)
        ]
        if (port_filters or service_filters) and not open_ports_payload:
            continue

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
            service_name = _service_name(port)
            service = port.get("service")
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


def _format_summary_text(result: SummaryResult) -> str:
    lines = [f"Hosts found: {len(result.hosts)}"]
    for index, host in enumerate(result.hosts, start=1):
        lines.append("")
        lines.append(f"Host {index}: {', '.join(host.addresses) or 'unknown'}")
        lines.append(f"Open ports: {len(host.open_ports)}")
        lines.extend(f"  {port_entry}" for port_entry in host.open_ports)
    lines.append("")
    lines.append("Note: These are observed Nmap service data, not confirmed vulnerabilities.")
    return "\n".join(lines)


def _format_summary_markdown(result: SummaryResult) -> str:
    lines = ["# RECONMIND Summary", "", f"## Hosts found: {len(result.hosts)}"]
    for index, host in enumerate(result.hosts, start=1):
        lines.extend(
            [
                "",
                f"### Host {index}: {', '.join(host.addresses) or 'unknown'}",
                "",
                f"**Open ports:** {len(host.open_ports)}",
            ]
        )
        if host.open_ports:
            lines.extend(["", "| Service observation |", "| --- |"])
            lines.extend(f"| {port_entry} |" for port_entry in host.open_ports)
        else:
            lines.extend(["", "_No open ports observed._"])
    lines.extend(
        [
            "",
            "**Note:** These are observed Nmap service data, not confirmed vulnerabilities.",
        ]
    )
    return "\n".join(lines)


def _format_summary_json(result: SummaryResult) -> str:
    payload = {
        "hosts_found": len(result.hosts),
        "hosts": [
            {
                "index": index,
                "addresses": host.addresses,
                "open_ports": host.open_ports,
            }
            for index, host in enumerate(result.hosts, start=1)
        ],
        "note": "These are observed Nmap service data, not confirmed vulnerabilities.",
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def format_summary(result: SummaryResult, output_format: str = "text") -> str:
    """Render a summary in the requested format."""
    if output_format == "text":
        return _format_summary_text(result)
    if output_format == "markdown":
        return _format_summary_markdown(result)
    if output_format == "json":
        return _format_summary_json(result)
    raise SummaryError(f"Unsupported summary format: {output_format}")


def write_summary_output(report: str, output_path: Path) -> None:
    """Write a report, creating parent directories when necessary."""
    parent = output_path.parent
    try:
        parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise SummaryOutputError(
            f"Failed to create output directory '{parent}': {exc}"
        ) from exc

    try:
        output_path.write_text(report + "\n", encoding="utf-8")
    except OSError as exc:
        raise SummaryOutputError(
            f"Failed to write output file '{output_path}': {exc}"
        ) from exc
