from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


class SummaryError(Exception):
    """Base summary error."""


class SummaryInputError(SummaryError):
    """Raised for missing/unreadable/invalid JSON input."""


class SummaryOutputError(SummaryError):
    """Raised for output path creation/write failures."""


@dataclass(frozen=True)
class SummaryFilters:
    hosts: tuple[str, ...] = ()
    ports: tuple[int, ...] = ()
    services: tuple[str, ...] = ()


@dataclass(frozen=True)
class MacAddressSummary:
    address: str
    vendor: str | None = None


@dataclass(frozen=True)
class ServiceSummary:
    port: int | None
    protocol: str
    service_name: str
    product: str | None = None
    version: str | None = None


@dataclass(frozen=True)
class HostSummary:
    addresses: list[str]
    hostnames: list[str]
    mac_addresses: list[MacAddressSummary]
    open_services: list[ServiceSummary]


@dataclass(frozen=True)
class SummaryResult:
    scan_metadata: dict[str, str]
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


def _extract_scan_metadata(payload: dict) -> dict[str, str]:
    scan = payload.get("scan")
    source = payload.get("source")
    runstats = scan.get("runstats") if isinstance(scan, dict) else {}
    runstats = runstats if isinstance(runstats, dict) else {}

    metadata = {
        "scanner": scan.get("scanner") if isinstance(scan, dict) else None,
        "args": scan.get("args") if isinstance(scan, dict) else None,
        "start": scan.get("start") if isinstance(scan, dict) else None,
        "start_human": scan.get("start_human") if isinstance(scan, dict) else None,
        "version": scan.get("version") if isinstance(scan, dict) else None,
        "xml_output_version": scan.get("xml_output_version") if isinstance(scan, dict) else None,
        "finished_time": runstats.get("finished_time"),
        "summary": runstats.get("summary"),
        "exit": runstats.get("exit"),
        "hosts_up": runstats.get("hosts_up"),
        "hosts_down": runstats.get("hosts_down"),
        "hosts_total": runstats.get("hosts_total"),
        "imported_at": source.get("imported_at") if isinstance(source, dict) else None,
    }
    return {
        key: str(value)
        for key, value in metadata.items()
        if isinstance(value, str) and value.strip()
    }


def _host_matches(host: HostSummary, filters: SummaryFilters) -> bool:
    if not filters.hosts:
        return True
    candidates = {value.casefold() for value in host.addresses + host.hostnames}
    return any(value.casefold() in candidates for value in filters.hosts)


def _service_matches(service: ServiceSummary, filters: SummaryFilters) -> bool:
    if filters.ports and service.port not in set(filters.ports):
        return False
    if filters.services and service.service_name.casefold() not in {
        value.casefold() for value in filters.services
    }:
        return False
    return True


def _service_detail(service: ServiceSummary) -> str:
    details = [value for value in [service.product, service.version] if value]
    return f" ({' '.join(details)})" if details else ""


def build_summary(input_path: Path, filters: SummaryFilters | None = None) -> SummaryResult:
    summary_filters = filters or SummaryFilters()
    payload = _read_json(input_path)
    hosts_payload = payload.get("hosts")
    if not isinstance(hosts_payload, list):
        hosts_payload = []

    hosts: list[HostSummary] = []
    for host in hosts_payload:
        if not isinstance(host, dict):
            continue
        addresses: list[str] = []
        mac_addresses: list[MacAddressSummary] = []
        for address in host.get("addresses", []):
            if not isinstance(address, dict):
                continue
            raw_address = address.get("address")
            if not isinstance(raw_address, str) or not raw_address:
                continue
            if address.get("type") == "mac":
                vendor = address.get("vendor")
                mac_addresses.append(
                    MacAddressSummary(
                        address=raw_address,
                        vendor=vendor if isinstance(vendor, str) and vendor else None,
                    )
                )
                continue
            addresses.append(raw_address)

        hostnames = sorted(
            {
                hostname.get("name")
                for hostname in host.get("hostnames", [])
                if isinstance(hostname, dict)
                and isinstance(hostname.get("name"), str)
                and hostname.get("name")
            }
        )

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

        open_services: list[ServiceSummary] = []
        for port in open_ports_payload:
            port_number = port.get("port")
            protocol = port.get("protocol", "unknown")
            service = port.get("service")
            service_name = (
                service.get("name")
                if isinstance(service, dict) and isinstance(service.get("name"), str)
                else "unknown"
            )
            product = (
                service.get("product")
                if isinstance(service, dict)
                and isinstance(service.get("product"), str)
                and service.get("product")
                else None
            )
            version = (
                service.get("version")
                if isinstance(service, dict)
                and isinstance(service.get("version"), str)
                and service.get("version")
                else None
            )

            open_services.append(
                ServiceSummary(
                    port=port_number if isinstance(port_number, int) else None,
                    protocol=str(protocol),
                    service_name=service_name,
                    product=product,
                    version=version,
                )
            )

        filtered_host = HostSummary(
            addresses=addresses,
            hostnames=hostnames,
            mac_addresses=mac_addresses,
            open_services=[entry for entry in open_services if _service_matches(entry, summary_filters)],
        )
        if _host_matches(filtered_host, summary_filters):
            hosts.append(filtered_host)

    return SummaryResult(scan_metadata=_extract_scan_metadata(payload), hosts=hosts)


def format_summary_text(result: SummaryResult) -> str:
    lines = [f"Hosts found: {len(result.hosts)}"]
    if result.scan_metadata:
        lines.append("")
        lines.append("Scan metadata:")
        for key in sorted(result.scan_metadata):
            lines.append(f"  {key}: {result.scan_metadata[key]}")
    for index, host in enumerate(result.hosts, start=1):
        lines.append("")
        lines.append(f"Host {index}: {', '.join(host.addresses) or 'unknown'}")
        if host.hostnames:
            lines.append(f"Hostnames: {', '.join(host.hostnames)}")
        if host.mac_addresses:
            formatted_mac_addresses = ", ".join(
                [
                    f"{entry.address} ({entry.vendor})" if entry.vendor else entry.address
                    for entry in host.mac_addresses
                ]
            )
            lines.append(f"MAC addresses: {formatted_mac_addresses}")
        lines.append(f"Open ports: {len(host.open_services)}")
        lines.extend(
            f"  {entry.port}/{entry.protocol}: {entry.service_name}{_service_detail(entry)}"
            for entry in host.open_services
        )
    lines.append("")
    lines.append("Note: These are observed Nmap service data, not confirmed vulnerabilities.")
    return "\n".join(lines)


def format_summary_markdown(result: SummaryResult) -> str:
    lines = ["# RECONMIND Summary", "", f"## Hosts found: {len(result.hosts)}"]
    if result.scan_metadata:
        lines.extend(["", "## Scan metadata"])
        for key in sorted(result.scan_metadata):
            lines.append(f"- **{key}**: {result.scan_metadata[key]}")

    for index, host in enumerate(result.hosts, start=1):
        lines.extend(["", f"### Host {index}: {', '.join(host.addresses) or 'unknown'}"])
        if host.hostnames:
            lines.append(f"- Hostnames: {', '.join(host.hostnames)}")
        if host.mac_addresses:
            lines.append(
                "- MAC addresses: "
                + ", ".join(
                    [
                        f"{entry.address} ({entry.vendor})" if entry.vendor else entry.address
                        for entry in host.mac_addresses
                    ]
                )
            )
        lines.append(f"- Open ports: {len(host.open_services)}")
        if host.open_services:
            lines.extend(
                [
                    "",
                    "| Port | Protocol | Service | Product/Version |",
                    "| --- | --- | --- | --- |",
                ]
            )
            for entry in host.open_services:
                detail = " ".join([value for value in [entry.product, entry.version] if value]) or "-"
                port = entry.port if entry.port is not None else "unknown"
                lines.append(f"| {port} | {entry.protocol} | {entry.service_name} | {detail} |")
        else:
            lines.extend(["", "_No matching open services._"])
    lines.extend(
        [
            "",
            "Note: These are observed Nmap service data, not confirmed vulnerabilities.",
        ]
    )
    return "\n".join(lines)


def format_summary_json(result: SummaryResult) -> str:
    payload = {
        "hosts_found": len(result.hosts),
        "scan_metadata": result.scan_metadata,
        "hosts": [
            {
                "index": index,
                "addresses": host.addresses,
                "hostnames": host.hostnames,
                "mac_addresses": [
                    {"address": mac.address, **({"vendor": mac.vendor} if mac.vendor else {})}
                    for mac in host.mac_addresses
                ],
                "open_services": [
                    {
                        "port": entry.port,
                        "protocol": entry.protocol,
                        "service": entry.service_name,
                        **({"product": entry.product} if entry.product else {}),
                        **({"version": entry.version} if entry.version else {}),
                    }
                    for entry in host.open_services
                ],
            }
            for index, host in enumerate(result.hosts, start=1)
        ],
        "note": "These are observed Nmap service data, not confirmed vulnerabilities.",
    }
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def format_summary(result: SummaryResult, output_format: str = "text") -> str:
    if output_format == "text":
        return format_summary_text(result)
    if output_format == "markdown":
        return format_summary_markdown(result)
    if output_format == "json":
        return format_summary_json(result)
    raise SummaryError(f"Unsupported summarize format: {output_format}")


def write_summary_output(report: str, output_path: Path) -> None:
    parent = output_path.parent
    try:
        if parent.exists() and not parent.is_dir():
            raise SummaryOutputError(f"Output directory path is not a directory: {parent}")
        parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise SummaryOutputError(f"Failed to create output directory '{parent}': {exc}") from exc

    try:
        output_path.write_text(report, encoding="utf-8")
    except OSError as exc:
        raise SummaryOutputError(f"Failed to write output file '{output_path}': {exc}") from exc
