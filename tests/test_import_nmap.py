from pathlib import Path

import pytest
from reconmind.cli import main
from reconmind.nmap_import import (
    InputValidationError,
    MalformedXMLError,
    parse_nmap_xml,
)

FIXTURE = Path(__file__).parent / "fixtures" / "sanitized_nmap.xml"


def test_parse_host_and_service_data() -> None:
    result = parse_nmap_xml(FIXTURE)

    assert result.payload["scan"]["scanner"] == "nmap"
    assert result.payload["scan"]["runstats"]["hosts_total"] == "1"

    host = result.payload["hosts"][0]
    assert host["addresses"][0]["address"] == "192.0.2.10"

    ports = {entry["port"]: entry for entry in host["ports"]}
    assert ports[22]["service"]["name"] == "ssh"
    assert ports[22]["service"]["product"] == "OpenSSH"
    assert ports[80]["service"]["version"] == "1.24.0"


def test_malformed_xml_error(tmp_path: Path) -> None:
    bad_xml = tmp_path / "bad.xml"
    bad_xml.write_text("<nmaprun><host></nmaprun>", encoding="utf-8")

    with pytest.raises(MalformedXMLError):
        parse_nmap_xml(bad_xml)


def test_missing_input_error(tmp_path: Path) -> None:
    missing = tmp_path / "missing.xml"

    with pytest.raises(InputValidationError):
        parse_nmap_xml(missing)


def test_cli_writes_json_output(tmp_path: Path) -> None:
    output = tmp_path / "processed" / "scan.json"

    exit_code = main(
        [
            "import-nmap",
            "--input",
            str(FIXTURE),
            "--output",
            str(output),
        ]
    )

    assert exit_code == 0
    assert output.exists()
    assert '"hosts"' in output.read_text(encoding="utf-8")


def test_output_directory_creation_failure(tmp_path: Path) -> None:
    fake_dir = tmp_path / "not_a_directory"
    fake_dir.write_text("block", encoding="utf-8")
    output = fake_dir / "scan.json"

    exit_code = main(
        [
            "import-nmap",
            "--input",
            str(FIXTURE),
            "--output",
            str(output),
        ]
    )

    assert exit_code == 2


def test_reject_non_xml_input(tmp_path: Path) -> None:
    input_file = tmp_path / "scan.txt"
    input_file.write_text("not xml", encoding="utf-8")
    output = tmp_path / "out.json"

    exit_code = main(
        [
            "import-nmap",
            "--input",
            str(input_file),
            "--output",
            str(output),
        ]
    )

    assert exit_code == 2
