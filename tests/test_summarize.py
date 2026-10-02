import json
from pathlib import Path

import pytest
from reconmind.cli import main


def _write_scan(tmp_path: Path) -> Path:
    input_path = tmp_path / "scan.json"
    input_path.write_text(
        json.dumps(
            {
                "hosts": [
                    {
                        "addresses": [{"address": "192.0.2.10", "type": "ipv4"}],
                        "ports": [
                            {"port": 22, "protocol": "tcp", "state": "open", "service": {"name": "ssh"}},
                            {"port": 80, "protocol": "tcp", "state": "open", "service": {"name": "http"}},
                        ],
                    },
                    {
                        "addresses": [{"address": "192.0.2.20", "type": "ipv4"}],
                        "ports": [
                            {"port": 443, "protocol": "tcp", "state": "open", "service": {"name": "https"}},
                        ],
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    return input_path


def test_cli_summarize_representative_payload(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    payload = {
        "hosts": [
            {
                "addresses": [
                    {"address": "192.0.2.10", "type": "ipv4"},
                    {"address": "08:00:27:AA:BB:CC", "type": "mac"},
                ],
                "ports": [
                    {"port": 80, "protocol": "tcp", "state": "open", "service": {"name": "http"}},
                    {"port": 22, "protocol": "tcp", "state": "open", "service": {"name": "ssh", "product": "OpenSSH", "version": "9.2p1"}},
                    {"port": 443, "protocol": "tcp", "state": "closed"},
                ],
            }
        ]
    }
    input_path = tmp_path / "scan.json"
    input_path.write_text(json.dumps(payload), encoding="utf-8")
    exit_code = main(["--log-level", "ERROR", "summarize", "--input", str(input_path)])
    captured = capsys.readouterr()
    assert exit_code == 0
    assert captured.err == ""
    assert captured.out == (
        "Hosts found: 1\n\nHost 1: 192.0.2.10\nOpen ports: 2\n"
        "  22/tcp: ssh (OpenSSH 9.2p1)\n  80/tcp: http\n\n"
        "Note: These are observed Nmap service data, not confirmed vulnerabilities.\n"
    )


def test_cli_summarize_no_hosts(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    input_path = tmp_path / "empty.json"
    input_path.write_text('{"hosts": []}', encoding="utf-8")
    exit_code = main(["--log-level", "ERROR", "summarize", "--input", str(input_path)])
    captured = capsys.readouterr()
    assert exit_code == 0
    assert captured.err == ""
    assert captured.out == "Hosts found: 0\n\nNote: These are observed Nmap service data, not confirmed vulnerabilities.\n"


def test_cli_summarize_missing_optional_fields(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    input_path = tmp_path / "minimal.json"
    input_path.write_text(json.dumps({"hosts": [{"addresses": [{"address": "198.51.100.20"}], "ports": [{"port": 443, "protocol": "tcp", "state": "open"}]}]}), encoding="utf-8")
    exit_code = main(["--log-level", "ERROR", "summarize", "--input", str(input_path)])
    captured = capsys.readouterr()
    assert exit_code == 0
    assert captured.err == ""
    assert "Host 1: 198.51.100.20" in captured.out
    assert "Open ports: 1" in captured.out
    assert "  443/tcp: unknown" in captured.out


def test_cli_summarize_missing_input_returns_error(capsys: pytest.CaptureFixture) -> None:
    exit_code = main(["--log-level", "ERROR", "summarize", "--input", "/tmp/does-not-exist.json"])
    captured = capsys.readouterr()
    assert exit_code == 2
    assert captured.out == ""
    assert "Error: Input file does not exist" in captured.err


def test_cli_summarize_invalid_json_returns_error(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    bad_json = tmp_path / "bad.json"
    bad_json.write_text("{", encoding="utf-8")
    exit_code = main(["--log-level", "ERROR", "summarize", "--input", str(bad_json)])
    captured = capsys.readouterr()
    assert exit_code == 2
    assert captured.out == ""
    assert "Error: Invalid JSON" in captured.err


def test_cli_summarize_requires_input_argument() -> None:
    with pytest.raises(SystemExit):
        main(["summarize"])


def test_cli_summarize_markdown_format(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    input_path = _write_scan(tmp_path)
    exit_code = main(["--log-level", "ERROR", "summarize", "--input", str(input_path), "--format", "markdown"])
    captured = capsys.readouterr()
    assert exit_code == 0
    assert captured.err == ""
    assert "# RECONMIND Summary" in captured.out
    assert "| 22/tcp: ssh |" in captured.out


def test_cli_summarize_json_format_is_valid_json(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    input_path = _write_scan(tmp_path)
    exit_code = main(["--log-level", "ERROR", "summarize", "--input", str(input_path), "--format", "json"])
    captured = capsys.readouterr()
    assert exit_code == 0
    report = json.loads(captured.out)
    assert report["hosts_found"] == 2
    assert report["hosts"][0]["open_ports"] == ["22/tcp: ssh", "80/tcp: http"]


def test_cli_summarize_writes_output_and_creates_parent_directory(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    input_path = _write_scan(tmp_path)
    output_path = tmp_path / "reports" / "nested" / "summary.md"
    exit_code = main(["--log-level", "ERROR", "summarize", "--input", str(input_path), "--format", "markdown", "--output", str(output_path)])
    captured = capsys.readouterr()
    assert exit_code == 0
    assert captured.out == ""
    assert captured.err == ""
    assert output_path.read_text(encoding="utf-8").startswith("# RECONMIND Summary")


def test_cli_summarize_output_failure_returns_error(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    input_path = _write_scan(tmp_path)
    output_parent = tmp_path / "not-a-directory"
    output_parent.write_text("file", encoding="utf-8")
    exit_code = main(["--log-level", "ERROR", "summarize", "--input", str(input_path), "--output", str(output_parent / "summary.txt")])
    captured = capsys.readouterr()
    assert exit_code == 2
    assert captured.out == ""
    assert "Error:" in captured.err


def test_cli_summarize_host_filter(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    input_path = _write_scan(tmp_path)
    exit_code = main(["--log-level", "ERROR", "summarize", "--input", str(input_path), "--host", "192.0.2.20"])
    captured = capsys.readouterr()
    assert exit_code == 0
    assert "Hosts found: 1" in captured.out
    assert "Host 1: 192.0.2.20" in captured.out
    assert "192.0.2.10" not in captured.out


def test_cli_summarize_port_and_service_filters_are_composable(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    input_path = _write_scan(tmp_path)
    exit_code = main(["--log-level", "ERROR", "summarize", "--input", str(input_path), "--port", "80", "--service", "HTTP"])
    captured = capsys.readouterr()
    assert exit_code == 0
    assert "Hosts found: 1" in captured.out
    assert "80/tcp: http" in captured.out
    assert "22/tcp" not in captured.out
    assert "192.0.2.20" not in captured.out


def test_cli_summarize_invalid_port_returns_parser_error(tmp_path: Path) -> None:
    input_path = _write_scan(tmp_path)
    with pytest.raises(SystemExit):
        main(["summarize", "--input", str(input_path), "--port", "70000"])
