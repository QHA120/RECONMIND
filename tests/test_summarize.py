import json
from pathlib import Path

import pytest
from reconmind.cli import main


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
                    {
                        "port": 80,
                        "protocol": "tcp",
                        "state": "open",
                        "service": {"name": "http"},
                    },
                    {
                        "port": 22,
                        "protocol": "tcp",
                        "state": "open",
                        "service": {"name": "ssh", "product": "OpenSSH", "version": "9.2p1"},
                    },
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
        "Hosts found: 1\n"
        "\n"
        "Host 1: 192.0.2.10\n"
        "Open ports: 2\n"
        "  22/tcp: ssh (OpenSSH 9.2p1)\n"
        "  80/tcp: http\n"
        "\n"
        "Note: These are observed Nmap service data, not confirmed vulnerabilities.\n"
    )


def test_cli_summarize_no_hosts(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    input_path = tmp_path / "empty.json"
    input_path.write_text('{"hosts": []}', encoding="utf-8")

    exit_code = main(["--log-level", "ERROR", "summarize", "--input", str(input_path)])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.err == ""
    assert captured.out == (
        "Hosts found: 0\n"
        "\n"
        "Note: These are observed Nmap service data, not confirmed vulnerabilities.\n"
    )


def test_cli_summarize_missing_optional_fields(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    payload = {
        "hosts": [
            {
                "addresses": [{"address": "198.51.100.20"}],
                "ports": [{"port": 443, "protocol": "tcp", "state": "open"}],
            }
        ]
    }
    input_path = tmp_path / "minimal.json"
    input_path.write_text(json.dumps(payload), encoding="utf-8")

    exit_code = main(["--log-level", "ERROR", "summarize", "--input", str(input_path)])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.err == ""
    assert "Host 1: 198.51.100.20" in captured.out
    assert "Open ports: 1" in captured.out
    assert "  443/tcp: unknown" in captured.out


def test_cli_summarize_missing_input_returns_error(capsys: pytest.CaptureFixture) -> None:
    exit_code = main(
        [
            "--log-level",
            "ERROR",
            "summarize",
            "--input",
            "/tmp/does-not-exist.json",
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 2
    assert captured.out == ""
    assert "Error: Input file does not exist" in captured.err


def test_cli_summarize_invalid_json_returns_error(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
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
