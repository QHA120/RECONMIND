# RECONMIND

AI-Assisted Attack Surface Intelligence & Authorized Pentest Copilot.

RECONMIND is a defensive security research project designed to analyze structured reconnaissance data from explicitly authorized systems in an isolated VirtualBox lab. It is not an autonomous exploitation platform.

## Current status

Phase 0 environment audit and initial Phase 1 lab validation are complete.
Phase 2 now includes a minimal CLI MVP for Nmap XML ingestion.

Validated:

- Intel Mac host running macOS 14.8.9
- VirtualBox 7.2.16
- Kali Linux scanner with Nmap 7.99
- Isolated VirtualBox network `192.168.56.0/24`
- Kali at `192.168.56.101`
- Metasploitable 2 at `192.168.56.102`
- Nmap XML output generated for the authorized Metasploitable target

Not yet implemented:

- Database
- Dashboard
- AI provider integration
- Automated report generation

## Phase 2 CLI MVP (Nmap XML import)

### Safety and authorization warning

Use this tool only on systems where you have explicit authorization. The MVP imports observed scan artifacts and does **not** run autonomous scanning. Service observations are not equivalent to confirmed vulnerabilities.

### Setup

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

### Import command

```bash
python -m reconmind import-nmap --input data/raw/metasploitable.xml --output data/processed/metasploitable.json
```

For the sanitized test fixture:

```bash
python -m reconmind import-nmap --input tests/fixtures/sanitized_nmap.xml --output data/processed/sanitized_nmap.json
```

### Summarize imported JSON

Text output remains the default:

```bash
python -m reconmind summarize --input data/processed/metasploitable.json
```

Generate a structured Markdown report:

```bash
python -m reconmind summarize \
  --input data/processed/metasploitable.json \
  --format markdown \
  --output reports/metasploitable.md
```

Generate machine-readable JSON:

```bash
python -m reconmind summarize \
  --input data/processed/metasploitable.json \
  --format json \
  --output reports/metasploitable.json
```

Without `--output`, the selected report is written to standard output. Output files create missing parent directories automatically. Logs are kept separate from report content, so JSON and Markdown reports can be redirected or saved safely.

This summary is deterministic observed Nmap service data and is not a confirmed vulnerability assessment.

### Expected JSON content

The output JSON preserves observed data and includes:

- Scan metadata (`scanner`, `args`, timing, runstats)
- Hosts and addresses
- Ports and protocols
- Service names/products/versions when present
- Source/evidence metadata showing where the artifact came from

## Safety boundary

Use RECONMIND only against localhost, the private VirtualBox lab, or systems for which explicit authorization exists. Do not scan the public Internet or networks that you do not own or have permission to test.

## Roadmap

1. Environment and lab validation
2. CLI MVP and safe Nmap XML ingestion
3. Deterministic attack-surface analysis
4. Attack-surface graph
5. Web dashboard
6. AI analysis abstraction
7. Human approval workflow
8. Safe validation modules
9. Evidence and reporting
10. Security hardening and portfolio demonstration
