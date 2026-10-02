# Evidence Index

Evidence files must be captured from actual commands or application output. Do not fabricate screenshots or results.

| ID | Filename | Phase | What it proves | Repository location |
|---|---|---:|---|---|
| E01 | `01-environment.png` | 0 | Host versions, resources, and installed tools | `evidence/phase-01/` |
| E02 | `01-environment-details.png` | 0 | Python packaging and VirtualBox VM inventory | `evidence/phase-01/` |
| E03 | `01-kali-nmap.png` | 1 | Nmap 7.99 is available in Kali | `evidence/phase-01/` |
| E04 | `02-kali-network.png` | 1 | Kali has `192.168.56.101/24` on `eth1` | `evidence/phase-01/` |
| E05 | `03-isolated-host-discovery.png` | 1 | Three hosts responded on the isolated lab subnet | `evidence/phase-01/` |
| E06 | `04-metasploitable-service-scan.png` | 1 | Authorized target service discovery completed | `evidence/phase-01/` |
| E07 | `05-nmap-xml-output.png` | 1 | Nmap XML artifact exists and contains scan metadata | `evidence/phase-01/` |

## Evidence handling

Screenshots are currently reported as captured during the interactive session. They must be added to the repository by the project owner; this repository update does not fabricate or upload image files.

The XML artifact should be copied from Kali into `data/raw/` only after transfer is configured and the file is reviewed for sensitive information.
