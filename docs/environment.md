# Environment Audit

**Audit date:** October 2, 2026

## Host system

| Item | Observed result | Status |
|---|---|---|
| Operating system | macOS 14.8.9, build 23J631 | Suitable |
| Architecture | Intel x86_64 | Suitable |
| CPU | 8 cores, Intel Kabylake | Suitable |
| Memory | 16 GB | Suitable |
| Free disk space | Approximately 12 GB at audit time | Limited; monitor before adding VMs or local AI models |
| Command Line Tools | `/Library/Developer/CommandLineTools` | Installed |
| Clang | Apple clang 15.0.0 | Installed |

## Development tools

| Tool | Observed result | Decision |
|---|---|---|
| Python | 3.14.7 at `/usr/local/opt/python@3.14/bin/python3.14` | Use a project virtual environment; verify package compatibility |
| pip | 26.2.1 | Available |
| venv | Available | Use for initial development |
| Git | 2.39.3 | Available |
| Homebrew | 7.0.7 at `/usr/local` | Available |
| Node.js | 24.18.0 | Available; frontend deferred initially |
| npm | 11.16.0 | Available; frontend deferred initially |
| Docker | Not installed | Deferred; not required for MVP |
| Nmap on macOS | Not installed | Intentionally deferred; Nmap runs in Kali |
| Nmap in Kali | 7.99 | Required scanner available |
| VirtualBox | 7.2.16r174877 | Available |

## Virtual machines discovered

- Kali
- Windows XP
- Windows7
- Win server 2008
- Metasploitable 2
- Victim Windows 10
- Windows Server 2012

The VM configurations showed that several vulnerable systems were previously using bridged networking. They must not be used in that state for this project. Vulnerable targets should use the isolated host-only lab network.

## Architecture decision

The initial RECONMIND backend will run on the Mac host where practical, while Kali performs reconnaissance inside the isolated lab. The first data flow is:

```text
Kali Nmap scan -> XML artifact -> RECONMIND parser -> structured data -> analysis
```

Docker and a separate Ubuntu development VM are deferred until a concrete compatibility or deployment need is demonstrated.

## Checklist

- [x] macOS, architecture, CPU, and RAM audited
- [x] Python, pip, and venv verified
- [x] Git and Homebrew verified
- [x] Node.js and npm verified
- [x] VirtualBox and VM inventory verified
- [x] Kali Nmap 7.99 verified
- [x] Isolated lab network validated
- [ ] Nmap XML copied into the repository data area
- [ ] Python dependency compatibility tested
- [ ] RECONMIND virtual environment created
- [ ] Application implementation started

## Limitations

This document records observed environment information only. It does not claim that Docker, macOS Nmap, a local LLM, or all listed VMs are installed, configured, or currently running.
