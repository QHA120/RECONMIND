# Isolated Lab Setup

**Validation date:** October 2, 2026

## Safety requirement

The lab must remain isolated from the normal Wi-Fi network. Vulnerable VMs must not use bridged networking through `en0`.

## Host network observed

The Mac host was observed on Wi-Fi network `192.168.18.0/24` with host address `192.168.18.19` and gateway `192.168.18.1`.

This is separate from the RECONMIND lab network.

## Lab network

The validated VirtualBox host-only network is:

```text
Network: 192.168.56.0/24
Kali:    192.168.56.101
Target:  192.168.56.102
```

Kali uses `eth1` for the lab network and has the route:

```text
192.168.56.0/24 dev eth1
```

## Validated systems

| System | Address | Role | Validation |
|---|---:|---|---|
| Kali Linux | 192.168.56.101 | Authorized scanner | Interface and route observed |
| Metasploitable 2 | 192.168.56.102 | Intentionally vulnerable lab target | Nmap service scan and VirtualBox MAC observed |
| VirtualBox host/DHCP-related address | 192.168.56.100 | Infrastructure address; not a target | Discovered by host discovery |

## Validated reconnaissance

Host discovery was run only against the isolated lab subnet:

```text
nmap -sn 192.168.56.0/24
```

A light service/version scan was run only against the confirmed Metasploitable target:

```text
nmap -sV --version-light -T3 -oX /tmp/metasploitable.xml 192.168.56.102
```

The scan identified multiple services, including FTP, SSH, Telnet, HTTP, SMB, MySQL, PostgreSQL, VNC, Java RMI, and Tomcat. These are reconnaissance observations and are not automatically treated as confirmed vulnerabilities.

## Recommended VM configuration

For the initial demonstration, run only:

1. Kali
2. Metasploitable 2
3. One Windows target later, after its network is changed to the isolated host-only adapter

Kali may have a separate NAT adapter for updates if required. Vulnerable targets should use only the host-only lab adapter unless a documented exception is approved.

## Not yet validated

- Windows target addresses
- All VM adapter changes
- Mac-to-lab application data transfer
- Whether the host-only network DHCP range is stable after reboot
- Full multi-target demonstration
