# VulnHub labs

Tres máquinas de laboratorio. En cada una: reconocimiento, acceso inicial y cómo se llegó a root.

| Lab | Foothold | Root |
| --- | --- | --- |
| [SickOs 1.1](labs/sickos-1.1.md) | Squid → WolfCMS (upload autenticado) | Cron sobre `connect.py` writable / password reuse hacia `sickos` |
| [Raven 2](labs/raven-2.md) | PHPMailer 5.2.16 (CVE-2016-10033) | MySQL `FILE` + UDF |
| [Symfonos 3](labs/symfonos-3.md) | CGI + Shellshock | `pcap` → FTP en loopback → `hades` → grupo `gods` + `sitecustomize` |

VulnHub. Red aislada. Credenciales y flags son del diseño del lab.
