# VulnHub labs

Writeups de cómo se resolvieron tres máquinas de laboratorio. Cadena completa: superficie, acceso inicial, movimiento y root.

| Lab | Serie | Foothold | Movimiento / root |
| --- | --- | --- | --- |
| [SickOs 1.1](labs/sickos-1.1.md) | SickOs | Squid → WolfCMS (upload autenticado) | Cron `connect.py` writable / reutilización de password SQL |
| [Raven 2](labs/raven-2.md) | Raven | PHPMailer CVE-2016-10033 | MySQL `FILE` + UDF |
| [Symfonos 3](labs/symfonos-3.md) | Symfonos | CGI + Shellshock | `pcap` → sniff loopback → `hades` → grupo `gods` + Python `sitecustomize` |

Fuente: VulnHub. Entorno aislado. No hay sistemas de producción.

Cada nota sigue el mismo orden: qué escuchaba el host, qué se probó, qué identidad salió, por qué el servicio lo aceptó, y qué caminos no pagaron.
