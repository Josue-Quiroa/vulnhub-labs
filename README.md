# VulnHub labs

Notas reorganizadas a partir de un export sucio de Joplin. El objetivo no es un walkthrough de copiar y pegar: es dejar por escrito **qué superficie existía**, **qué identidad se obtuvo** y **qué premisa de confianza se rompió**.

| Lab | Serie | Foothold | Movimiento / root |
| --- | --- | --- | --- |
| [SickOs 1.1](labs/sickos-1.1.md) | SickOs | Squid → WolfCMS (upload autenticado) | Cron `connect.py` writable / reutilización de password SQL |
| [Raven 2](labs/raven-2.md) | Raven | PHPMailer CVE-2016-10033 | MySQL `FILE` + UDF |
| [Symfonos 3](labs/symfonos-3.md) | Symfonos | CGI + Shellshock | Grupo `pcap` → sniff loopback → `hades` |

Fuente original: VulnHub. Entorno de laboratorio. No hay sistemas de producción involucrados.

## Cómo leer cada nota

Cada writeup responde las mismas preguntas, en este orden:

1. **Qué escuchaba el host** y qué plano de autenticación abre cada servicio.
2. **Qué hipótesis se formuló** y si murió o se confirmó.
3. **Qué secreto o contexto de seguridad se obtuvo** (usuario web, hash SQL, credencial FTP en claro).
4. **Por qué el protocolo o la app lo aceptó**.
5. **Callejones sin salida** — igual de importantes que el path que funcionó.

Las capturas de Joplin (`_resources/*.png`) no viajaron con el texto. Cuando se reexporten, van en `labs/<box>/img/`.

## Convención

- Un `.md` por máquina.
- Sin payloads listos para disparar. Si hace falta ilustrar un mecanismo, se describe el contrato que se abusó (header CGI, argumento de `sendmail`, privilegio `FILE` de MySQL, bit de grupo `pcap`).
- Credenciales de laboratorio se mencionan porque el box las pone a propósito. No reutilizar ese hábito en un engagement real.
