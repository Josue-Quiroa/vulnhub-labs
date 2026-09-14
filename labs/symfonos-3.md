# Symfonos 3

VulnHub: [Symfonos: 3](https://www.vulnhub.com/entry/symfonos-3,332/)

## Superficie

Tres puertos: HTTP, FTP, SSH.

HTTP. `/gate/cerberus` es una imagen, no un panel. La primera pasada de ffuf no saca más. La segunda encuentra `/cgi-bin`. Sin slash final el árbol se ve distinto: Apache suele devolver 403 en `/cgi-bin` y 200 en `/cgi-bin/algo`. `/cgi-bin/underworld` no es una página; corre vía `mod_cgi` y responde algo tipo `uptime`.

FTP. Banner Debian. Anonymous fallido. Sin listado. El plano vuelve a importar cuando se captura loopback.

SSH. Banner viejo. Enum y exploit remoto no pagan. El login entra cuando hay password de usuario.

## Acceso inicial: Shellshock

Apache lanza el CGI, copia headers HTTP a variables de entorno (`User-Agent` → `HTTP_USER_AGENT`) y hace `exec` del script.

CVE-2014-6271 está en Bash, no en Apache. Si el valor de una variable empieza como función `() { :; };`, Bash ejecutaba el código que iba detrás al importar el entorno. Cualquier script con `#!/bin/bash` (o que invoque bash) y entorno controlado por el cliente le da ese canal.

En Caido, `User-Agent: () { :; }; whoami` cambia la respuesta. El callback nace como `cerberus`, el uid del CGI. Una shell “ya TTY” solo quiere decir que el payload lanzó bash interactivo.

## cerberus → hades

LSE como `cerberus`:

- grupo `pcap`
- `tcpdump` con `CAP_NET_RAW` / `CAP_NET_ADMIN`
- un job root periódico: `curl` a `127.0.0.1` y `/opt/ftpclient/ftpclient.py` hablando FTP contra localhost
- `fst140`: `/var/mail/hades` readable
- `/srv/ftp` + `statuscheck.txt` como otro extremo del check

`pcap` + raw sockets permite ver frames que no son del proceso. El tráfico útil está en `lo`, no en la LAN. FTP manda `USER` y `PASS` en claro. El par `hades:<password>` sale del stream. SSH como `hades` cambia de contexto: de CGI a sesión de usuario.

El loopback es privado respecto de otros hosts. No lo es respecto de otro uid en el mismo kernel con packet socket.

## hades → root

LSE como `hades`:

1. `hades` está en el grupo `gods`
2. buena parte de `/usr/lib/python2.7/` es escribible por ese grupo, incluido `ftplib.py` y el symlink `sitecustomize.py` → `/etc/python2.7/sitecustomize.py`
3. root lanza `/usr/bin/python2.7 /opt/ftpclient/ftpclient.py`
4. el script hace `import ftplib` y después `ftplib.FTP(...)` contra localhost

No es cwd-hijack (`sys.path[0] == ''` + un `ftplib.py` al lado del script). Se puede escribir la stdlib que el intérprete privilegiado va a cargar.

El UID lo pone el proceso que importa, no el dueño del fichero. El mismo `sitecustomize.py` corre como `hades` o como root según quién arranque Python.

| Orden | Método | Efecto colateral |
| --- | --- | --- |
| 1 | `sitecustomize.py` | no toca la stdlib |
| 2 | parche mínimo de `ftplib.py` (dejar un stub de `FTP`) | el script no muere con `AttributeError` |
| 3 | romper `ftplib.py` entero | tumba el job y cualquier otro consumidor |

`sitecustomize` lo carga el módulo `site` al arrancar el intérprete, antes de `ftpclient.py`. `python -S` se lo salta. El cron no usa `-S` (se ve en `ps` o en `sys.flags.no_site`).

Un `import` inválido en `ftplib` (`os.sys` vs `os, sys`) demuestra que se está cargando el archivo tocado. También deja la caja inestable.

Python puede preferir un `.pyc` más nuevo si el `.py` desapareció o es más viejo. Cuando root importa, suele regenerar el `.pyc` como root. La pregunta útil es `modulo.__file__`, no “¿existe el `.py`?”.

Una prueba local (efecto en disco, sin red) confirma que el hook corre como root antes de pelear el callback. `nc -e` no es oráculo: el binario no existe igual en todas las distros.

Lo que falla no es “Python”. Es la premisa de que un job root puede importar la stdlib porque esa stdlib es de root. El grupo `gods` rompe esa premisa. El cron solo arranca el intérprete con UID 0.

## Callejones

- `/gate/cerberus`: decorado
- FTP anónimo: cerrado
- SSH sin password: cerrado
- ffuf sobre CGI sin slash final: falso negativo
- SUID de `passwd` / `su` / `mount` / `exim4`: LSE no marca uncommon setuid
- cwd-hijack en `/opt/ftpclient`: razonable, no era el hueco abierto
- destruir `ftplib.py`: PoC sucia
