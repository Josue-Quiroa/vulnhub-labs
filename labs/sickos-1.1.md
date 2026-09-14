# SickOs 1.1

VulnHub: [SickOs: 1.1](https://www.vulnhub.com/entry/sickos-11,132/)

Nmap 7.95 (`-Pn -n --min-rate 2000 -p 22,3128,8080 -sSVC`). El host suele ignorar ping; sin `-Pn` el scan queda vacío.

## Superficie

No hay un HTTP útil en 80 a primera vista. Lo que importa es Squid en 3128, con SSH al lado.

| Puerto | Estado | Servicio | Nota |
| --- | --- | --- | --- |
| 22/tcp | open | OpenSSH 5.9p1 Debian 5ubuntu1.1 | Ubuntu 12.04 Precise. No fue el foothold. |
| 3128/tcp | open | Squid 3.1.19 | Forward proxy. Nmap marca *Potentially OPEN proxy*. Métodos vistos: `GET` y `HEAD`. |
| 8080/tcp | closed | http-proxy | Cerrado desde fuera. No prueba que no exista HTTP interno. |

Squid filtra el acceso al origen. Sin proxy, el sitio parece muerto. Con el cliente apuntando a 3128 (`-x`, `--useproxy` o proxy del browser), el mismo request saca `robots.txt`, `/wolfcms` y el panel.

El request-line cambia: el cliente manda `GET http://<origen>/ruta HTTP/1.1` al proxy y Squid abre la conexión al origen. Pedir `http://<IP>:3128/` a pelo devuelve el error page de Squid (`The requested URL could not be retrieved`, header `squid/3.1.19`). Eso confirma el proxy, no la aplicación.

Solo se vieron `GET` y `HEAD`. No hay evidencia de `CONNECT` ni de un túnel TCP genérico. El origen, una vez se habla a través de Squid, es Apache 2.2 + PHP 5.3 de Precise.

Enumeración detrás del proxy:

- `robots.txt` permitido
- `/wolfcms` alcanzable
- `/docs/` con un txt de versión (`3800.txt` / exception) que apunta al panel admin
- `/cgi-bin/status` existe (Shellshock plausible en Precise) y no se usó

SSH queda para más tarde. El usuario `sickos` existe; el login interactivo llega por reutilización de secreto, no por el banner.

## Acceso inicial: WolfCMS

Credenciales por defecto: `admin:admin`. El file manager deja subir un PHP a `/wolfcms/public`, que es document root. Apache interpreta el archivo. El upload es solo el canal de escritura; el RCE es que Apache ejecuta el PHP que quedó en un path web.

Sesión como `www-data` (uid del worker). No hay login(1): es un hijo de Apache. Hay que levantar TTY a mano.

## config.php

Mismo patrón que `wp-config.php`: el worker tiene que leer el DSN. Desde `www-data` el archivo es readable.

En la base `wolf`, tabla `users`, el hash del admin cae otra vez a `admin`. No suma identidad nueva.

El usuario/password del DSN sí importan: el mismo secreto vale para la cuenta local `sickos`.

`@@secure_file_priv = NULL` no significa “sin FILE”. Significa que no hay jaula de directorio para `LOAD_FILE` / `INTO DUMPFILE`. Un UDF pide otra terna (`FILE` + `plugin_dir` escribible + `CREATE FUNCTION ... SONAME`). Aquí no hacía falta: el cron ya ejecuta un archivo writable. Quedó un `/tmp/raptor_udf2.so` de prueba que no escala; `mysqld` corre como `mysql`, no como root.

## Root: dos caminos independientes

### A — password reuse + grupo `sudo`

`sickos` tiene shell. El password del DSN abre `su` o `ssh`. No es un bug de MySQL: es el mismo secreto en dos stores.

En Precise, `sickos` está en el grupo `sudo` (`%sudo ALL=(ALL:ALL) ALL`). No hay `NOPASSWD`. `sudo -n` falla; `sudo` + PAM contra `/etc/shadow` funciona. LSE llega a imprimir `uid=0(root)` en `sud020`. `PermitRootLogin yes` sobra si ya hay grupo sudo.

### B — cron sobre `connect.py`

`/etc/cron.d/automate`:

```text
* * * * * root /usr/bin/python /var/www/connect.py
```

Cada minuto, como root. La política es `root:root` 644; no se toca. Lo que se escribe es `/var/www/connect.py` (writable por `www-data`).

No es PATH hijack (el job usa rutas absolutas) ni wildcard de `tar`. Es overwrite del script que root ejecuta.

```text
cron (uid 0)
  └─ CRON
       └─ /bin/sh -c "/usr/bin/python /var/www/connect.py"
            └─ /usr/bin/python /var/www/connect.py    uid 0
```

Ese Python no hereda la shell de `www-data`: sin TTY, `PATH` corto, `HOME=/root`. Si el script termina, el euid 0 muere con él. Si se queda bloqueado, al minuto nace otra instancia.

`/usr/bin/python` en Precise es Python 2.7. El shebang del fichero no manda; manda el `execve` del cron. Un one-liner de Py3 (f-strings) o un `bash -i >& /dev/tcp/...` pegado dentro del `.py` muere con `SyntaxError` en syslog (`CRON[...]`), no en la TTY. Compilar antes con el mismo binario:

```text
/usr/bin/python -m py_compile /var/www/connect.py
```

En esta caja no se dejó una reverse. El tick escribe un drop-in en `/etc/sudoers.d/` para `www-data` con `NOPASSWD`, modo `0440`. `sudoers.d` ignora nombres con punto (`foo.bak`); un guión vale. Si el modo es world-writable, `sudo` descarta el fichero. Después del tick, `sudo` SUID lee la regla nueva y no pide password.

## Callejones

- Tratar 3128 como sitio web: solo el error de Squid
- `8080 closed`: no cierra HTTP interno
- `/cgi-bin/status` / Shellshock: plausible, no usado
- UDF: descartado; `mysqld` no es uid 0
- Dirty COW / kernel `3.11.0-15-generic`: hay `gcc`, no era el fallo plantado
- `umask 0000` de `www-data` solo afecta ficheros nuevos; un overwrite in-place conserva el modo del inode
