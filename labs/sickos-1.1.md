# SickOs 1.1

VulnHub: [SickOs: 1.1](https://www.vulnhub.com/entry/sickos-11,132/)  
Notas origen: `Scan.md`, `Explotation.md`, `Priv Escalation.md`  
Scan de referencia: Nmap 7.95 (`-Pn -n --min-rate 2000 -p 22,3128,8080 -sSVC`). El host a menudo no responde ping; `-Pn` no es opcional en este box.

## Superficie

El scan no muestra un HTTP “normal” en 80 como primera impresión útil. Lo que importa es el **proxy Squid** junto con SSH. Inventario observado:

| Puerto | Estado | Servicio | Qué implica |
| --- | --- | --- | --- |
| 22/tcp | open | OpenSSH 5.9p1 Debian 5ubuntu1.1 | Ubuntu 12.04 Precise. Banner viejo; no fue el foothold. |
| 3128/tcp | open | Squid http proxy 3.1.19 | Forward proxy. Nmap: *Potentially OPEN proxy*. Métodos vistos: `GET` y `HEAD`. |
| 8080/tcp | closed | http-proxy | Cerrado *desde fuera*. No demuestra que no exista origen HTTP interno. |

MAC VMware: es una VM de laboratorio, no un dato de explotación.

Squid en este box no es “un puerto más”. Es un *forward proxy* que el propio host usa como filtro de acceso al origen HTTP. Sin hablarle al proxy, el origen parece muerto o vacío. Con el proxy, el mismo request revela el sitio real, `robots.txt` y `/wolfcms`.

Eso no es magia de la herramienta: el cliente HTTP cambia el request-line. En modo proxy el browser/ffuf envía `GET http://<origen>/ruta HTTP/1.1` al listener de Squid; Squid abre la conexión al origen. Si se enumera como si 80/3128 fueran un vhost directo, se mide el *error page* del proxy, no la app.

Negativos de primer contacto (fáciles de olvidar la primera vez que se ve un proxy):

- Pedir `http://<IP>:3128/` sin *request-line* de origen devuelve el error de Squid (`The requested URL could not be retrieved` / header `squid/3.1.19`). Eso confirma el proxy, no la aplicación.
- `8080/tcp closed` no cierra la hipótesis de HTTP en `:80` o en `127.0.0.1` *a través* de 3128.
- Solo se vieron `GET` y `HEAD`. No asumir `CONNECT` (túnel TLS) ni un pivot TCP genérico hasta probarlo. La enumeración útil es HTTP en claro con el cliente apuntando al proxy (`-x`, `--useproxy`, proxy del browser).

Detrás del proxy el origen es el stack de Precise: Apache 2.2.x + PHP 5.3.x. Esas versiones no se leen en el scan de 3128; aparecen en los headers del origen cuando el request va *vía* Squid.

Hallazgos de enumeración (siempre con el proxy en el medio):

- `robots.txt` permitido a través del proxy.
- `/wolfcms` alcanzable.
- Fuzzing → `/docs/` con un txt que filtra versión (`3800.txt` / exception).
- Panel admin de WolfCMS.
- Superficie CGI típica de este box (`/cgi-bin/status`) **no** fue el path usado. Queda como hipótesis de Precise + Bash viejo (Shellshock) que no se persiguió aquí. Distinta de “file manager autenticado”: no pide login del CMS; pide que el worker CGI herede variables de entorno hacia Bash.

SSH está abierto. En este path no fue el foothold. El usuario de sistema `sickos` sí existe; el acceso interactivo llegó después, por reutilización de secreto, no por el banner de `sshd`.

## Foothold: WolfCMS

WolfCMS viejo + panel de archivos. La pregunta no es “¿hay un exploit de file upload?”. La pregunta es:

> ¿El CMS trata un archivo subido por un usuario autenticado como *contenido estático servible* y lo deja bajo el document root donde Apache/PHP lo interpretan?

Condiciones que tenían que cumplirse:

1. Credencial válida en el panel. `admin:admin` no es “suerte”: es default de instalación que nadie rotó. El login demuestra que el *password store* del CMS no se endureció.
2. El plugin/file manager no separa *store* de *execute*. Subir a `/wolfcms/public` implica que esa ruta es web-accesible y que el handler PHP no está restringido por extensión/content-type de forma efectiva.
3. El worker del web server corre el intérprete sobre lo que se acaba de escribir.

El RCE no vive en “el upload”. Vive en **escribir un script en un path que el SAPI de PHP va a incluir**. El upload solo es el canal de escritura autenticado.

Identidad obtenida: `www-data` (contexto del vhost). No es un usuario de sistema interactivo; es la cuenta del worker. Por eso el TTY hay que construirlo después: no hay sesión login(1), hay un proceso hijo de Apache.

## Post-explotación: secreto en config.php

`config.php` de WolfCMS cumple el mismo rol que `wp-config.php`: el proceso web **debe** conocer el DSN de MySQL en claro (o en un secreto que el proceso pueda leer). Si el foothold es el mismo uid que el worker, ese archivo es readable por diseño.

De la base `wolf`:

- Tabla `users` con hashes.
- El hash del admin del CMS cae a `admin` — coherente con el login que ya se tenía. No es un hallazgo nuevo de identidad; es confirmación de que el password store del CMS y el de la app coinciden en mediocridad.

El secreto del DSN (usuario/password de MySQL en `config.php`) sí se anotó como material reutilizable. El valor en claro no se deja aquí a propósito; el hecho útil es que **el mismo secreto alimenta dos stores** (servicio SQL y cuenta local `sickos`).

`@@secure_file_priv` en `NULL` es fácil interpretarlo como “no se puede hacer UDF / no se puede escribir”. Esa lectura es incorrecta:

- `secure_file_priv = NULL` (o vacío, según versión) **no** significa automáticamente “sin FILE”. Significa “no hay jaula de directorio para `LOAD_FILE`/`INTO DUMPFILE`”.
- Lo que mata un UDF es otra terna: privilegio `FILE`, `plugin_dir` escribible por el uid de `mysqld`, y que el server acepte `CREATE FUNCTION ... SONAME`.
- En este box el UDF **no** era el camino usado. Correcto: no forzar MySQL si el cron ya da un writer controlado por root. Quedó un artefacto de ensayo (`/tmp/raptor_udf2.so`) que no escala: `mysqld` corre como usuario `mysql`, no como root.

## Privilegio: dos caminos, ambos cerrados

Hay que separar *identidad* (PAM / grupo `sudo`) de *código* (cron que ejecuta un artefacto escribible). Los dos funcionan en esta caja y no se necesitan entre sí.

### Path A — reutilización de secreto + grupo `sudo`

`/etc/passwd` lista `sickos` con shell. El password del DSN de MySQL (el de `config.php`) sirve para esa cuenta de sistema. El acceso puede ser `su` desde `www-data` o `ssh` contra el `sshd` ya visto; el plano que se rompe es el mismo.

Esto no es una vulnerabilidad de MySQL. Es **password reuse** entre:

- secreto de servicio (DB),
- cuenta local.

En Precise, el paquete `sudo` mete a `sickos` en el grupo `sudo` con la regla típica `%sudo ALL=(ALL:ALL) ALL`. No hay `NOPASSWD`: LSE marca *sudo without password = nope* y *sudo with password = yes*. La diferencia es `sudo -n` (falla sin ticket) frente a `sudo` + PAM (`pam_unix` contra `/etc/shadow`).

Una vez autenticado como `sickos`, `sudo` es SUID root: valida el caller, hace `setuid(0)` y `execve` del comando. LSE llegó a imprimir `uid=0(root)` en el check `sud020`. Eso no es “casi root”: es root en ese proceso.

`PermitRootLogin yes` solo importa si aparece un secreto de *root*. Aquí no hizo falta: el grupo `sudo` ya delega.

### Path B — cron + archivo que root ejecuta

LSE marca `/etc/cron.d/automate`:

```text
* * * * * root /usr/bin/python /var/www/connect.py
```

Cinco asteriscos = máscara que coincide **cada minuto**. Resolución de Vixie cron: 60 s. El sexto token en `/etc/cron.d/` es el usuario efectivo (`root`). El fichero de política es `root:root` y no se toca.

El bug no es “hay un cron”. Casi todo Linux tiene cron. El bug es la **intersección**:

- El *principal* que ejecuta el job es root.
- El *objeto* (`/var/www/connect.py`) es escribible por `www-data`.

Eso es un fallo de DAC / *confused deputy*. Root hace `execve` de un archivo cuyo contenido lo decide otro uid. No hace falta un exploit de kernel.

#### Qué clase de abuso de cron es (y cuáles no)

| Clase | Qué controlas | ¿SickOs? |
| --- | --- | --- |
| Overwrite del script | El fichero que el job ejecuta | **Sí**: `connect.py` |
| PATH hijack | Dir escribible *antes* en el `PATH` de cron y comando **sin** ruta absoluta | No: el job usa `/usr/bin/python` + ruta absoluta |
| Wildcard (`tar *`) | Nombres de fichero que el binario interpreta como flags | No |
| Escribes `/etc/cron.d` | La política | No: `automate` es 644 root |

Write-ups de “tar checkpoint” o `PATH=/home/user` no describen esta máquina.

#### Anatomía de un tick (lo que LSE cazó en `ps`)

```text
cron (uid 0, daemon)
  └─ CRON
       └─ /bin/sh -c "/usr/bin/python /var/www/connect.py"
            └─ /usr/bin/python /var/www/connect.py    uid 0
```

El entorno **no** es la shell de `www-data`:

- sin TTY
- `PATH` corto (`/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin`)
- `HOME=/root`, `SHELL=/bin/sh`
- no hereda variables de Apache

Si el script termina, euid 0 desaparece. Si bloquea (socket, loop), al minuto siguiente nace **otra** instancia. Por eso un callback persistente apila procesos root.

#### El runtime lo fija el `execve`, no el shebang

`/usr/bin/python` en Precise es un symlink a **python2.7**. Cron nombra el intérprete en la línea del job; el `#!/usr/bin/python` del fichero es cosmética.

Error real de laboratorio: meter un one-liner pensado para Py3 (f-strings, walrus, o peor: pegar `bash -i >& /dev/tcp/...` *dentro* de un `.py`). El lexer de 2.7 suelta `SyntaxError` y el job muere en milisegundos. No hay prompt. El traceback va a syslog (`CRON[...]`), no a la TTY.

Superficie 2.7 que sí parsea: `str.format()`, `with open(...)`, `0o440` (2.6+).

Antes de esperar el tick:

- compilar con **el mismo binario** que cron usa (`/usr/bin/python -m py_compile /var/www/connect.py`);
- si “no pasa nada”, mirar `/var/log/syslog` líneas `CRON`, no el shell actual.

#### Qué se inyectó (mutación de política, no reverse)

En lugar de una sesión, el script —ya como root en el tick— escribe un drop-in en `/etc/sudoers.d/` para `www-data` con `NOPASSWD` y fija modo `0440`.

Contrato que hay que respetar:

- `#includedir /etc/sudoers.d` **ignora** ficheros con `.` en el nombre (`foo.bak`). Un guión (`www-data`) vale.
- `sudo` **descarta** el drop-in si el modo es world-writable. `0440` no es adorno: es lo que hace que la regla exista para `sudo`.
- Owner acaba `root:root` porque quien hace el `open()` es el proceso del cron, no `www-data`.

Después del tick el flujo ya no es cron: `sudo` SUID lee la política nueva y PAM no pide password a `www-data`. Mismo destino (`euid=0`), huella distinta al path A.

En un engagement escribir `sudoers.d` es artefacto estable y ruidoso. En el lab sirve para demostrar uid 0 **sin** listener y **sin** pillar el PID del python.

## Callejones

- Tratar `:3128` como sitio web: solo el error page de Squid. Cerrado como origen.
- `8080/tcp closed` desde el atacante: no es evidencia de que no haya HTTP interno.
- CGI `/cgi-bin/status` / Shellshock: superficie plausible en Precise; no fue el foothold. Escribible por `www-data` = persistencia web, no privesc.
- UDF MySQL: descartado a propósito; el cron ya era writer root. Además `mysqld` no es uid 0.
- Kernel `3.11.0-15-generic` / Dirty COW y familia: reserva. Hay `gcc` en el box. No era el fallo que el autor plantó.
- El panel admin se descubre por un txt en `/docs`, no por “intuición CMS”. Los leftovers de documentación son superficie.
- `umask 0000` de la sesión `www-data` solo afecta ficheros *nuevos*. Un overwrite in-place conserva el modo del inode original.
