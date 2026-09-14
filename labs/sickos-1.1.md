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

Eso no es magia de la herramienta: el cliente HTTP cambia el request-line. En modo proxy el browser/ffuf envía `GET http://<origen>/ruta HTTP/1.1` al listener de Squid; Squid abre la conexión al origen. Si enumeras como si 80/3128 fueran un vhost directo, estás midiendo el *error page* del proxy, no la app.

Negativos de primer contacto (fáciles de olvidar la primera vez que se ve un proxy):

- Pedir `http://<IP>:3128/` sin *request-line* de origen devuelve el error de Squid (`The requested URL could not be retrieved` / header `squid/3.1.19`). Eso confirma el proxy, no la aplicación.
- `8080/tcp closed` no cierra la hipótesis de HTTP en `:80` o en `127.0.0.1` *a través* de 3128.
- Solo se vieron `GET` y `HEAD`. No asumir `CONNECT` (túnel TLS) ni un pivot TCP genérico hasta probarlo. La enumeración útil es HTTP en claro con el cliente apuntando al proxy (`-x`, `--useproxy`, proxy del browser).

Detrás del proxy el origen es el stack de Precise: Apache 2.2.x + PHP 5.3.x. Esas versiones no se leen en el scan de 3128; aparecen en los headers del origen cuando el request va *vía* Squid.

Hallazgos de enumeración (según tus notas, siempre con el proxy en el medio):

- `robots.txt` permitido a través del proxy.
- `/wolfcms` alcanzable.
- Fuzzing → `/docs/` con un txt que filtra versión (en tus notas, `3800.txt` / exception).
- Panel admin de WolfCMS.
- Superficie CGI típica de este box (`/cgi-bin/status`) **no** fue el path usado. Queda como hipótesis de Precise + Bash viejo (Shellshock) que no se persiguió aquí. Distinta de “file manager autenticado”: no pide login del CMS; pide que el worker CGI herede variables de entorno hacia Bash.

SSH está abierto. En este path no fue el foothold. El usuario de sistema `sickos` sí existe; el acceso interactivo llegó después, por reutilización de secreto, no por el banner de `sshd`.

## Hipótesis de foothold

WolfCMS viejo + panel de archivos. La pregunta no es “¿hay un exploit de file upload?”. La pregunta es:

> ¿El CMS trata un archivo subido por un usuario autenticado como *contenido estático servible* y lo deja bajo el document root donde Apache/PHP lo interpretan?

Condiciones que tenían que cumplirse:

1. Credencial válida en el panel. `admin:admin` no es “suerte”: es default de instalación que nadie rotó. El login solo demuestra que el *password store* del CMS no se endureció.
2. El plugin/file manager no separa *store* de *execute*. Subir a `/wolfcms/public` implica que esa ruta es web-accesible y que el handler PHP no está restringido por extensión/content-type de forma efectiva.
3. El worker del web server corre el intérprete sobre lo que acabas de escribir.

El RCE no vive en “el upload”. Vive en **escribir bytecode/script en un path que el SAPI de PHP va a incluir**. El upload solo es el canal de escritura autenticado.

Identidad obtenida: `www-data` (contexto del vhost). No es un usuario de sistema interactivo; es la cuenta del worker. Por eso el TTY hay que construirlo después: no hay sesión login(1), hay un proceso hijo de Apache.

## Post-explotación: secreto en config.php

`config.php` de WolfCMS cumple el mismo rol que `wp-config.php`: el proceso web **debe** conocer el DSN de MySQL en claro (o en un secreto que el proceso pueda leer). Si el foothold es el mismo uid que el worker, ese archivo es readable por diseño.

De la base `wolf`:

- Tabla `users` con hashes.
- El hash del admin del CMS cae a `admin` — coherente con el login que ya tenías. No es un hallazgo nuevo de identidad; es confirmación de que el password store del CMS y el de la app coinciden en mediocridad.

El secreto del DSN (usuario/password de MySQL en `config.php`) sí se anotó como material reutilizable. El valor en claro no se deja aquí a propósito; el hecho útil es que **el mismo secreto alimenta dos stores** (servicio SQL y cuenta local `sickos`).

`@@secure_file_priv` en `NULL` lo interpretaste como “no puedo hacer UDF / no puedo escribir”. Cuidado con esa lectura:

- `secure_file_priv = NULL` (o vacío, según versión) **no** significa automáticamente “sin FILE”. Significa “no hay jaula de directorio para `LOAD_FILE`/`INTO DUMPFILE`”.
- Lo que mata un UDF es otra terna: privilegio `FILE`, `plugin_dir` escribible por el uid de `mysqld`, y que el server acepte `CREATE FUNCTION ... SONAME`.
- En este box el UDF **no** era el camino que usaste. Correcto: no fuerces MySQL si el cron ya te da un writer controlado por root.

## Privilegio: dos caminos, uno usado

Hay que separar *qué se usó* de *qué se confirmó después*.

### Path usado: cron + archivo que root ejecuta

LSE marca un cron bajo `/etc/cron.d/automate` (o equivalente) que dispara un `connect.py`.

Aquí el bug no es “hay un cron”. Casi todo Linux tiene cron. El bug es la **intersección**:

- El *principal* que ejecuta el job es root (o un uid distinto al tuyo).
- El *objeto* (`connect.py`) es escribible por `www-data`.

Eso es un fallo de DAC. Root va a `exec` un archivo cuyo contenido lo decide otro uid. No hace falta un exploit de kernel. El scheduler es un invocador privilegiado de código no privilegiado.

Decidiste no poner una reverse shell en el script y en su lugar añadir tu usuario a sudoers. Conceptualmente es lo mismo: estás inyectando un cambio de política en un contexto root. La diferencia operativa es persistencia vs. callback. En un lab da igual; en un engagement, escribir `/etc/sudoers` deja un artefacto más ruidoso y más estable que un one-shot.

`sudo su` después solo confirma que la política nueva ya está cargada.

### Path confirmado después: reutilización de secreto

`/etc/passwd` lista el usuario `sickos` con shell. El password del DSN de MySQL (el de `config.php`) sirve para esa cuenta de sistema. El acceso puede ser `su` desde `www-data` o `ssh` contra el `sshd` ya visto; el plano que se rompe es el mismo.

Esto no es una vulnerabilidad de MySQL. Es **password reuse** entre:

- secreto de servicio (DB),
- cuenta local.

El proceso de instalación o el autor del lab usó el mismo material en dos stores que no deberían compartir destino. Una vez tienes el secreto del worker, pruebas el mismo material contra `su`/`ssh`. Barato, y muy frecuente.

En muchos writeups de este box, `sickos` ya tiene sudo amplio sin tocar sudoers. Aquí el root *operativo* fue el cron que escribe política; el reuso de password es el atajo que se verificó después, no el que abrió la sesión inicial.

## Callejones y notas

- Tratar `:3128` como sitio web: solo el error page de Squid. Cerrado como origen.
- `8080/tcp closed` desde el atacante: no es evidencia de que no haya HTTP interno.
- CGI `/cgi-bin/status` / Shellshock: superficie plausible en Precise; no fue el foothold de estas notas.
- UDF MySQL: descartado a propósito; el cron ya era writer root.
- El panel admin se descubre por un txt en `/docs`, no por “intuición CMS”. Los leftovers de documentación son superficie.
- Las imágenes originales de Joplin y el `-oN` del Nmap no están en este repo. Cuando se reexporten: `labs/sickos-1.1/img/` y el scan junto a la tabla de puertos.

## Qué deberías poder explicar sin mirar el writeup

- Por qué un forward proxy cambia lo que “existe” en HTTP, y por qué el error page de Squid no es la app.
- Por qué `8080 closed` y “solo GET/HEAD” cambian lo que puedes asumir del pivot.
- Por qué un file manager autenticado + document root = RCE, aunque no haya CVE con logo.
- Por qué CGI + Bash de Precise es otra hipótesis distinta (y por qué aquí no se usó).
- Por qué un cron no es privesc hasta que el archivo ejecutado es writable por un uid inferior.
- Por qué `secure_file_priv` no es el único bit que decide un UDF.
- Por qué reusar el secreto del DSN contra `sickos` no es un bug de MySQL.
