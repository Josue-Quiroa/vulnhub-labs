# SickOs 1.1

VulnHub: [SickOs: 1.1](https://www.vulnhub.com/entry/sickos-11,132/)  
Notas origen: `Scan.md`, `Explotation.md`, `Priv Escalation.md`

## Superficie

El scan no muestra un HTTP “normal” en 80 como primera impresión útil. Lo que importa es el **proxy Squid** (típicamente `3128/tcp`) junto con SSH.

Squid en este box no es “un puerto más”. Es un *forward proxy* que el propio host usa como filtro de acceso al origen HTTP. Sin hablarle al proxy, el origen parece muerto o vacío. Con el proxy, el mismo request revela el sitio real, `robots.txt` y `/wolfcms`.

Eso no es magia de la herramienta: el cliente HTTP cambia el request-line. En modo proxy el browser/ffuf envía `GET http://<origen>/ruta HTTP/1.1` al listener de Squid; Squid abre la conexión al origen. Si enumeras como si 80/3128 fueran un vhost directo, estás midiendo el *error page* del proxy, no la app.

Hallazgos de enumeración (según tus notas):

- `robots.txt` permitido a través del proxy.
- `/wolfcms` alcanzable.
- Fuzzing → `/docs/` con un txt que filtra versión (en tus notas, `3800.txt` / exception).
- Panel admin de WolfCMS.

SSH está abierto. En este path no fue el foothold.

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

`@@secure_file_priv` en `NULL` lo interpretaste como “no puedo hacer UDF / no puedo escribir”. Cuidado con esa lectura:

- `secure_file_priv = NULL` (o vacío, según versión) **no** significa automáticamente “sin FILE”. Significa “no hay jaula de directorio para `LOAD_FILE`/`INTO DUMPFILE`”.
- Lo que mata un UDF es otra terna: privilegio `FILE`, `plugin_dir` escribible por el uid de `mysqld`, y que el server acepte `CREATE FUNCTION ... SONAME`.
- En este box el UDF **no** era el camino que usaste. Correcto: no fuerces MySQL si el cron ya te da un writer controlado por root.

## Privilegio: cron + archivo que root ejecuta

LSE marca un cron bajo `/etc/cron.d/automate` (o equivalente) que dispara un `connect.py`.

Aquí el bug no es “hay un cron”. Casi todo Linux tiene cron. El bug es la **intersección**:

- El *principal* que ejecuta el job es root (o un uid distinto al tuyo).
- El *objeto* (`connect.py`) es escribible por `www-data`.

Eso es un fallo de DAC. Root va a `exec` un archivo cuyo contenido lo decide otro uid. No hace falta un exploit de kernel. El scheduler es un invocador privilegiado de código no privilegiado.

Decidiste no poner una reverse shell en el script y en su lugar añadir tu usuario a sudoers. Conceptualmente es lo mismo: estás inyectando un cambio de política en un contexto root. La diferencia operativa es persistencia vs. callback. En un lab da igual; en un engagement, escribir `/etc/sudoers` deja un artefacto más ruidoso y más estable que un one-shot.

`sudo su` después solo confirma que la política nueva ya está cargada.

## Camino alternativo: reutilización de secreto

`/etc/passwd` lista el usuario `sickos`. El password del DSN de MySQL (el de `config.php`) sirve para esa cuenta de sistema.

Esto no es una vulnerabilidad de MySQL. Es **password reuse** entre:

- secreto de servicio (DB),
- cuenta local.

El proceso de instalación o el autor del lab usó el mismo material en dos stores que no deberían compartir destino. Una vez tienes el secreto del worker, pruebas el mismo material contra `su`/`ssh`. Barato, y muy frecuente.

## Callejones y notas

- El panel admin se descubre por un txt en `/docs`, no por “intuición CMS”. Los leftovers de documentación son superficie.
- No documentaste banner SSH ni si el usuario `sickos` tenía shell. Si reexportas las capturas, anota el `sshd` y el login path (`su` vs `ssh`).
- Las imágenes originales de Joplin no están en este repo.

## Qué deberías poder explicar sin mirar el writeup

- Por qué un forward proxy cambia lo que “existe” en HTTP.
- Por qué un file manager autenticado + document root = RCE, aunque no haya CVE con logo.
- Por qué un cron no es privesc hasta que el archivo ejecutado es writable por un uid inferior.
- Por qué `secure_file_priv` no es el único bit que decide un UDF.
