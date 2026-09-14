# Raven 2

VulnHub: [Raven: 2](https://www.vulnhub.com/entry/raven-2,269/)  
Notas origen: `Escanning.md`, `Wordpress.md`, `Priv escalation.md` (UDF), `SSH.md`

## Superficie

Puertos relevantes en tus notas: HTTP/80 (Apache 2.4.10 Debian), SSH, `rpcbind`.

`rpcbind` en un box Linux de este perfil casi nunca es el foothold. Es el mapper de RPC (port 111). Sin un servicio NFS/mountd expuesto de forma útil, enumerarlo y cerrar el ticket es la decisión correcta. Lo dejaste como negativo. Bien.

HTTP sí importa. El fuzzing saca `/wordpress` y `/vendor`. Esos dos directorios no pesan igual:

- `/wordpress` es una app con su propio plano de identidad (wp-login, XML-RPC, usuarios en `wp_users`).
- `/vendor` es *dependencia empaquetada*. En PHP, `vendor/` suele ser Composer o un third-party drop. Ahí no buscas un login: buscas `VERSION`, `README`, `CHANGELOG`. La versión es el input de la hipótesis CVE.

SSH: banner viejo. Más abajo.

## XML-RPC: superficie que no explotaste (y está bien)

Pegaste `system.listMethods` sobre `xmlrpc.php`. Eso no es “el protocolo WordPress”. Es XML-RPC: un bus de procedimientos sobre HTTP, heredado de Blogger/metaWeblog/MovableType, que WP sigue exponiendo.

Lo que `listMethods` te dice:

- El endpoint está vivo (200 + `methodResponse`).
- Hay métodos de lectura y de escritura (`wp.newPost`, `wp.uploadFile`, `wp.getUsers`, pingback, etc.).
- `demo.sayHello` / `demo.addTwoNumbers` son probes de liveness, no de auth.

Intentaste usarlo como canal de enumeración o de SSRF (`pingback.ping` hacia tu máquina). Mismo *faultCode*, mismo timing, sin callback. Conclusión válida: **el método existe, la precondición no**. Pingback necesita que el servidor pueda iniciar HTTP saliente y que el filtro de destino no lo corte. Si no hay diferencia de tiempo ni paquete de vuelta, no sigas golpeando el mismo método.

XML-RPC *sí* puede ser vector (auth brute sobre `wp.getUsers`/`system.multicall`, upload autenticado, SSRF histórico). Aquí no lo fue. El writeup debe registrar el negativo para no reabrir el pozo.

## Foothold: PHPMailer en `/vendor`

Versión antigua (rama 5.2.x). CVE-2016-10033 no es “PHPMailer ejecuta PHP”. Es **inyección de argumentos en el transporte `sendmail`**.

Modelo mental:

1. La app construye un correo y pasa el remitente a `mail()` / a un binario `sendmail -t`.
2. El campo `From` (o equivalente) llega a argv del transportista **sin aislarse**.
3. `sendmail` de GNU/Postfix interpreta switches como `-X` (log file) u `-OQueueDirectory=`.
4. Si controlas el `From`, controlas *dónde* sendmail escribe y *qué* escribe. El payload no es un webshell mágico: es un archivo que el transportista materializa bajo el document root porque le diste la ruta con `-X`.

Precondiciones reales:

- Formulario que *usa* esa librería (en Raven 2 suele ser `contact.php`, no el `xmlrpc.php`).
- Transporte mail() / sendmail, no un SMTP socket bien encapsulado.
- El worker web puede escribir el path destino (típicamente bajo `/var/www/html`).

Identidad: `www-data`. Otra vez el uid del SAPI, no un usuario de negocio.

## SSH: enumeración que no pagó

Banner OpenSSH viejo → hipótesis de *user enum* por diferencia de respuesta en el protocolo de autenticación (timing / mensaje). `scanner/ssh/ssh_enumusers` no “adivina usuarios”: habla el handshake SSH y mide si el servidor corta distinto ante un principal existente vs. inexistente.

En versiones parcheadas esa diferencia desaparece. Tus notas: la lista corta confirma que *el scanner corre*; la lista larga + brute no saca secretos. El brute force contra SSH en lab es ruido útil para aprender rate-limit; en real es el camino más corto a lockout y a un ticket de IR.

Deja SSH como callejón. El foothold ya estaba en HTTP.

## Privilegio: tres planos, no un salto

`www-data` ≠ `root@localhost` (cuenta MySQL) ≠ UID 0 del proceso `mysqld`. Mezclarlos es el error que hace parecer “magia” a la UDF.

El worker lee el DSN de la app. Eso te hace **cliente SQL**, no root del OS. En esta instancia la cuenta mapeada fue `root@localhost` con `GRANT ALL ON *.*`. Sigue sin ser UID 0 hasta que el daemon cargue código nativo.

El LSE ya había contestado el plano del proceso: `mysqld` arrancaba con `--user=root` y `--plugin-dir=/usr/lib/mysql/plugin`. Eso es dato de *deployment*, no de la UDF en abstracto.

### Inventario (lo que hay que medir antes de hablar de `.so`)

| Pregunta | Valor en esta instancia | Por qué existe |
| --- | --- | --- |
| `USER()` vs `CURRENT_USER()` | ambos `root@localhost` | Uno es lo que enviaste; el otro es la cuenta con la que el server te mapeó (`user@host`). El grant set cuelga de `CURRENT_USER()`. |
| `@@version` | `5.5.60-0+deb8u1` | Rama 5.5: `SONAME` solo se busca en `plugin_dir`; filtro de símbolos auxiliares activo por defecto. |
| `SHOW GRANTS` | `ALL ON *.*` + `WITH GRANT OPTION` | Privilegio efectivo. Aquí incluye `FILE` e `INSERT` sobre `mysql` (registrar en `mysql.func`). |
| `plugin_dir` | `/usr/lib/mysql/plugin/` | Único sitio de donde 5.5 hace `dlopen` de una UDF. |
| `secure_file_priv` | **vacío** | Vacío = sin jaula de rutas. `NULL` = la primitiva FILE queda muerta. No son lo mismo. |
| `max_allowed_packet` | `16777216` | Un `.so` no entra si el paquete es más chico que el blob. |
| `file_priv` / `super_priv` en `mysql.user` | `Y`/`Y` en `root@localhost`, `root@raven`, `root@127.0.0.1`, `root@::1`, `debian-sys-maint@localhost` | Confirmación por fila, no solo por el texto de `GRANT`. |

`debian-sys-maint` es la cuenta de mantenimiento de Debian para arrancar/parar MySQL. No aporta más poder del que ya tenías como `root@localhost`.

### `LOAD_FILE` no es un `open()` del UID de `mysqld`

Como `www-data` no podías ni hacer `stat` de `/root/.bashrc` (`/root` suele ser `0700`) ni leer `/etc/shadow` (`0640` `root:shadow`).

Como cliente SQL:

| Path | Qué pasó | Qué demuestra |
| --- | --- | --- |
| `/root/.bashrc` | `LOAD_FILE` devolvió texto | el proceso **atraviesa** `/root` (UID 0) y el fichero tiene `o+r` |
| `/etc/shadow` | `NULL` | no es “el daemon no es root”. MySQL exige además que el fichero sea *readable by all* (`S_IROTH`). `0640` no pasa ese filtro. |

`FILE` no anula el DAC del kernel, y **encima** el motor se autocastra: `LOAD_FILE` ≠ `open()` desnudo. Un `0600` típico (`id_rsa`, `.bash_history`) da el mismo `NULL` que `shadow`, aunque `mysqld` sea root. `HEX(LOAD_FILE(...))` no rescata nada: el `NULL` se decide antes de copiar bytes.

### Primitivas FILE que no escalan

`INTO OUTFILE` al document root crea un PHP nuevo. El inode suele nacer `0666` owned by root y **sigue ejecutándose como `www-data`**: mismo subject del SAPI, otro path.

Ese modo permisivo además tumba consumidores Unix:

- `cron` ignora ficheros world-writable en `/etc/cron.d`
- `sshd` rechaza `authorized_keys` group/world-writable
- `sudo` no traga un sudoers `0666`

Por eso esta escritura no es un PE. Es la misma identidad con un fichero más.

`INTO OUTFILE` serializa texto (escapes, terminadores). `INTO DUMPFILE` es la fila cruda, una columna. Para un ELF solo vale la segunda. Si el `.so` de origen está `0600`/`0640`, `LOAD_FILE` inserta `NULL` y el destino en `plugin_dir` pesa 0 bytes. Síntoma de laboratorio: el fichero “está”, `file(1)` ya no dice ELF, `CREATE FUNCTION` carga aire.

Comprobar tamaño y tipo en origen y en `plugin_dir` **antes** de registrar la función.

### UDF: tres puertas

UDF es el mecanismo *oficial* de MySQL para cargar una shared object y exponerla como función SQL. El abuso es code loading: el siguiente `SELECT` corre C **dentro del PID de `mysqld`**. Si ese PID es UID 0, el hijo de `system(3)` hereda UID 0. `do_system('…')` no es un verbo SQL; es libc dentro del daemon.

| Puerta | Qué tiene que cumplirse |
| --- | --- |
| Artefacto | ELF64, `-shared -fPIC`, símbolos `xxx` + `xxx_init` / `xxx_deinit`. 5.5, con `--allow-suspicious-udfs` off, rechaza bibliotecas que solo exportan el símbolo principal. Compilar en la caja evita otra glibc. |
| Depósito | el `.so` vive **solo** en `plugin_dir`. `SONAME` es el basename, no un path absoluto. Destino de `DUMPFILE` no puede existir. |
| Registro | `CREATE FUNCTION` hace `INSERT` en `mysql.func` + `dlopen`. Hasta que `SELECT * FROM mysql.func` muestre la fila, no hay salto de UID. |

Si `mysqld` corriera como `mysql`, la misma cadena te dejaría como `mysql`. Aquí el deployment era root; por eso leer `/root/.bashrc` y el callback posterior cuadran.

## Callejones

- RPC bind: cerrado como vector.
- XML-RPC pingback / enum: mismo fault, sin callback.
- SSH enum + brute: sin secreto.
- PHP vía `INTO OUTFILE` al docroot: sigue siendo `www-data`; `0666` además invalida cron/sshd/sudoers.
- `LOAD_FILE('/etc/shadow')`: filtro `o+r` de MySQL, no contradicción con un daemon UID 0 ni con la UDF posterior.
- `.so` de 0 bytes en `plugin_dir`: transporte (`OUTFILE` / `LOAD_FILE` de un objeto sin `o+r`), no “UDF rota”.

## Qué deberías poder explicar sin mirar el writeup

- Diferencia entre “hay XML-RPC” y “XML-RPC es explotable ahora”.
- Por qué CVE-2016-10033 vive en argv de sendmail y no en el parser MIME de PHP.
- Por qué `root@mysql` no es UID 0 hasta el `dlopen`.
- Por qué `LOAD_FILE('/root/.bashrc')` puede funcionar y `LOAD_FILE('/etc/shadow')` devolver `NULL` en el mismo proceso root.
- Por qué vacío ≠ `NULL` en `secure_file_priv`.
- Por qué un PHP `0666` en el docroot no es privilegio y por qué `DUMPFILE` no es `OUTFILE`.
