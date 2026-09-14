# Raven 2

VulnHub: [Raven: 2](https://www.vulnhub.com/entry/raven-2,269/)

## Superficie

HTTP/80 (Apache 2.4.10 Debian), SSH (OpenSSH 6.7p1) y `rpcbind` en 111.

`rpcbind` es el mapper RPC. Sin NFS/mountd útil detrás, se cierra. El fuzzing web saca `/wordpress` y `/vendor`. No pesan igual: WordPress es app (login, XML-RPC, `wp_users`); `/vendor` es dependencia empaquetada. Ahí se mira `VERSION`, `README`, `CHANGELOG`.

## XML-RPC

`POST /wordpress/xmlrpc.php` + `system.listMethods` responde 200 con el catálogo entero (`wp.*`, `metaWeblog.*`, `blogger.*`, `pingback.ping`, `system.multicall`). `demo.sayHello` también 200: el bus está vivo.

`pingback.ping` hacia el atacante: mismo *faultCode*, mismo timing, sin paquete de vuelta. El método existe; el servidor no inicia HTTP saliente útil. XML-RPC puede servir para brute con `system.multicall` o SSRF histórico. Aquí no pagó.

## Acceso inicial: PHPMailer

`/vendor/VERSION` = 5.2.16. CVE-2016-10033 no evalúa PHP dentro del correo. El `From` llega a argv de `sendmail -t` sin aislar. Switches tipo `-X` / `-OQueueDirectory=` deciden dónde escribe el transportista. Si esa ruta cae bajo el document root, Apache sirve el archivo.

El formulario que usa la librería es `contact.php`, no `xmlrpc.php`. Transporte `mail()` / sendmail, no SMTP encapsulado. Sesión como `www-data`.

## SSH

El banner viejo permite user enum: el handshake responde distinto si el principal existe. `scanner/ssh/ssh_enumusers` confirma que la diferencia está. Lista larga + brute: sin secreto. El foothold ya estaba en HTTP.

## Root: MySQL, no “el SQL es root”

Tres planos distintos: `www-data` (OS), `root@localhost` (cuenta MySQL), UID 0 del proceso `mysqld`. Mezclarlos hace parecer magia a la UDF.

`wp-config.php` es readable por el worker. Da un cliente SQL. En esta caja el mapeo fue `root@localhost` con `GRANT ALL ON *.*`. Sigue sin ser UID 0 hasta que el daemon haga `dlopen` de código nativo.

LSE: `mysqld` arranca con `--user=root` y `--plugin-dir=/usr/lib/mysql/plugin`.

| Check | Valor | Para qué |
| --- | --- | --- |
| `USER()` / `CURRENT_USER()` | `root@localhost` | El grant set cuelga de `CURRENT_USER()` |
| `@@version` | `5.5.60-0+deb8u1` | En 5.5 el `SONAME` solo se busca en `plugin_dir` |
| `SHOW GRANTS` | `ALL ON *.*` + `WITH GRANT OPTION` | Incluye `FILE` e `INSERT` sobre `mysql.func` |
| `plugin_dir` | `/usr/lib/mysql/plugin/` | Único sitio del `dlopen` |
| `secure_file_priv` | vacío | Sin jaula de rutas. `NULL` apaga FILE; no es lo mismo |
| `max_allowed_packet` | 16777216 | El `.so` tiene que entrar en un paquete |
| `file_priv` / `super_priv` | `Y`/`Y` en los `root@…` y `debian-sys-maint` | Por fila, no solo por el texto de `GRANT` |

`debian-sys-maint` es la cuenta de arranque/parada de Debian. No suma poder.

### LOAD_FILE

Como `www-data` no hay `stat` de `/root/.bashrc` (`/root` 0700) ni lectura de `/etc/shadow` (0640 `root:shadow`).

Como cliente SQL:

| Path | Resultado | Qué dice |
| --- | --- | --- |
| `/root/.bashrc` | texto | el proceso atraviesa `/root` (UID 0) y el fichero tiene `o+r` |
| `/etc/shadow` | `NULL` | MySQL exige `S_IROTH` además del DAC. 0640 no pasa |

`LOAD_FILE` no es un `open()` desnudo. Un `0600` (`id_rsa`, `.bash_history`) da el mismo `NULL`. `HEX(LOAD_FILE(...))` no arregla un `NULL` previo.

`INTO OUTFILE` a un PHP en el docroot nace `0666` owned by root y se ejecuta igual como `www-data`. Además tumba consumidores Unix: cron ignora world-writable en `/etc/cron.d`, `sshd` rechaza `authorized_keys` group/world-writable, `sudo` no traga un sudoers `0666`. No es PE.

`INTO OUTFILE` serializa texto. `INTO DUMPFILE` es la fila cruda. Para un ELF solo vale la segunda. Si el `.so` origen está `0600`/`0640`, `LOAD_FILE` inserta `NULL` y en `plugin_dir` queda un fichero de 0 bytes: `file(1)` ya no dice ELF y `CREATE FUNCTION` carga aire. Medir tamaño y tipo en origen y destino antes de registrar.

### UDF

Mecanismo oficial: shared object + función SQL. El `SELECT` corre C dentro del PID de `mysqld`. Si ese PID es UID 0, `system(3)` hereda UID 0.

| Puerta | Condición |
| --- | --- |
| Artefacto | ELF64, `-shared -fPIC`, símbolos `xxx` + `xxx_init` / `xxx_deinit`. 5.5, sin `--allow-suspicious-udfs`, rechaza bibliotecas que solo exportan el símbolo principal. Compilar en la caja evita otra glibc. |
| Depósito | el `.so` vive solo en `plugin_dir`. `SONAME` es el basename. El destino de `DUMPFILE` no puede existir todavía. |
| Registro | `CREATE FUNCTION` hace `INSERT` en `mysql.func` + `dlopen`. Hasta que `SELECT * FROM mysql.func` muestre la fila, no hay salto de UID. |

Si `mysqld` corriera como `mysql`, la misma cadena dejaría al atacante como `mysql`. Aquí el daemon es root; por eso `/root/.bashrc` y el callback cuadran.

## Callejones

- `rpcbind`: cerrado
- XML-RPC pingback: mismo fault, sin callback
- SSH enum + brute: sin secreto
- PHP vía `OUTFILE` al docroot: sigue `www-data`
- `LOAD_FILE('/etc/shadow')`: filtro `o+r` de MySQL, no contradice un daemon UID 0
- `.so` de 0 bytes: transporte, no “UDF rota”
