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

## Privilegio: de `wp-config.php` a UDF

Mismo patrón que WolfCMS: el worker lee el DSN. `wp-config.php` te da usuario/password de MySQL. Con eso no eres root del OS. Eres un cliente SQL.

Tu checklist fue el correcto, y es el que hay que interiorizar **antes** de hablar de `raptor_udf`:

| Pregunta | Por qué existe |
| --- | --- |
| `USER()` vs `CURRENT_USER()` | Uno es lo que enviaste; el otro es la cuenta con la que el server te mapeó (`user@host`). El grant set cuelga de `CURRENT_USER()`. |
| `SHOW GRANTS` | Privilegio efectivo, no el que “parece” el username. |
| `plugin_dir` | Dónde `mysqld` carga `.so`. Si no puedes escribir ahí, no hay UDF nueva. |
| `secure_file_priv` | Jaula de `LOAD_FILE` / `INTO DUMPFILE`. Vacío o NULL cambia el recinto, no el privilegio. |
| `max_allowed_packet` | Un `.so` no entra si el paquete es más chico que el blob. |
| `file_priv` / `super_priv` en `mysql.user` | `FILE` permite leer/escribir el FS *como el uid de mysqld*. Eso no es root-del-kernel; es el usuario del proceso `mysqld`. En muchos labs ese uid es `mysql` y el `plugin_dir` es suyo. |

UDF (User Defined Function) es el mecanismo *oficial* de MySQL para cargar una shared object y exponerla como función SQL. El abuso es: si puedes depositar un `.so` en `plugin_dir` y ejecutar `CREATE FUNCTION ... SONAME`, el siguiente `SELECT mi_funcion('cmd')` corre código nativo **dentro del proceso mysqld**.

Por eso compilas para la *misma* ABI/arch que el servidor, subes el objeto a un path que `LOAD_FILE` pueda leer (`/tmp` suele servir), lo materializas en `plugin_dir` con `INTO DUMPFILE` / `INTO OUTFILE`, y registras la función. El `do_system('nc ...')` no es “MySQL hace red”: es libc `system()` dentro de `mysqld`.

Si `mysqld` corre como root (malísimo, y a veces cierto en labs viejos), el callback nace root. Si corre como `mysql`, eres `mysql`. Tus notas llegan a leer `/root`, así que en este box el proceso tenía el privilegio suficiente. Eso es un dato del *deployment*, no de la UDF en abstracto.

`LOAD_FILE('/etc/shadow')` falló antes. Esperable: `FILE` no anula el DAC del OS. `mysqld` lee como su uid. `shadow` es `root:shadow` 640. Distinto de escribir en `plugin_dir`, que *sí* suele ser del usuario mysql.

## Callejones

- RPC bind: cerrado como vector.
- XML-RPC pingback / enum: mismo fault, sin callback.
- SSH enum + brute: sin secreto.
- `LOAD_FILE` de `shadow`: DAC, no “MySQL no vulnerable”.

## Qué deberías poder explicar sin mirar el writeup

- Diferencia entre “hay XML-RPC” y “XML-RPC es explotable ahora”.
- Por qué CVE-2016-10033 vive en argv de sendmail y no en el parser MIME de PHP.
- Por qué `FILE` + `plugin_dir` escribible es un problema de *identity del proceso mysqld*, no de “SQL injection”.
- Por qué fallar `LOAD_FILE('/etc/shadow')` no contradice un UDF posterior.
