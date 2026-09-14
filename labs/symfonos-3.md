# Symfonos 3

VulnHub: [Symfonos: 3](https://www.vulnhub.com/entry/symfonos-3,332/)  
Notas origen: `Scanning.md`, `Priv escalation.md` (pcap / hades)

## Superficie

Tres puertos. HTTP + FTP + SSH. Eso ya delimita el modelo: un servicio que habla con humanos (HTTP), un plano de archivos (FTP) y un plano de shell (SSH). Ninguno se descarta; se ordenan.

HTTP:

- `/gate/cerberus` es una imagen. Tema mitológico del lab, no un panel. Primera pasada de ffuf sin más hallazgos útiles.
- Segunda pasada encuentra `/cgi-bin`. Detalle que *sí* importa: sin trailing slash (`-f` / `/` final) el tree se ve distinto. `cgi-bin` es un directorio de ejecución, no de documentos. Muchos wordlists + configs de Apache devuelven 403 en `/cgi-bin` y 200 en `/cgi-bin/algo`.
- `/cgi-bin/underworld` responde como script (en la práctica, output tipo `uptime`). Eso no es una página. Es un programa que Apache lanza vía `mod_cgi` / `mod_cgid`.

FTP: banner Debian. Anonymous fallido. Sin secreto aún, no hay listado. El plano FTP **va a importar después**, cuando huelas loopback. Ahora es un negativo.

SSH: banner viejo. Enum / exploit remoto no pagan. Correcto dejarlo. El login SSH entra cuando tengas un password de usuario, no antes.

## Foothold: CGI + Shellshock

`/cgi-bin` existe para que Apache cree un proceso, rellene su entorno con headers HTTP y haga `exec` del script. Traducción:

- `User-Agent`, `Referer`, `Cookie`, `Host`, etc. → variables de entorno (`HTTP_USER_AGENT`, …).
- El script decide qué hacer con ese entorno.

**Shellshock** (CVE-2014-6271 y familia) no es un bug de Apache. Es un bug de **Bash** al parsear variables de entorno: si el valor empieza como una función `() { :; };`, Bash ejecutaba el *trailing code* al importar la variable. Cualquier programa que:

1. sea un script con `#!/bin/bash` (o invoque bash),
2. reciba entorno controlado por el atacante,

le está dando a Bash un canal de ejecución.

CGI es el caso de libro porque *todo* header HTTP se vuelve entorno. El `User-Agent: () { :; }; comando` no “engaña a Apache”. Apache es un mensajero fiel. Bash es quien interpreta de más.

Tus notas: respuesta distinta / error cuando metes la función en `User-Agent` (Caido). Eso es el probe. El callback posterior nace como `cerberus` (el uid del CGI), no como root. Una shell “ya TTY” en este contexto suele significar que el payload lanzó bash interactivo; no significa privilegio.

## De cerberus a hades: identidad en tránsito

LSE / capabilities / grupos:

- Perteneces al grupo `pcap`.
- Hay capability asociada a captura (`CAP_NET_RAW` / `CAP_NET_ADMIN` en el binario o en el proceso, según cómo esté armado el box).
- Root lanza un health-check: `curl` contra `127.0.0.1` volcando a `/opt/ftpclient/statuscheck.txt`.
- `/srv/ftp` y el cliente FTP interno son el *otro* extremo de ese check.

Grupo `pcap` + tcpdump no es “un toy de red”. Es permiso de **ver frames que no son tuyos**. En Linux, capturar implica `CAP_NET_RAW` (y a menudo `CAP_NET_ADMIN`). El grupo `pcap` + un `tcpdump` setcap / un socket packet es la forma “legítima” de delegar sniffing sin uid 0. El lab te la deja puesta.

El tráfico interesante no está en el ethernet de la LAN. Está en **loopback**. Un cron/root habla FTP contra `127.0.0.1` para escribir un status file. FTP es un protocolo de los 70: `USER` y `PASS` van en claro. Si puedes sniffear lo:21 en `lo`, el secreto no se “rompe”. Se *observa*.

Eso es distinto de crackear un hash. No hay primitiva criptográfica que falló. Falló el supuesto “el loopback es privado porque no sale de la máquina”. Es privado respecto de *otros hosts*. No lo es respecto de otro uid en el mismo kernel con capacidad de packet socket.

Mueves el pcap vía `/var/www/html` porque tu uid web/cgi puede escribir el docroot y tú puedes HTTP GET. Es un canal de exfil sucio y válido. El dato que extraes (Wireshark → stream FTP) es un par `hades:<password>`.

SSH con `hades` cambia de contexto: de proceso CGI a sesión de usuario. Nuevo home, nuevo DAC, nueva enumeración.

## Hades → root: writeup incompleto a propósito

Las notas se cortan en una segunda pasada de LSE como `hades` (varios screenshots sin texto). No voy a cerrar esa puerta por ti.

Antes de pedir el payload, responde esto con lo que *ya* viste en esas capturas:

1. ¿Qué archivo bajo `/opt/ftpclient` (o el `PYTHONPATH` / `sys.path` de un script que root ejecuta) es escribible por `hades`?
2. ¿Ese script corre como root por cron, por sudo, o porque el health-check anterior vive en el mismo directorio?
3. Si es Python: ¿el import es relativo al cwd del job? Un `.py` writable al lado de un script privilegiado no es “Python vulnerable”. Es **library/cwd hijack**: `import ftplib` carga *el primer* `ftplib.py` en `sys.path`, y el primer elemento suele ser `''` (directorio de trabajo).

Cuando tengas esas tres respuestas, el último párrafo de este archivo se escribe solo. Hasta entonces el salto a root no está documentado — y no debe parecer que lo está.

## Callejones

- `/gate/cerberus`: piel del lab, no vector.
- FTP anónimo: cerrado.
- SSH sin credencial: cerrado. Con credencial de `hades`, abierto.
- Fuzzing de CGI sin slash final: falso negativo. Vale más que el payload.

## Qué deberías poder explicar sin mirar el writeup

- Por qué un header HTTP termina como variable de entorno en CGI.
- Por qué Shellshock es un bug de Bash y CGI solo es el transportista.
- Por qué `lo` + FTP en claro + grupo `pcap` es un robo de identidad, no un exploit de FTP.
- Qué pregunta hacerle a `sys.path` cuando un usuario no-root comparte directorio con un job root en Python.
