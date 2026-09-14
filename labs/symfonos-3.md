# Symfonos 3

VulnHub: [Symfonos: 3](https://www.vulnhub.com/entry/symfonos-3,332/)  
Notas origen: `Scanning.md`, `Priv escalation.md` (pcap / hades) + sesión de enumeración LSE (`cerberus` y `hades`)

## Superficie

Tres puertos. HTTP + FTP + SSH. Eso ya delimita el modelo: un servicio que habla con humanos (HTTP), un plano de archivos (FTP) y un plano de shell (SSH). Ninguno se descarta; se ordenan.

HTTP:

- `/gate/cerberus` es una imagen. Tema mitológico del lab, no un panel. Primera pasada de ffuf sin más hallazgos útiles.
- Segunda pasada encuentra `/cgi-bin`. Detalle que *sí* importa: sin trailing slash (`-f` / `/` final) el tree se ve distinto. `cgi-bin` es un directorio de ejecución, no de documentos. Muchos wordlists + configs de Apache devuelven 403 en `/cgi-bin` y 200 en `/cgi-bin/algo`.
- `/cgi-bin/underworld` responde como script (en la práctica, output tipo `uptime`). Eso no es una página. Es un programa que Apache lanza vía `mod_cgi` / `mod_cgid`.

FTP: banner Debian. Anonymous fallido. Sin secreto aún, no hay listado. El plano FTP **va a importar después**, cuando se huela loopback. Ahora es un negativo.

SSH: banner viejo. Enum / exploit remoto no pagan. El login SSH entra cuando hay un password de usuario, no antes.

## Foothold: CGI + Shellshock

`/cgi-bin` existe para que Apache cree un proceso, rellene su entorno con headers HTTP y haga `exec` del script. Traducción:

- `User-Agent`, `Referer`, `Cookie`, `Host`, etc. → variables de entorno (`HTTP_USER_AGENT`, …).
- El script decide qué hacer con ese entorno.

**Shellshock** (CVE-2014-6271 y familia) no es un bug de Apache. Es un bug de **Bash** al parsear variables de entorno: si el valor empieza como una función `() { :; };`, Bash ejecutaba el *trailing code* al importar la variable. Cualquier programa que:

1. sea un script con `#!/bin/bash` (o invoque bash),
2. reciba entorno controlado por el atacante,

le está dando a Bash un canal de ejecución.

CGI es el caso de libro porque *todo* header HTTP se vuelve entorno. El `User-Agent: () { :; }; comando` no “engaña a Apache”. Apache es un mensajero fiel. Bash es quien interpreta de más.

Probe: respuesta distinta / error cuando la función va en `User-Agent` (Caido). El callback posterior nace como `cerberus` (el uid del CGI), no como root. Una shell “ya TTY” en este contexto suele significar que el payload lanzó bash interactivo; no significa privilegio.

## De cerberus a hades: identidad en tránsito

LSE / capabilities / grupos:

- El uid del CGI pertenece al grupo `pcap`.
- Hay capability asociada a captura (`CAP_NET_RAW` / `CAP_NET_ADMIN` en `tcpdump`).
- Root lanza un health-check periódico: `curl` contra `127.0.0.1` y un cliente Python (`/opt/ftpclient/ftpclient.py`) que habla FTP contra localhost.
- `/srv/ftp` y `statuscheck.txt` son el otro extremo de ese check.

Grupo `pcap` + tcpdump no es “un toy de red”. Es permiso de **ver frames que no son del proceso**. En Linux, capturar implica `CAP_NET_RAW` (y a menudo `CAP_NET_ADMIN`). El grupo `pcap` + un `tcpdump` setcap es la forma “legítima” de delegar sniffing sin uid 0. El lab deja esa delegación puesta.

El tráfico interesante no está en el ethernet de la LAN. Está en **loopback**. Un job root habla FTP contra `127.0.0.1` para mover un status file. FTP es un protocolo de los 70: `USER` y `PASS` van en claro. Si se puede sniffear lo:21 en `lo`, el secreto no se “rompe”. Se *observa*.

Eso es distinto de crackear un hash. No hay primitiva criptográfica que falló. Falló el supuesto “el loopback es privado porque no sale de la máquina”. Es privado respecto de *otros hosts*. No lo es respecto de otro uid en el mismo kernel con capacidad de packet socket.

LSE como `cerberus` ya marcaba dos señales que no son ruido:

- `fst140`: mail de `hades` legible (`/var/mail/hades`).
- Proceso root periódico escribiendo estado hacia el plano FTP.

El dato que sale del stream FTP es un par `hades:<password>`. SSH con `hades` cambia de contexto: de proceso CGI a sesión de usuario. Nuevo home, nuevo DAC, nueva enumeración.

## Hades → root: el job Python y el grupo `gods`

LSE como `hades` cambia el mapa. Lo que importa no es “hay cron”. Es esta combinación:

1. `hades` está en el grupo **`gods`**.
2. Gran parte de `/usr/lib/python2.7/` (stdlib) es escribible por ese grupo. Incluye `ftplib.py` y el symlink `sitecustomize.py` → `/etc/python2.7/sitecustomize.py`.
3. Root ejecuta periódicamente:
   ```text
   /usr/bin/python2.7 /opt/ftpclient/ftpclient.py
   ```
4. Ese script hace `import ftplib` y después instancia `ftplib.FTP(...)` contra localhost.

Esto **no** es el cwd-hijack clásico (`sys.path[0] == ''` y un `ftplib.py` al lado del script). Aquí la ruptura es más directa: el usuario de bajo privilegio puede escribir en la **librería estándar** que el intérprete privilegiado va a cargar.

El archivo en disco no tiene privilegios propios. Quien determina el UID es el **proceso que hace el import**. Si `hades` corre Python, el hook corre como `hades`. Si el cron de root arranca `python2.7`, el mismo archivo corre como root.

### Tres formas de abusar el mismo contrato (de peor a mejor)

| Prioridad | Método | Qué rompe | Cuándo usarlo |
| --- | --- | --- | --- |
| 1 | `sitecustomize.py` | Nada de la stdlib | Siempre que se pueda escribirlo en una ruta de `sys.path` |
| 2 | Patch controlado de `ftplib.py` | Mínimo (un stub de `FTP`) | Si no se puede tocar `sitecustomize` |
| 3 | Sobrescribir / romper `ftplib.py` entero | La librería y cualquier otro consumidor | Solo lab, y peor práctica |

**`sitecustomize`** no lo importa el script. Lo importa el módulo `site` **al arrancar el intérprete**, una sola vez, antes de correr `ftpclient.py`. El nombre es fijo. Existe en Python 2 y Python 3. En esta caja el path visible bajo `/usr/lib/python2.7/sitecustomize.py` es un symlink al fichero real en `/etc/python2.7/`.

Se puede saltar: `python -S` no carga `site` (ni `sitecustomize` ni `usercustomize`). Se verifica en la línea de comando del proceso (`ps`) o con `sys.flags.no_site`. Aquí el cron no usaba `-S`.

**Patch limpio de `ftplib`**: el script hace `import ftplib` y después `ftplib.FTP(...)`. El código de nivel superior del módulo se ejecuta en el import. Si además queda una clase `FTP` mínima, el script no muere de inmediato con `AttributeError`. Eso es distinto de borrar el módulo entero.

**Romper `ftplib`**: un `import` inválido (`os.sys` vs `os, sys`) prueba que el archivo propio se está cargando, pero tumba el job y cualquier otro uso de la librería. Útil como síntoma de laboratorio, inaceptable como técnica.

### `.py` vs `.pyc`

No siempre que existe un `.pyc` existe el `.py`. El `.pyc` es bytecode. Python carga el `.pyc` si es más reciente o si el fuente ya no está. Cuando root importa el módulo, suele regenerar el `.pyc` **como root**. Por eso un overwrite del `.py` no basta si el intérprete sigue prefiriendo un `.pyc` ajeno. La pregunta operativa es `modulo.__file__`, no “¿existe el `.py`?”.

Una prueba local (efecto lateral en disco, sin red) sirve para confirmar que el hook corre como root *antes* de pelear el canal de callback. `nc -e` además es un binario inconsistente entre distros; no es el oráculo de si el vector funciona.

### Qué se rompió de verdad

No “Python es inseguro”. Se rompió esta premisa:

> un job root puede importar la stdlib porque esa stdlib es de root y no la toca nadie más.

El grupo `gods` + permisos de escritura en `/usr/lib/python2.7` y `/etc/python2.7/sitecustomize.py` convierten esa premisa en falsa. El cron solo es el *transportista* que arranca el intérprete con UID 0.

## Callejones

- `/gate/cerberus`: piel del lab, no vector.
- FTP anónimo: cerrado.
- SSH sin credencial: cerrado. Con credencial de `hades`, abierto.
- Fuzzing de CGI sin slash final: falso negativo. Vale más que el payload.
- SUID estándar (`passwd`, `su`, `mount`, `exim4`): LSE ya dijo que no había uncommon setuid.
- Cwd-hijack al lado de `/opt/ftpclient`: hipótesis razonable, no era el contrato que el box dejó abierto. El contrato abierto era la stdlib + `sitecustomize` vía grupo `gods`.
- Destruir `ftplib.py` entero: funciona como PoC sucia y deja la caja inestable.
