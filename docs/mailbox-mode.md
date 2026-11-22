# Buzón (`buzon.py`)

[← README](../README.md) · [English](mailbox-mode.en.md) · **Castellano**

Hace una pasada por el INBOX y termina. Lo lanza `run.sh` desde cron o un timer de systemd cada pocos minutos, con `flock` para no solapar pasadas y `timeout` de 25 min. Solo escribe en `~/.local/state/analista-correo/run.log` si hay errores; lo analizado queda en `correos/`. `--uid N` (repetible) procesa solo esos UID sin leer.

- Lee los no leídos (máximo 6 por pasada).
- Solo analiza los de `REMITENTES`. El resto se marca como leído sin responder, para no contestar a
  cualquiera ni rebotar spam.
- El From se puede falsificar: comprueba además el DKIM del reenvío en el `Authentication-Results` que añade el MX
  del buzón (`MX_BUZON` en `buzon.env`, p. ej. `mx.example.org`; los de debajo los puede escribir el remitente). Tiene que ser `pass` y
  del dominio del From. Por defecto solo avisa, en el log y en la respuesta («Tu envío: verificado / NO
  VERIFICADO»); con `EXIGIR_DKIM=si` en `buzon.env` descarta los no verificados.
- Ignora los correos con `Auto-Submitted` distinto de `no` (respuestas de vacaciones, rebotes); las respuestas
  llevan `Auto-Submitted: auto-replied` para que otros hagan lo mismo. Llevan también `Date`: sin ella, algún proveedor
  rechaza con `550 5.7.1 Command rejected` (hay proveedores que no la añaden al reenviar).
- Guarda el `.eml` en `~/.local/state/analista-correo/correos/` (600); el análisis va a la base de datos.
- Responde con un resumen y `analisis.json` adjunto. En el resumen y el asunto, las URLs y dominios que vienen del
  correo van desactivados (`hxxp`, `[.]`) para que el cliente de correo no los enlace, y la explicación del modelo
  se corta a 40 palabras y la marca a 40 caracteres por código (desde la 1.11: ese texto lo puede dirigir el correo).

La configuración va en `~/.config/analista-correo/buzon.env` (600; se niega a arrancar si no lo es), o en la
ruta de `ANALISTA_CORREO_ENV`:

```
IMAP_HOST=imap.example.org
IMAP_PORT=993
SMTP_HOST=smtp.example.org
SMTP_PORT=465
MAIL_USER=buzon@example.org
MX_BUZON=mx.example.org
MAIL_PASS=...
REMITENTES=yo@example.org,otra-cuenta@example.org
EXIGIR_DKIM=si
```

Prueba sin IMAP ni SMTP, que imprime la respuesta que enviaría: `python3 buzon.py --eml a.eml b.eml …`. Usa una base de datos en memoria, así que sirve para probar duplicados sin tocar la real. Por defecto consulta los servicios de enriquecimiento (abuse.ch, RDAP y su catálogo de IANA, Team Cymru, Tranco, las listas de IFIN) y crea `~/.local/state/analista-correo/listas/`; para una prueba sin ninguna conexión de red externa, antepón `ANALISTA_CORREO_SIN_ENRIQUECER=1` (solo hace falta el Ollama local).

## Base de datos y duplicados

`~/.local/state/analista-correo/analisis.db` (SQLite, 600) tiene tres tablas:
- `analisis`: un análisis por correo distinto, con el JSON completo en `resultado`.
- `envios`: cada reenvío recibido, con el análisis que se usó y si fue `reutilizado`.
- `iocs`: los IOCs de cada análisis (`tipo`, `valor`, `raiz`, `rol`, `compartido`). `buzon.py --rellenar-iocs`
  los saca de los análisis anteriores desde la copia del `.eml`, sin modelo. Desde la 1.6 también la
  infraestructura de la IP de origen: `asn` (por ejemplo `AS64500`), `prefijo` (raiz: su ASN) y `ptr` (raiz: su dominio). Es
  la base para el análisis por grafos: cada análisis enlaza con sus IOCs, y `raiz` enlaza cada nodo con su padre.

Nodos de campaña (desde la 1.8, `rol = 'campana'`; no puntúan). Sirven para unir envíos de una misma campaña que
rota dominio, IP y ASN:
- `plantilla`: sha256 (32 hex) de las letras del texto, sin URLs, direcciones, cifras ni el usuario del
  destinatario. Mismo texto con otra fecha o desde otro dominio, mismo nodo. Solo si quedan 200 letras o más.
- `kit`: la forma de cabeceras y enlaces, con las palabras legibles tal cual y lo aleatorio por clase (`a`
  minúsculas, `A` mayúsculas, `9` cifras, `h` hexadecimal, `x` mezcla). `raiz` dice de qué es:
  - `list-unsubscribe`: `http://*/LEAVE=To`;
  - `return-path`: el usuario por forma y su dominio respecto al From (`return-a@padre-del-from`);
  - `message-id`: con la longitud de cada trozo (`a30@a18`);
  - `enlace`: la forma de los enlaces de alojamiento compartido (`https://storage.googleapis.com/a/a.html#x`).
- `enlace`: el enlace de alojamiento compartido sin parámetros ni fragmento (el cubo del atacante); `raiz`, el host.
- `alias_ptr` (en `rol = 'origen'`): el CNAME del PTR si apunta a otro dominio (`www.tienda.example.com` →
  `tienda-example.net`). Es el de hoy, no el del día en que llegó el correo.

Hay formas que comparten miles de correos legítimos (uuid de Gmail en el Message-ID, `return-path:bounce.h@from`):
son nodos concentradores y el análisis por grafos tendrá que restarles peso. `buzon.py --rellenar-campana` añade
estos nodos a los análisis guardados.

Un correo cuenta como ya analizado si coincide su **huella**, o su **Message-ID y asunto** a la vez. La huella es el
sha256 de asunto sin `Fwd:`/`RV:`, texto del cuerpo y dominios enlazados. No se usa el Message-ID solo porque hay
campañas que lo falsifican. Las dos claves salen del correo analizado, no de tu reenvío: reenviar el mismo correo
dos veces da la misma huella. En un duplicado se responde con el resultado guardado y el aviso «YA ANALIZADO», sin
llamar al modelo.

Solo se reutilizan análisis de la misma `version`: al cambiar reglas o modelo hay que subir `VERSION` en
`analizar_correo.py`. `--reanalizar` fuerza un análisis nuevo. `buzon.py --reanalizar-guardado ID…` vuelve a
analizar análisis ya guardados desde su `.eml`, con modelo y sin responder, (para
corregir falsos positivos de versiones anteriores).

```
sqlite3 ~/.local/state/analista-correo/analisis.db "SELECT fecha, veredicto, riesgo, asunto FROM analisis ORDER BY id DESC LIMIT 10"
sqlite3 ~/.local/state/analista-correo/analisis.db "SELECT e.fecha, e.reutilizado, a.veredicto, e.asunto FROM envios e JOIN analisis a ON a.id = e.analisis_id ORDER BY e.id DESC LIMIT 10"
```

Infraestructura compartida (mismo ASN en varios análisis, aunque cambien IP y dominios):

```
sqlite3 ~/.local/state/analista-correo/analisis.db "SELECT i.valor, count(DISTINCT a.id), group_concat(DISTINCT a.veredicto) FROM iocs i JOIN analisis a ON a.id = i.analisis_id WHERE i.tipo = 'asn' GROUP BY i.valor ORDER BY 2 DESC"
```

Campañas (mismo dominio raíz en varios análisis, o misma plantilla o kit desde dominios distintos):

```
sqlite3 ~/.local/state/analista-correo/analisis.db "SELECT i.raiz, count(DISTINCT a.id), group_concat(DISTINCT a.veredicto) FROM iocs i JOIN analisis a ON a.id = i.analisis_id WHERE i.tipo = 'dominio' AND NOT i.compartido GROUP BY i.raiz ORDER BY 2 DESC"
sqlite3 ~/.local/state/analista-correo/analisis.db "SELECT i.tipo, i.valor, group_concat(DISTINCT a.id), group_concat(DISTINCT a.veredicto) FROM iocs i JOIN analisis a ON a.id = i.analisis_id WHERE i.rol = 'campana' OR i.tipo = 'alias_ptr' GROUP BY i.tipo, i.valor HAVING count(DISTINCT a.id) > 1 ORDER BY count(DISTINCT a.id) DESC"
```
