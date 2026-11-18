# analista-correo

[English](README.md) · **Castellano**

**Analizador local de correos sospechosos (phishing, fraude, malware, spam).** Reenvías un correo dudoso a un buzón
propio y recibes un JSON con la valoración de riesgo: indicadores técnicos deterministas (SPF/DKIM/DMARC, enlaces,
adjuntos analizados por dentro y sin ejecutarlos) más la opinión de un modelo local con Ollama (`qwen2.5:7b`). Nada
sale de tu equipo salvo el correo con tu proveedor y las consultas de enriquecimiento a servicios de reputación públicos, que puedes desactivar.

> **English:** see [README.md](README.md). Esta es la versión en castellano; el resto de la documentación técnica (reglas, esquema, mensajes del programa) está solo en castellano.

## Cómo encajan las piezas

```mermaid
flowchart LR
    U["Tú: reenvías un correo sospechoso"] --> MB[("Tu buzón (IMAP)")]
    subgraph HOST["Equipo del analizador (LXC o Debian)"]
        T["temporizador o cron cada 2 min: run.sh"] --> B["buzon.py: una pasada por el INBOX"]
        B --> F{"¿Remitente en REMITENTES, no es respuesta automática, DKIM ok (si EXIGIR_DKIM)?"}
        F -- "no" --> SK["Se marca leído, sin respuesta"]
        F -- "sí" --> D{"¿Ya analizado? Huella, o Message-ID y asunto"}
        D -- "sí" --> R1["Responde con el resultado guardado (YA ANALIZADO): sin modelo ni consultas"]
        D -- "no" --> A["analizar_correo.py: desmonta y puntúa indicadores"]
        A --> E["enriquecer.py: listas, RDAP, abuse.ch, OTX (opcional)"]
        A --> L["Ollama: modelo local, segunda opinión"]
        E --> V["Riesgo final y veredicto"]
        L --> V
        V --> S[("Estado: analisis.db y copias .eml")]
        V --> R2["Respuesta: veredicto y analisis.json"]
    end
    MB --> B
    R1 --> U
    R2 --> U
    E -.-> NET(("Servicios públicos de reputación"))
    S --> X1["contrib/graylog: exportar_graylog.py"] --> CSV["Listas CSV de IPs y dominios maliciosos"]
    CSV --> GL["Graylog: lookup tables y alertas"]
    CSV --> MISP["MISP: un evento por campaña"]
    S --> X2["contrib/grafana-telegraf: metricas.py"] --> TG["Telegraf"] --> IDB[("InfluxDB")] --> GF["Panel de Grafana"]
```

`contrib/despliegue/` monta el equipo del analizador (contenedor, Ollama, modelo y temporizador) con un comando; todo lo que queda a la derecha del analizador es opcional.

## Inicio rápido

Requisitos: Python 3.11+, [Ollama](https://ollama.com) con un modelo (`ollama pull qwen2.5:7b`; `qwen2.5:3b` si vas
justo de memoria; con más capacidad, uno mayor con `ANALISTA_CORREO_MODELO=qwen2.5:14b` o `--modelo` en `analizar_correo.py`), `dig` (paquete `dnsutils`/`bind-utils`, para el rDNS del enriquecimiento) y, para `pruebas/probar.sh`,
`jq`. Para el modo buzón, una cuenta de correo con IMAP y SMTP.

```
git clone <este repositorio> && cd <directorio del repositorio>
python3 analizar_correo.py pruebas/sinteticos/malware-adjunto.eml      # un análisis, sin buzón
python3 -I pruebas/probar_reglas.py                                    # pruebas sin modelo ni red
```

Para el modo buzón:

```
mkdir -p ~/.config/analista-correo && cp buzon.env.example ~/.config/analista-correo/buzon.env
chmod 600 ~/.config/analista-correo/buzon.env      # y edítalo: servidor, usuario, MX_BUZON, REMITENTES
ANALISTA_CORREO_SIN_ENRIQUECER=1 python3 buzon.py --eml pruebas/sinteticos/legitimo-trabajo.eml   # sin IMAP/SMTP ni servicios externos: imprime la respuesta que enviaría (el modelo local sí hace falta)
```

Despliegue automático en un LXC de Proxmox (o en un Debian): `contrib/despliegue/` (un comando; solo pones tu `buzon.env` y, si quieres, otro modelo de Ollama con `--modelo`). Para hacerlo a mano, programa `run.sh` en cron o en un timer de systemd (ver «Buzón»). Para reenviar desde Thunderbird o Gmail,
`guia-reenvio.md`. Lo opcional (exportar IOCs a Graylog, métricas para Grafana) está en `contrib/`.

## Privacidad y límites

- El analizador no abre enlaces ni ejecuta adjuntos. El texto del correo llega al modelo local; el correo, los
  análisis y las respuestas quedan en `~/.local/state/analista-correo/` (700, ficheros 600).
- Un modelo de 7B se equivoca: trata el veredicto como una segunda opinión. Los correos pueden intentar manipular al
  modelo (inyección); por eso el texto oculto y las frases de inyección puntúan aparte y el modelo no puede rebajar los
  indicadores fuertes.
- Las consultas de enriquecimiento (abuse.ch, listas públicas, RDAP, OTX) envían a esos servicios IP y dominios del
  correo. En `analizar_correo.py` solo ocurren con `--enriquecer`; el modo buzón (`buzon.py`) las hace siempre salvo que
  pongas `ANALISTA_CORREO_SIN_ENRIQUECER=1` en el entorno de `run.sh`/cron.
- Seguridad: ver `SECURITY.md`. Licencia: AGPL-3.0-only (`LICENSE`), copyright © 2026 k4y53r: puedes usarlo, modificarlo y compartirlo, pero las versiones modificadas (también las ofrecidas como servicio en red) deben publicarse con la misma licencia.

## Fuentes de terceros y atribución

El enriquecimiento (opcional) usa servicios y listas públicas con sus propios términos de uso; revísalos antes de un uso intensivo: [abuse.ch](https://abuse.ch) (ThreatFox, URLhaus; exige una Auth-Key gratuita), la lista de salidas de [Tor](https://check.torproject.org/torbulkexitlist), [Feodo Tracker](https://feodotracker.abuse.ch/), [Spamhaus DROP](https://www.spamhaus.org/drop/) (condiciones de uso propias), el ranking [Tranco](https://tranco-list.eu) (cítalo si publicas resultados que lo usen), RDAP (registros públicos de cada RIR/registro) y, si lo configuras, AlienVault OTX.

## Cómo funciona

1. **Desmonta el .eml** (Python, biblioteca estándar): cabeceras, texto (HTML a texto, arregla el mojibake y
   el relleno invisible), enlaces y adjuntos (con su sha256).
2. **Indicadores técnicos deterministas**, con puntos:
   - SPF, DKIM y DMARC del `Authentication-Results` más reciente. Es el que añade el último MX, el único fiable.
     Desde la 1.8.1 se leen juntos todos los seguidos de arriba hasta el siguiente `Received`: algún proveedor reparte
     dmarc, spf y dkim en tres cabeceras y antes salía «sin firma DKIM» en todo lo reenviado desde allí.
   - Return-Path, Reply-To y firma DKIM de otro dominio que el From. Nombre visible con otra dirección.
     Dominios que parecen generados al azar (serie de 5+ cifras, 5+ consonantes seguidas o casi sin vocales; el
     mensaje dice cuál) o con 3+ niveles de subdominio, y TLD de abuso frecuente. Desde la 1.7, el Return-Path y
     la firma DKIM de una plataforma de envío (`PROVEEDORES_ENVIO`: Mailchimp, SendGrid…) no cuentan: ahí son lo
     normal.
   - URLs: IP, punycode, acortadores, alojamiento genérico (`storage.googleapis.com`…), texto del enlace
     que no coincide con el destino.
   - Seguimiento de clics de plataformas de envío (desde la 1.9, `SEGUIMIENTO`: `awstrack.me` de Amazon SES,
     `rs6.net` de Constant Contact, `list-manage.com` de Mailchimp, SendGrid, Brevo, HubSpot…): +5 una sola vez
     por correo, porque es legítimo pero oculta el destino real. Esos enlaces no puntúan además por subdominio
     aleatorio ni por texto que no coincide, y su dominio con una marca (`amazonses.com`) en el Return-Path
     tampoco. Constant Contact se trata además como plataforma de envío (su IP de origen cuenta como compartida).
   - Adjuntos ejecutables, con macros, contenedores/HTML y dobles extensiones, por el nombre.
   - Adjuntos por dentro (desde la 1.12), en memoria, sin escribirlos ni ejecutar nada:
     - Tipo real por los primeros bytes (`MAGIA`): un ejecutable de Windows (MZ con cabecera PE; un texto que
       empiece por «MZ» no cuenta), ELF o acceso directo `.lnk` con otro nombre suma +60 y deja el adjunto en
       peligroso; un ZIP, RAR, 7z, CAB, gzip o ISO llamado `.pdf`, `.jpg`, `.doc`… (`EXT_DOCUMENTO`) suma +30. Un
       `.docx` o `.xlsx` es un ZIP y no cuenta.
     - Índice del ZIP (también docx, xlsx, jar), con `zipfile` sobre los bytes: solo se lee el índice, no se
       descomprime nada, así que una bomba ZIP no hace daño; se guardan como mucho 1000 nombres. Un ejecutable dentro
       suma +60 y deja el adjunto en peligroso; macros (`vbaProject.bin` en un `.docx`, o un `.docm` dentro) +40,
       también peligroso; un contenedor o HTML dentro +20; el ZIP cifrado +30 (la contraseña suele ir en el cuerpo
       para que no lo vea el antivirus); un ZIP ilegible +10. Los nombres de dentro van al informe sin caracteres de
       control ni de formato (el U+202E: `fac<U+202E>txt.exe` se lee `facexe.txt`), cortados por delante para no
       perder la extensión, y sin los «.» y « » finales que Windows ignora (`factura.exe.`). El nombre del adjunto
       también se limpia.
     - Un ZIP legible, sin cifrar y con solo documentos o imágenes (`EXT_SIN_MACROS`: sin `.doc`, `.xls`, `.ppt` ni
       `.rtf`, que pueden llevar macros que no se miran) suma +10 en lugar de los +30 de contenedor. Antes,
       todo correo con un ZIP salía sospechoso: los +30 además impedían la rebaja a la mitad.
     - Lo nuevo solo está probado con sintéticos (`pruebas/generar_adjuntos.py`, contenidos inertes). No mira: URLs o JavaScript dentro de PDF,
       RAR/7z/ISO por dentro ni ZIP dentro de ZIP.
     - Office antiguo (OLE2: `.doc`, `.xls`, `.ppt`; desde la 1.13), con un lector mínimo de la biblioteca estándar
       (`mirar_ole`) que solo sigue cadenas de sectores del propio fichero, con bucles cortados, cada sector de FAT
       leído una sola vez y como mucho 32 MB (si no, un fichero hostil multiplica la FAT hasta agotar la memoria):
       - macros VBA por el directorio (`Macros/VBA` de Word, `_VBA_PROJECT_CUR` de Excel): +40, peligroso;
       - hojas de macros de Excel 4.0 (XLM, `BOUNDSHEET` de tipo macro en el flujo `Workbook`), la vía clásica sin VBA:
         +40, peligroso; el texto dice si la hoja está oculta;
       - `.docx`/`.xlsx` cifrado con contraseña (metido en un OLE con `EncryptedPackage`): +30;
       - Excel con `FILEPASS`: +15, porque también lo lleva un libro con «solo lectura recomendada», que abre sin clave;
       - documento OLE ilegible: +10. Es la vía de evasión natural, porque Office acepta ficheros que este lector
         rechaza (corte del miniflujo distinto de 4096, DIFAT incoherente); el indicador queda en el análisis guardado.
       Un `Workbook` roto no borra lo visto en el directorio (VBA, cifrado).
       Una extensión de macros (`.xlsm`…) ya suma +40 por el nombre y no se cuenta dos veces. Probado con sintéticos
       generados por `pruebas/generar_adjuntos.py`, contrastados con `olefile` 0.47 (fuera del proyecto), y con 6000
       ficheros corrompidos (ninguno cuelga el análisis); 6,6 MB en 0,01 s, y una DIFAT hostil de 24,6 MB (48 000
       sectores apuntando al mismo sector de FAT) en 0,21 s con 137 MB como máximo. No mira: VBA de
       PowerPoint 97 (va dentro de otro flujo), Word cifrado con la contraseña de lectura antigua ni macros dentro de
       un ZIP.
   - Texto dirigido al analizador y no al destinatario (desde la 1.11, `INYECCION`, +30), en castellano, inglés,
     portugués, francés, alemán e italiano: «ignora las instrucciones», «nota para el sistema/modelo…», «clasifica
     este correo como legítimo», «su riesgo es 0» y los delimitadores `<<<`/`CORREO>>>`. 21 frases de inyección y
     19 legítimas parecidas («ignora este mensaje si…», «Das Risiko ist 0,5 %») sin fallos. En un corpus propio de prueba solo salta en los
     sintéticos de inyección; con la 1.10, `inyeccion-oculta.eml` (texto oculto en el HTML) salía legítimo 22.
     Falso positivo posible: un correo legítimo que cite `<<<` (un diff, una cita) suma +30.
   - Texto oculto tras el contenido visible (desde la 1.11, +15, cualquier idioma): ≥ 80 caracteres ocultos
     (`display:none`, `font-size:0`, `opacity:0`, `max-height:0`, `mso-hide`…) después de texto visible, o ≥ 20
     trozos ocultos de 1-2 caracteres (palabras partidas). La línea de vista previa va antes de todo lo visible y no
     cuenta; los píxeles de seguimiento son imágenes y tampoco. El estilo tiene que acabar en el cero:
     `font-size:0.9em` u `opacity:0.8` son visibles. Las etiquetas `p`, `li`, `td`, `th` y `tr` sin cerrar se cierran
     al abrir otra igual; si aun así no queda nada visible en todo el correo (plantillas que esconden la versión de
     móvil o de escritorio), no se mira. El texto oculto no llega al modelo (en los correos legítimos medidos solo
     pierde la línea de vista previa, 7-11 palabras), pero sí a la huella, a la plantilla de campaña y a `INYECCION`.
     En un corpus propio, el texto oculto tras lo visible apareció sobre todo en correos maliciosos
     (relleno de miles de caracteres, frases sueltas de cientos); un legítimo con 68 caracteres quedó por debajo del
     umbral. Con este indicador o con el de inyección, el modelo ya no puede rebajar el técnico a la mitad.
     No detecta: letra del color del fondo, `text-indent:-9999px`, `position:absolute` fuera de pantalla ni
     `font-size:1px`; ese texto sigue llegando al modelo. Un `<span>`, `<font>` o `<a>` oculto sin cerrar esconde lo
     que viene detrás (solo se vuelve a mirar todo si no queda nada visible).
3. **Modelo local** (`qwen2.5:7b` por defecto). Recibe remitente, asunto, indicadores y cuerpo como datos no
   fiables y responde con un esquema JSON forzado (`format` de la API de Ollama): clasificación, riesgo,
   marca suplantada, tácticas y explicación. El modelo no tiene herramientas: lo peor que consigue una inyección es
   cambiar su respuesta; los `<<<`/`>>>` del correo se sustituyen para que no pueda cerrar el bloque de datos.
4. **Riesgo final** = técnico + puntos del modelo (tope 100), y nunca menos de 65 si el modelo dice phishing,
   fraude o malware (15 si dice spam). Si el modelo ve un correo normal sin rasgos raros, el técnico pesa la mitad,
   salvo con un indicador de 20 puntos o más (desde la 1.11: si no, un correo que convence al modelo se rebaja solo).
   Si dice spam, sus rasgos suman como mucho 10, lo mismo que la publicidad sola (desde la 1.10: los boletines
   legítimos con «plazas limitadas» o «descuento» pasaban de 30 solo por el modelo).
   ≥ 80 si hay un adjunto peligroso.
   **Remitente propio** (desde la 1.7): DMARC pass, dominio del From en el top 100.000 de Tranco, y la IP de origen
   es suya por PTR o por el titular del ASN (`communications.paypal.com` desde AS17012 PayPal). Entonces se
   descarta el `suplanta_marca` del modelo (la pregunta es «se presenta como una marca», cierto en todo correo de
   la marca) y no se aplica el mínimo por clase. No basta con PTR y DMARC: un atacante los monta en un VPS con su
   dominio; la popularidad no.
5. **IOCs** (`iocs` en el JSON): se extraen, nunca se visitan. IP que entregó el correo al MX que firma el
   `Authentication-Results` (la única fiable; `aproximada` si no se reconoce ese MX), dominios con su raíz y su
   papel (from, return_path, reply_to, dkim, url), URLs completas, direcciones y sha256 de adjuntos.
   `compartido` marca webmail, redes sociales, alojamiento genérico, acortadores y IPs de proveedores de envío:
   ahí el IOC es la URL o la dirección, no el dominio ni la IP.
   Veredicto: `< 30` legítimo, `30-64` sospechoso, `≥ 65` malicioso. Si el modelo falla, queda el técnico y
   un aviso.

### Cómo enviar el correo

- **Reenviar como adjunto** (Gmail: ⋮ → «Reenviar como archivo adjunto»): modo `adjunto_rfc822`, análisis
  completo con cabeceras originales.
- **Reenvío normal**: se pierden las cabeceras del original. Con un bloque «Forwarded message» se toman
  From y asunto de ahí (`reenvio_en_linea`). Sin él (`--reenviado`, o siempre desde `buzon.py`) solo se
  analizan cuerpo, enlaces y el Reply-To, que Gmail conserva (`reenvio_sin_cabeceras`).
- **Automático desde Thunderbird** (el correo que clasifica como basura, reenviado como adjunto por un filtro):
  `guia-reenvio.md`, con las alternativas (Apps Script en Gmail, reenvío manual, complementos).

## Uso

```
python3 analizar_correo.py correo.eml
python3 analizar_correo.py --reenviado reenviado.eml
python3 analizar_correo.py --sin-modelo correo.eml
python3 analizar_correo.py --modelo qwen2.5:3b correo.eml
python3 analizar_correo.py --enriquecer correo.eml      # listas públicas, abuse.ch y RDAP (y OTX si lo configuras)
```

Sin dependencias externas. Con el 7B en CPU tarda unos 15-55 s por correo con el modelo cargado y 40-75 s en frío (medido en CPU, sin GPU).

`pruebas/probar_reglas.py` (sin modelo ni red, segundos) comprueba frases de inyección, estilos ocultos y visibles y
HTML con etiquetas sin cerrar, tipos reales y adjuntos ZIP; pásalo tras tocar `INYECCION`, `CSS_OCULTO`, `Texto`,
`MAGIA`, `mirar_ole` o las reglas de adjuntos.

`pruebas/probar.sh [modelo] [salida.jsonl]` pasa `pruebas/corpus.tsv` (correos etiquetados con el veredicto esperado) y marca
si coincide. En el repo solo hay los sintéticos de `pruebas/sinteticos/` (dominios `*.example` o inventados, sin datos
personales); añade tus propios correos a `corpus.tsv` guardándolos **fuera de git**, porque los reales tienen datos
personales. Con modelo tarda ~1 min por correo (`PAUSA` segundos de descanso entre ellos, 60 por defecto).

## Elegir modelo

El modelo da una segunda opinión; los indicadores deterministas deciden la mayoría de los veredictos. Una comparación
sobre los 23 correos sintéticos de `pruebas/corpus.tsv` (mismo código, solo cambia `--modelo`; con enriquecimiento) da un
punto de referencia:

| Modelo | Dentro del veredicto esperado | Tiempo del modelo por correo (mediana / máx) | Corpus entero |
|---|---|---|---|
| `qwen2.5:7b` (por defecto) | 23 / 23 | 64 s / 143 s | 28 min |
| `qwen2.5:14b` | 22 / 23 | 145 s / 298 s | 59 min |

Medido en un Xeon E5-2620 v1 de 6 núcleos (solo AVX, DDR3-1067, sin GPU) con un contenedor de 10 vCPU y 28 GB de RAM; los
tiempos escalan con tu equipo y una GPU los cambia mucho.

- **Veredicto y riesgo distintos en 6 de 23 correos.** El 14b clasifica mejor los que el 7b llamaba «legítimos» siendo
  maliciosos (inyección con texto oculto, adjuntos con macros o cifrados, un cebo), pero el veredicto final casi no se
  movió, porque los indicadores técnicos ya acertaban.
- **El modelo mayor no es mejor sin más.** El 14b fue el único que falló: puntuó como malicioso (65) un cebo sin enlace
  donde el 7b dijo sospechoso (50), y lo esperado era cualquier cosa por debajo de malicioso.
- **Cuesta unas 2,3 veces el tiempo y el doble de memoria** (el 14b necesita ~9 GB libres además del sistema).
- Este corpus es sintético y está hecho para ejercitar las reglas, no para engañar al modelo. No es un ranking: es un
  punto de partida. Para comparar con tu correo, pasa `pruebas/probar.sh <modelo> salida.jsonl` una vez por modelo y
  compara los resultados; guarda tu corpus real **fuera de git**. Para cambiar: `--modelo` en `analizar_correo.py`, o
  `ANALISTA_CORREO_MODELO` (el temporizador, en `contrib/despliegue/README.es.md`).
- Regla práctica: empieza con el de por defecto; prueba uno mayor si te sobra memoria, tus correos dependen más del texto
  que de las cabeceras, o tienes GPU; usa `qwen2.5:3b` solo si vas justo de memoria (no medido aquí).

## Buzón (`buzon.py`)

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

Prueba sin IMAP ni SMTP, que imprime la respuesta que enviaría: `python3 buzon.py --eml a.eml b.eml …`. Usa una base de datos en memoria, así que sirve para probar duplicados sin tocar la real. Por defecto consulta los servicios de enriquecimiento (abuse.ch, RDAP, Team Cymru, Tranco) y crea `~/.local/state/analista-correo/listas/`; para una prueba sin ninguna conexión de red externa, antepón `ANALISTA_CORREO_SIN_ENRIQUECER=1` (solo hace falta el Ollama local).

### Base de datos y duplicados

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

## Qué hacer con la salida

El analizador está pensado para alimentar las herramientas que ya tengas. Cada análisis deja cuatro tipos de salida: el
`analisis.json` adjunto a cada respuesta (veredicto, riesgo, indicadores e `iocs`), la base SQLite (`analisis.db`) y dos
exportaciones opcionales en `contrib/`: listas CSV de IPs y dominios maliciosos y métricas en line protocol de InfluxDB.

| Objetivo | Cómo | Dónde |
|---|---|---|
| Detectarlo en tu red (Graylog o cualquier SIEM) | Las listas CSV (`correo_iocs_ip.csv`, `correo_iocs_dominio.csv`) sirven de lookup table: alerta cuando un cliente de tu LAN resuelve o contacta una IP o un dominio que ya llegó por correo. | `contrib/README.es.md`, «Exportación de IOCs» |
| Panel (Grafana) | `metricas.py` escribe line protocol de InfluxDB y Telegraf lo recoge. Medidas: `correo_dia` (veredictos y riesgo medio por día), `correo_indicador` (qué lo disparó: cabeceras, cuerpo, adjuntos, URLs, enriquecimiento), `correo_envios` (reenvíos y análisis reutilizados), `correo_modelo` (latencia del modelo), `correo_autenticacion` (resultados de SPF/DKIM/DMARC), `correo_total` y `correo_campana` (campañas). Hay un panel importable en `contrib/grafana-telegraf/dashboard.json`. | `contrib/README.es.md`, «Métricas para Grafana» |
| Plataforma de inteligencia de amenazas (MISP) | Lee esas mismas listas CSV (o la tabla `iocs`) y crea un evento de MISP por campaña, con las IPs y dominios como atributos. En `contrib/README.es.md` hay un ejemplo corto con PyMISP. | `contrib/README.es.md`, «MISP» |
| Bloquear en el DNS (AdGuard Home, Pi-hole…) | Convierte el CSV de dominios en una lista de bloqueo. Revísala antes: es una muestra de lo que llegó a tu buzón, no un feed curado. | tu filtro DNS |
| Preguntas puntuales | Las consultas SQL de «Base de datos y duplicados» (infraestructura compartida por ASN, campañas por dominio raíz, plantilla o kit). | `analisis.db` |

![Panel de Grafana: totales y gráficas por día](docs/img/dashboard-grafana-resumen.png)
*El panel de `contrib/grafana-telegraf/dashboard.json`: totales por veredicto, correos nuevos por día, riesgo, indicadores por origen, reenvíos y latencia del modelo. Datos reales del buzón del autor.*

![Panel de Grafana: autenticación y campañas](docs/img/dashboard-grafana-detalle.png)
*Resultados de SPF/DKIM/DMARC y campañas (el mismo texto o enlace de alojamiento desde remitentes distintos).*

Qué conviene saber antes de automatizar encima:
- Las listas CSV solo llevan veredictos maliciosos, quitan la infraestructura compartida (webmail, acortadores,
  plataformas de envío), tus dominios y los populares del ranking Tranco, y limitan la edad de lo que exportan (90 días
  las IPs, 180 los dominios). Aun así son la opinión de un modelo sobre unos pocos correos: deja a una persona en el
  circuito antes de bloquear.
- Un enlace a alojamiento compartido es un IOC como URL completa, no como dominio; el exportador ya mantiene esa
  distinción.
- `info` en el CSV solo lleva datos propios (riesgo, campaña, fecha, número de correos), nunca el asunto ni el texto,
  porque los escribe el atacante.
- Da a cada integración sus propias credenciales con el mínimo privilegio (una clave de MISP solo Publisher, un token de
  InfluxDB solo de escritura) y guárdalas en ficheros con permisos 600, no en la línea de comandos.

## Enriquecimiento (`enriquecer.py`, desde la 1.2)

Consulta los IOCs no compartidos y suma sus puntos al riesgo técnico (tope 40). `buzon.py` lo usa siempre;
`analizar_correo.py` solo con `--enriquecer` (y `probar.sh` lo pasa). El modelo no ve estos hallazgos. Si una
consulta falla, el análisis sigue sin ella y la respuesta lo avisa.

Pesos: Feodo 40, DROP 30, OTX dominio 25, OTX IP 20, dominio de menos de 30 días 20, Tor 15, de menos de un año
10, ya no registrado 10. Un dominio de menos de 24 h (desde la 1.5) lleva además el riesgo final a 80 como mínimo,
y uno de menos de 48 h a 60 (sospechoso): casi nadie legítimo escribe con un dominio recién registrado.

Dominios populares (desde la 1.7): los del top 100.000 de Tranco (`ESTADO/listas/tranco.txt`, una vez por semana)
no se consultan en OTX, abuse.ch ni RDAP, y salen en `populares`. OTX y abuse.ch meten dominios populares
(grandes plataformas de pago o de envío) en pulses por cualquier mención, y eso hacía salir maliciosos correos
legítimos. Excepción: `ANFITRIONES_LIBRES` (duckdns.org, ngrok, blogspot…), donde cualquiera crea subdominios.
Contrapartida: un enlace a una web popular comprometida no suma por enriquecimiento.

Infraestructura de la IP de origen no compartida (desde la 1.6):
- **ASN y prefijo** por el DNS de Team Cymru (`dig`, sin clave). Siempre sale como indicador informativo (0 puntos)
  con ASN, titular, prefijo, país y PTR. Puntúa solo con historial propio: si el mismo prefijo ya ha dado al menos 2
  correos maliciosos distintos (por huella) en 90 días y son al menos la mitad de los suyos, +15; si no, lo mismo
  con el ASN, +10. Un ASN de hosting aloja de todo, por eso no hay lista fija de ASN malos. Ojo: se realimenta (los
  maliciosos suben el historial), por eso el peso es bajo y sin mínimo.
- **PTR**: el rDNS que anotó el MX en `Received`; si no lo hay, `dig -x` de ahora. Marca conocida en el PTR con un
  ASN cuyo titular no la nombra, +25 (p. ej. un PTR con el nombre de una gran empresa en un hosting ajeno; resuelve de
  ida y vuelta, así que FCrDNS no lo detecta). PTR genérico de proveedor (`vps-<hex>`, la IP escrita en el nombre), +10.
  Sin PTR, +10.
- **Alias del PTR** (desde la 1.8, 0 puntos): si el PTR es un CNAME a otro dominio, sale como indicador informativo y
  como nodo `alias_ptr`. En campañas reales se han visto PTR de webs conocidas con CNAME a dominios ajenos que
  resuelven a decenas de IPs, entre ellas la de origen.

OTX por niveles (desde la 1.3), según el nombre y las etiquetas de cada pulse:
- **grave** (ransomware, RAT, C2/botnet, stealer, loader, Cobalt Strike, Emotet…): +40 y riesgo final de al menos 80,
  si hay 2 pulses graves o 1 de los últimos 180 días. Una sola y antigua cuenta como media: las IPs de C2 rotan.
- **medio** (phishing, malware, troyano, exploit): +25 dominio, +20 IP.
- **leve** (spam, scam, fraude): +10.
El comando de `ANALISTA_CORREO_OTX_CMD` decide cuántas pulses y etiquetas imprime.

abuse.ch (desde la 1.4), con la Auth-Key gratuita `ABUSECH_AUTH_KEY` en `buzon.env` ; sin ella se omite:
- **ThreatFox** (IP de origen y dominios raíz) y **URLhaus** (los mismos, y las URLs de alojamiento compartido sin
  consulta ni fragmento, que suelen llevar el usuario): si aparece y es reciente (online o de los últimos 180
  días; ThreatFox solo guarda 6 meses), +40 y riesgo final de al menos 80; si es antiguo, +25.
- **MalwareBazaar** (sha256 de los adjuntos): muestra conocida, +40 y al menos 80.
- Solo se guarda si aparece y un resumen, no la respuesta. Uso no comercial y de poco volumen: sus condiciones
  prohíben el acceso automático de «high volume» sin dar cifra, y pueden retirar la clave sin aviso.

- **IP de origen**: listas Tor, Feodo (C2) y Spamhaus DROP, descargadas
  a `~/.local/state/analista-correo/listas/` una vez al día, y OTX si es IPv4.
- **Dominio raíz**: OTX y RDAP (fecha de alta). RDAP no cubre `.es` ni `.pp.ua`, y se salta en sufijos privados
  como `uk.com`; rdap.org da 429 con ~10 consultas seguidas, por eso hay 2 s de pausa.
- **OTX** (opcional, `ANALISTA_CORREO_OTX_CMD`: un comando que imprime las pulses del valor): solo cuentan las pulses que hablan de amenazas por nombre o
  etiquetas. Muchas otras son volcados de URLscan o listas de rastreo con dominios legítimos.
- Los resultados se guardan en `cache_enriquecimiento` (OTX 7 días, RDAP y Cymru 30, PTR y su alias 7); los errores no.

```
python3 enriquecer.py --simular        # qué cambiaría en los análisis guardados, sin tocarlos
python3 enriquecer.py correo.eml       # enriquece un .eml sin modelo
python3 enriquecer.py --rellenar-infra # ASN, prefijo y PTR de los análisis guardados que no los tienen
```

## Reglas de detección de la 1.15
Motivo: un correo de cebo íntimo (fotos y un secreto, con enlace) puede salir «legítimo» con riesgo bajo si solo suma una señal de enriquecimiento y el modelo local responde «conversación normal», porque esa respuesta rebaja los puntos a la mitad. Todas las reglas son genéricas (sin dominios ni nombres propios) y ninguna alcanza sola el umbral de sospechoso.

| Regla | Dónde | Puntos | Señal |
|---|---|---|---|
| R1 | `evaluar` | 15 en enlace, 10 en texto | marcador de plantilla sin sustituir (`{tag}`, `{{x}}`, `%%x%%`, `[[x]]`, `${x}`, `<%= x %>`, también codificado en el enlace); el CSS de `<style>` que arrastra el texto visible se ignora |
| R2 | `evaluar` | 10 + 5 (tope 15) | nombre del From distinto del de la firma o presentación («Saludos, X», «soy X», «met X»); saludo por alias («Hola Gebruiker4821») |
| R3 | `evaluar` | 10 | parte local de sistema (postmaster, noreply, admin…) con nombre de persona de 2+ palabras |
| R5 | `evaluar` + modelo | 15 (sin rebaja a la mitad) + 25 del modelo | fotos/vídeos/archivos y fórmula de secreto a menos de 400 caracteres, con enlace o adjunto no inline y cuerpo de menos de 800 caracteres; el modelo tiene la pregunta `cebo_intimo_o_chantaje` (rasgo, no clase) |
| R6 | `evaluar` | 0 | idioma dominante (palabras funcionales) fuera de `ANALISTA_CORREO_IDIOMAS` (por defecto `es,en`); solo abre la puerta de R4 |
| R4 | `combinar` | suelo 40 | el modelo dice legítimo + conversación normal, hay `List-Unsubscribe` o UUID en un enlace del dominio del From **y** al menos otra señal independiente (R1, R2, R3, R5, R6, dominio de menos de un año, historial propio, cebo del modelo). Anula la rebaja a la mitad. No se aplica a remitente propio |
| R7 | `enriquecer.py` | 20 (antes 10/15) | ASN o prefijo con 5+ maliciosos y 85 % o más en 90 días; cuenta como indicador fuerte. Vuelve a 10/15 si la PTR es de una plataforma de envío o algún dominio del correo tiene más de 2 años |

R2, R3 y R6 no se aplican si el remitente es propio autenticado (`no_propio` en el indicador). Las señales sin puntos que ve el modelo (`List-Unsubscribe`, UUID de seguimiento, idioma dominante, contradicción) van en `senales_info` del JSON, no en `indicadores`, para no alterar `metricas.py` ni el resumen. Prompt: `conversacion_normal` ya no vale para un boletín con baja o un mensaje por alias.
Pruebas: `python3 -I pruebas/probar_reglas.py` (tablas SÍ/NO, `combinar`, R7 con sqlite en memoria, y los 10 sintéticos con el modelo simulado como «conversación normal»); `pruebas/generar_sinteticos.py pruebas/sinteticos` regenera los sintéticos nuevos.
Límites: R2 cree «Alejandro» y «Alex» el mismo nombre (prefijo de 3 letras) y no distingue apodos sin prefijo común (Robert/Bob dispara +10). Marcha atrás: volver a la versión anterior de tu copia; la base no se revierte (las filas guardadas llevan `version` 1.15).
