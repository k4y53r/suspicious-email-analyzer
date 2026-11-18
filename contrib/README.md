# contrib: extras opcionales

[English](README.en.md) · **Castellano**

Salen del montaje del autor (Graylog para logs de red, Telegraf/InfluxDB/Grafana para métricas). Son ejemplos: dependen de tu infraestructura y no forman parte del analizador. Nada de esto hace falta para usarlo.

## Exportación de IOCs a Graylog (`graylog/exportar_graylog.py`)

Genera `~/.local/state/analista-correo/graylog/correo_iocs_ip.csv` y `correo_iocs_dominio.csv` (columnas `ip|dominio,info`) para usarlos como lookup tables. Para activarlo, copia `exportar_graylog.py` junto a `buzon.py`: `buzon.py` lo importa si existe y lo regenera tras cada correo nuevo. Cargar los CSV en Graylog queda de tu parte (copiarlos a donde lea la lookup table, validarlos fila a fila).

- Solo veredictos maliciosos y del último análisis de cada correo. IPs: la de origen, pública y no compartida, de los últimos 90 días. Dominios: la raíz no compartida de los últimos 180 días, si es del remitente o de un enlace con señal propia.
- Excluidos siempre: tus dominios (`DOMINIOS_PROPIOS=ejemplo.org,ejemplo.net` en el entorno) y los de `~/.config/analista-correo/no-exportar.txt` (uno por línea, incluye subdominios).
- Nunca los dominios populares de Tranco: un falso positivo con un dominio popular haría saltar tus alertas de DNS a cada visita.
- `info` solo lleva datos propios (riesgo, campaña, fecha, número de correos), nunca el asunto ni el texto.

## Métricas para Grafana (`grafana-telegraf/`)

`metricas.py` lee `analisis.db` en solo lectura y escribe `metricas.lp` (line protocol de InfluxDB) en `/var/lib/analista-correo-metricas/` solo si cambia; `telegraf-analista-correo.conf` es el `[[inputs.file]]` de Telegraf que lo lee. El directorio lo creas tú con permisos para el usuario del analizador y lectura para Telegraf. Lánzalo tras cada pasada (por ejemplo, otra línea de cron). Solo cuentas, nunca asuntos, remitentes ni IOCs.

```
python3 -I metricas.py --salida /tmp/metricas.lp
```

**Dashboard listo para importar.** `grafana-telegraf/dashboard.json` es el panel del autor (11 paneles: totales, correos nuevos por día y veredicto, riesgo por día, indicadores por origen, reenvíos, tiempo del modelo, resultados de SPF/DKIM/DMARC y campañas), exportado para que se pueda importar:
1. En Grafana: Dashboards → New → Import → sube `dashboard.json`.
2. Elige tu fuente de datos de InfluxDB (la pide como `DS_INFLUXDB`).
3. Pon en la variable `host` la etiqueta `host` que Telegraf añade a los puntos (el nombre de la máquina, o lo que fijes en su configuración).
4. Las consultas Flux leen el bucket `home`: si el tuyo se llama de otra forma, cámbialo en los paneles (Edit → consulta).
Solo muestra cuentas (ni asuntos, ni remitentes, ni IOCs).

## OTX (`ANALISTA_CORREO_OTX_CMD`)

El enriquecimiento puede consultar AlienVault OTX por medio de un comando tuyo: dado un valor (IP o dominio), debe imprimir `Apariciones en pulses de OTX: N` y una línea `  - <nombre> (id=<id>, creada=<fecha ISO>, tags=<tags>)` por pulse. Sin esa variable, OTX se omite.

## MISP (ejemplo con PyMISP)

No hay un script de MISP en el repositorio porque depende de tu instancia, pero las listas CSV de `graylog/` ya traen lo necesario: `info` lleva el riesgo, la campaña, la fecha y el número de correos. Receta mínima (instala `pymisp` en un entorno virtual propio; la URL y la clave en un fichero 600 o en variables de entorno, nunca en la línea de comandos):

```python
import csv, os
from pymisp import PyMISP, MISPEvent

misp = PyMISP(os.environ["MISP_URL"], os.environ["MISP_KEY"], ssl=os.environ.get("MISP_CA", True))
CSV = os.path.expanduser("~/.local/state/analista-correo/graylog/correo_iocs_dominio.csv")
ev = MISPEvent()
ev.info = "Correo malicioso: dominios del analizador"
ev.distribution = 0            # solo tu organización
ev.threat_level_id = 2         # medio
ev.analysis = 0                # inicial
ev.add_tag("analista-correo")
with open(CSV, newline="", encoding="utf-8") as f:
    for fila in csv.DictReader(f):
        ev.add_attribute("domain", fila["dominio"], category="Network activity", to_ids=True, comment=fila["info"])
misp.add_event(ev)             # sin publicar: revisa el evento en MISP antes de compartirlo
```

Cambia `domain` por `ip-src` y `dominio` por `ip` con `correo_iocs_ip.csv`. Para usarlo de verdad:
- Agrupa por campaña (el texto `campana X` de `info`) en un evento por campaña, no un evento gigante.
- Antes de crear nada, busca el valor en MISP (`misp.search(value=...)`) para no duplicar atributos entre ejecuciones.
- Pon caducidad a lo que subes: una IP de VPS se reasigna en semanas.
- Usa una clave con rol Publisher y sin más permisos, y no publiques ni compartas automáticamente.
- Esto es una opinión de un modelo sobre tus propios correos, no inteligencia verificada: marca `to_ids` solo cuando lo hayas revisado, o déjalo en `False` y deja que un humano lo active.
