# contrib: extras opcionales

Salen del montaje del autor (Graylog para logs de red, Telegraf/InfluxDB/Grafana para métricas). Son ejemplos: dependen de tu infraestructura y no forman parte del analizador. Nada de esto hace falta para usarlo.
Los scripts de `contrib/despliegue/` (despliegue automático en LXC/Debian) son lo único de aquí que no es un extra del montaje del autor: ver su README.

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

## OTX (`ANALISTA_CORREO_OTX_CMD`)

El enriquecimiento puede consultar AlienVault OTX por medio de un comando tuyo: dado un valor (IP o dominio), debe imprimir `Apariciones en pulses de OTX: N` y una línea `  - <nombre> (id=<id>, creada=<fecha ISO>, tags=<tags>)` por pulse. Sin esa variable, OTX se omite.
