# contrib: optional extras

**English** · [Castellano](README.md)

These come from the author's own setup (Graylog for network logs, Telegraf/InfluxDB/Grafana for metrics). They are examples: they depend on your infrastructure and are not part of the analyzer. None of this is needed to use it. 

## Exporting IOCs to Graylog (`graylog/exportar_graylog.py`)

Generates `~/.local/state/analista-correo/graylog/correo_iocs_ip.csv` and `correo_iocs_dominio.csv` (columns `ip|dominio,info`) to use as lookup tables. To enable it, copy `exportar_graylog.py` next to `buzon.py`: `buzon.py` imports it if present and regenerates the lists after every new mail. Loading the CSV into Graylog is up to you (copy them to where the lookup table reads, validate them row by row).

- Only malicious verdicts, and only the latest analysis of each mail. IPs: the origin one, public and not shared, from the last 90 days. Domains: the non-shared root of the last 180 days, if it belongs to the sender or to a link with its own signal.
- Always excluded: your own domains (`DOMINIOS_PROPIOS=example.org,example.net` in the environment) and those in `~/.config/analista-correo/no-exportar.txt` (one per line, subdomains included).
- Never the popular domains of Tranco: a false positive on a popular domain would fire your DNS alerts on every visit.
- `info` only carries your own data (risk, campaign, date, number of mails), never the subject or the text.

## Metrics for Grafana (`grafana-telegraf/`)

`metricas.py` reads `analisis.db` read-only and writes `metricas.lp` (InfluxDB line protocol) to `/var/lib/analista-correo-metricas/` only if it changed; `telegraf-analista-correo.conf` is the Telegraf `[[inputs.file]]` that reads it. You create the directory, writable by the analyzer's user and readable by Telegraf. Run it after every pass (for instance as another cron line). Measurements: `correo_dia`, `correo_indicador`, `correo_envios`, `correo_modelo`, `correo_autenticacion`, `correo_total`, `correo_campana`.

```
python3 -I metricas.py --salida /tmp/metricas.lp
```

**Ready-made dashboard.** `grafana-telegraf/dashboard.json` is the author's dashboard (11 panels: totals, new mails per day by verdict, risk per day, indicators by origin, forwards, model latency, SPF/DKIM/DMARC results and campaigns), exported to be importable:
1. In Grafana: Dashboards → New → Import → upload `dashboard.json`.
2. Pick your InfluxDB data source (it is asked as `DS_INFLUXDB`).
3. Set the `host` variable to the `host` tag that Telegraf adds to the points (the machine name, or what you set in its config).
4. The Flux queries read the bucket `home`: if yours has another name, replace it in the panels (Edit → query).
It only shows counts (no subjects, senders or IOCs). Panel texts are in Spanish, like the program's output.

## OTX (`ANALISTA_CORREO_OTX_CMD`)

The enrichment can query AlienVault OTX through a command of yours: given a value (IP or domain), it must print `Apariciones en pulses de OTX: N` and one line `  - <name> (id=<id>, creada=<ISO date>, tags=<tags>)` per pulse. Without that variable, OTX is skipped.

## MISP (PyMISP example)

There is no MISP script in the repository because it depends on your instance, but the CSV lists of `graylog/` already carry what is needed: `info` holds the risk, the campaign, the date and the number of mails. Minimal recipe (install `pymisp` in a virtualenv of its own; keep the URL and key in a mode-600 file or in environment variables, never on the command line):

```python
import csv, os
from pymisp import PyMISP, MISPEvent

misp = PyMISP(os.environ["MISP_URL"], os.environ["MISP_KEY"], ssl=os.environ.get("MISP_CA", True))
CSV = os.path.expanduser("~/.local/state/analista-correo/graylog/correo_iocs_dominio.csv")
ev = MISPEvent()
ev.info = "Malicious mail: domains from the analyzer"
ev.distribution = 0            # your organisation only
ev.threat_level_id = 2         # medium
ev.analysis = 0                # initial
ev.add_tag("analista-correo")
with open(CSV, newline="", encoding="utf-8") as f:
    for row in csv.DictReader(f):
        ev.add_attribute("domain", row["dominio"], category="Network activity", to_ids=True, comment=row["info"])
misp.add_event(ev)             # unpublished: review the event in MISP before sharing it
```

For IPs use `ip-src`, `row["ip"]` and `correo_iocs_ip.csv`. To use it for real:
- Group by campaign (the `campana X` text in `info`) into one event per campaign, not one giant event.
- Search the value in MISP (`misp.search(value=...)`) before creating anything, so runs do not duplicate attributes.
- Give what you upload an expiry: a VPS IP is reassigned within weeks.
- Use a key with the Publisher role and nothing more, and do not publish or share automatically.
- This is one model's opinion about your own mail, not verified intelligence: set `to_ids` only after review, or leave it `False` and let a person turn it on.
