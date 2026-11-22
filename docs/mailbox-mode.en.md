# Mailbox mode (`buzon.py`)

[← README](../README.en.md) · **English** · [Castellano](mailbox-mode.md)

Makes one pass over the INBOX and exits. `run.sh` launches it from cron or a systemd timer every few minutes, with `flock`
so passes do not overlap and a 25-minute `timeout`. It only writes to `~/.local/state/analista-correo/run.log` when there
are errors; what was analysed goes to `correos/`. `--uid N` (repeatable) processes only those unread UIDs.

- Reads the unread mails (at most 6 per pass).
- Only analyses those from `REMITENTES`. The rest are marked as read without a reply, so it does not answer anybody or
  bounce spam.
- The From can be forged: it also checks the DKIM of the forward in the `Authentication-Results` added by the mailbox's MX
  (`MX_BUZON` in `buzon.env`, e.g. `mx.example.org`; the ones below can be written by the sender). It must be `pass` and
  for the From's domain. By default it only warns, in the log and in the reply ("Tu envío: verificado / NO VERIFICADO");
  with `EXIGIR_DKIM=si` in `buzon.env` it discards the unverified ones.
- Ignores mails with `Auto-Submitted` other than `no` (out-of-office, bounces); its replies carry
  `Auto-Submitted: auto-replied` so others do the same. They also carry `Date`: without it some providers reject with
  `550 5.7.1 Command rejected`.
- Stores the `.eml` in `~/.local/state/analista-correo/correos/` (600); the analysis goes to the database.
- Replies with a summary and `analisis.json` attached. In the summary and subject, URLs and domains coming from the mail
  are defanged (`hxxp`, `[.]`) so the mail client does not link them, and the model's explanation is cut to 40 words and
  the brand to 40 characters per code (since 1.11: that text can be steered by the mail).

Configuration lives in `~/.config/analista-correo/buzon.env` (600; it refuses to start otherwise), or in the path of
`ANALISTA_CORREO_ENV`:

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

Test without IMAP or SMTP, printing the reply it would send: `python3 buzon.py --eml a.eml b.eml …`. It uses an in-memory
database, so it is good for testing duplicates without touching the real one. By default it queries the enrichment services
(abuse.ch, RDAP and its IANA catalogue, Team Cymru, Tranco, the IFIN lists) and creates `~/.local/state/analista-correo/listas/`; for a test with no external
network connection, prefix `ANALISTA_CORREO_SIN_ENRIQUECER=1` (only the local Ollama is needed).

## Database and duplicates

`~/.local/state/analista-correo/analisis.db` (SQLite, 600) has three tables:
- `analisis`: one analysis per distinct mail, with the full JSON in `resultado`.
- `envios`: every forward received, with the analysis used and whether it was `reutilizado` (reused).
- `iocs`: the IOCs of each analysis (`tipo`, `valor`, `raiz`, `rol`, `compartido`). `buzon.py --rellenar-iocs` extracts
  them from earlier analyses from the `.eml` copy, without the model. Since 1.6 also the origin IP's infrastructure:
  `asn`, `prefijo` (root: its ASN) and `ptr` (root: its domain). This is the basis for graph analysis: every analysis
  links to its IOCs, and `raiz` links each node to its parent.

Campaign nodes (since 1.8, `rol = 'campana'`; they do not score) link sends of one campaign that rotates domain, IP and
ASN: `plantilla` (sha256 of the letters of the text, without URLs, addresses, digits or the recipient's user name; only
if 200 letters or more remain), `kit` (the shape of headers and links, readable words as they are and the random parts by
class), `enlace` (the shared-hosting link without parameters or fragment) and `alias_ptr` (the PTR's CNAME if it points to
another domain). Some shapes are shared by thousands of legitimate mails (Gmail's uuid in the Message-ID): they are hub
nodes and graph analysis will have to down-weight them. `buzon.py --rellenar-campana` adds these nodes to stored analyses.

A mail counts as already analysed if its **fingerprint** matches, or its **Message-ID and subject** both do. The
fingerprint is the sha256 of the subject without `Fwd:`/`RV:`, the body text and the linked domains. Message-ID alone is
not used because some campaigns forge it. Both keys come from the analysed mail, not from your forward: forwarding the
same mail twice gives the same fingerprint. For a duplicate, the stored result is returned with the warning "YA
ANALIZADO", without calling the model.

Only analyses of the same `version` are reused: when you change rules or model, bump `VERSION` in `analizar_correo.py`.
`--reanalizar` forces a fresh analysis. `buzon.py --reanalizar-guardado ID…` re-analyses stored analyses from their
`.eml`, with the model and without replying (to fix false positives of earlier versions). Note that changing
`ANALISTA_CORREO_MODELO` does not by itself invalidate stored analyses.

```
sqlite3 ~/.local/state/analista-correo/analisis.db "SELECT fecha, veredicto, riesgo, asunto FROM analisis ORDER BY id DESC LIMIT 10"
sqlite3 ~/.local/state/analista-correo/analisis.db "SELECT e.fecha, e.reutilizado, a.veredicto, e.asunto FROM envios e JOIN analisis a ON a.id = e.analisis_id ORDER BY e.id DESC LIMIT 10"
```

Shared infrastructure (same ASN across several analyses, even if the IP and domains change):

```
sqlite3 ~/.local/state/analista-correo/analisis.db "SELECT i.valor, count(DISTINCT a.id), group_concat(DISTINCT a.veredicto) FROM iocs i JOIN analisis a ON a.id = i.analisis_id WHERE i.tipo = 'asn' GROUP BY i.valor ORDER BY 2 DESC"
```

Campaigns (same root domain across several analyses, or the same template or kit from different domains):

```
sqlite3 ~/.local/state/analista-correo/analisis.db "SELECT i.raiz, count(DISTINCT a.id), group_concat(DISTINCT a.veredicto) FROM iocs i JOIN analisis a ON a.id = i.analisis_id WHERE i.tipo = 'dominio' AND NOT i.compartido GROUP BY i.raiz ORDER BY 2 DESC"
sqlite3 ~/.local/state/analista-correo/analisis.db "SELECT i.tipo, i.valor, group_concat(DISTINCT a.id), group_concat(DISTINCT a.veredicto) FROM iocs i JOIN analisis a ON a.id = i.analisis_id WHERE i.rol = 'campana' OR i.tipo = 'alias_ptr' GROUP BY i.tipo, i.valor HAVING count(DISTINCT a.id) > 1 ORDER BY count(DISTINCT a.id) DESC"
```
