# Enrichment (`enriquecer.py`, since 1.2)

[← README](../README.en.md) · **English** · [Castellano](enrichment.md)

Queries the non-shared IOCs and adds their points to the technical risk (capped at 40). `buzon.py` always uses it;
`analizar_correo.py` only with `--enriquecer` (and `probar.sh` passes it). The model does not see these findings. If a
lookup fails, the analysis goes on without it and the reply says so.

Weights: Feodo 40, DROP 30, OTX domain 25, OTX IP 20, domain younger than 30 days 20, Tor 15, younger than one year 10,
no longer registered 10. A domain younger than 24 h (since 1.5) also raises the final risk to at least 80, and one younger
than 48 h to 60 (suspicious): almost no legitimate sender writes from a freshly registered domain.

Popular domains (since 1.7): those in the Tranco top 100,000 (`~/.local/state/analista-correo/listas/tranco.txt`, refreshed weekly) are not looked
up in OTX, abuse.ch or RDAP and are reported as `populares`; OTX and abuse.ch put popular domains (big payment or sending
platforms) into pulses for any mention, which made legitimate mails come out malicious. Exception: `ANFITRIONES_LIBRES`
(duckdns.org, ngrok, blogspot…), where anyone can create subdomains. Trade-off: a link to a compromised popular site does
not add points through enrichment.

Origin-IP infrastructure (non-shared, since 1.6): **ASN and prefix** through Team Cymru's DNS (`dig`, no key), always shown
as an informational indicator (0 points) and scoring only with your own history (same prefix already seen in at least 2
distinct malicious mails in 90 days and at least half of its mails: +15; otherwise the same with the ASN, +10; it feeds
back, so the weight is low and there is no minimum). **PTR**: the rDNS noted by the MX in `Received`, else a fresh `dig -x`;
a well-known brand in the PTR with an ASN whose holder does not name it, +25; generic provider PTR (`vps-<hex>`, the IP
written in the name) +10; no PTR +10. **PTR alias** (since 1.8, 0 points): if the PTR is a CNAME to another domain, it is
reported as an informational indicator and as an `alias_ptr` node.

OTX by levels (since 1.3), from each pulse's name and tags: **severe** (ransomware, RAT, C2/botnet, stealer, loader, Cobalt
Strike, Emotet…): +40 and final risk of at least 80 if there are 2 severe pulses or 1 from the last 180 days; **medium**
(phishing, malware, trojan, exploit): +25 domain, +20 IP; **mild** (spam, scam, fraud): +10. The command in
`ANALISTA_CORREO_OTX_CMD` decides how many pulses and tags it prints.

abuse.ch (since 1.4), with the free Auth-Key `ABUSECH_AUTH_KEY` in `buzon.env`; without it, it is skipped: **ThreatFox**
(origin IP and root domains) and **URLhaus** (the same, plus shared-hosting URLs): if listed and recent (online or within
180 days), +40 and final risk of at least 80; if old, +25. **MalwareBazaar** (attachment sha256): known sample, +40 and at
least 80. Only the fact of a hit and a summary are stored, not the response. Non-commercial, low-volume use: their terms
forbid "high volume" automated access without giving a figure, and they may withdraw the key without notice.

Origin IP also checks the Tor, Feodo (C2) and Spamhaus DROP lists, downloaded to `~/.local/state/analista-correo/listas/`
once a day, and OTX if it is IPv4. Root domain: OTX and RDAP (registration date). RDAP is queried directly at the registry server of each TLD, taken
from the IANA bootstrap catalogue (`https://data.iana.org/rdap/dns.json`, once a week in
`~/.local/state/analista-correo/listas/rdap-dns.json`; it is validated, and an empty or much smaller catalogue never
replaces the previous one). It used to go through `rdap.org`, which sits behind Cloudflare: in some countries operators
block Cloudflare ranges by IP (for example during football matches in Spain) and TLS fails with a foreign certificate.
If the registry does not answer, `rdap.org` is tried; a TLD that is not in the catalogue (`.es`, `.pp.ua`) is skipped.
RDAP is also skipped for private suffixes such as `uk.com`, with a 2 s pause between queries.

IFIN lists (context only, 0 points): nine domain lists from [lists.ifin.network](https://lists.ifin.network/)
(AGPL-3.0, no warranty) of legitimate services that get abused: free hosting with subdomains, chat APIs and webhooks,
webhooks as a service, paste sites (text and code), port-forwarding tunnels, IPFS gateways, online PDF editors and
third-party download mirrors. They are downloaded once a week to `listas/ifin-<list>.txt` (2 MB max, valid domains only;
an empty download, or one that loses more than half of the list, never replaces the previous one). If a host of the
mail or of its links, or a parent domain, is in one of them, a finding with **0 points** (`PUNTOS["ifin"]`) is added:
a link to a paste site or to free hosting is not malicious by itself, so it does not count as a strong signal or as a
gate. Nothing from the mail is sent: the lists are only downloaded. Tests: `pruebas/probar_ifin.py` and
`pruebas/probar_rdap.py`. Results are cached in `cache_enriquecimiento` (OTX 7 days, RDAP and Cymru 30, PTR and its
alias 7; the IANA RDAP catalogue and the IFIN lists, 7); errors are not.

```
python3 enriquecer.py --simular        # what would change in stored analyses, without touching them
python3 enriquecer.py correo.eml       # enrich an .eml without the model
python3 enriquecer.py --rellenar-infra # ASN, prefix and PTR for stored analyses that lack them
```
