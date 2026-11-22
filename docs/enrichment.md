# Enriquecimiento (`enriquecer.py`, desde la 1.2)

[← README](../README.md) · [English](enrichment.en.md) · **Castellano**

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
- **Dominio raíz**: OTX y RDAP (fecha de alta). RDAP se consulta directamente al servidor del registro de cada TLD,
  según el catálogo de IANA (`https://data.iana.org/rdap/dns.json`, una vez por semana en
  `~/.local/state/analista-correo/listas/rdap-dns.json`; se valida y un catálogo vacío o muy reducido no pisa el
  anterior). Antes se usaba `rdap.org`, que está tras Cloudflare: en algunos países los operadores bloquean por IP
  rangos de Cloudflare (p. ej. durante partidos de fútbol en España) y el TLS falla con un certificado ajeno. Si el
  registro no responde, se prueba `rdap.org`; si el TLD no figura en el catálogo (`.es`, `.pp.ua`), se omite. RDAP se
  salta también en sufijos privados como `uk.com`; hay 2 s de pausa entre consultas.
- **Listas de IFIN** (solo contexto, 0 puntos): nueve listas de dominios de [lists.ifin.network](https://lists.ifin.network/)
  (AGPL-3.0, sin garantía) de servicios legítimos que se abusan: hosting gratuito con subdominios, APIs y webhooks de
  chat, webhooks como servicio, pastebins (texto y código), túneles de reenvío de puertos, pasarelas IPFS, editores de
  PDF en línea y mirrors de descargas. Se descargan una vez por semana a `listas/ifin-<lista>.txt` (máx. 2 MB, solo
  dominios válidos; una descarga vacía o que pierde más de la mitad no pisa la anterior). Si un host del correo o de
  sus enlaces, o un dominio padre, figura en alguna, sale un hallazgo con 0 puntos (`PUNTOS["ifin"]`): un enlace a un
  pastebin o a un hosting gratuito no es malicioso por sí solo, así que no cuenta como señal fuerte ni como puerta. No
  se envía nada del correo: solo se descargan las listas. Licencia (leída el 2026-11-22): el sitio de las listas las
  declara bajo AGPL-3.0 y sin garantía; el foro de IFIN usa CC BY-NC-ND 4.0 para su propio contenido, y sus condiciones
  de uso excluyen `lists.ifin.network`. Este repo no incluye ni redistribuye las listas: las descarga cada instalación.
  Autoría según las propias listas: Mike Bunner (B'ad Samurai) y Erik Hjelmvik (Netresec). Pruebas: `pruebas/probar_ifin.py` y `pruebas/probar_rdap.py`.
- **OTX** (opcional, `ANALISTA_CORREO_OTX_CMD`: un comando que imprime las pulses del valor): solo cuentan las pulses que hablan de amenazas por nombre o
  etiquetas. Muchas otras son volcados de URLscan o listas de rastreo con dominios legítimos.
- Los resultados se guardan en `cache_enriquecimiento` (OTX 7 días, RDAP y Cymru 30, PTR y su alias 7; el catálogo RDAP de IANA y las listas de IFIN, 7); los errores no.

```
python3 enriquecer.py --simular        # qué cambiaría en los análisis guardados, sin tocarlos
python3 enriquecer.py correo.eml       # enriquece un .eml sin modelo
python3 enriquecer.py --rellenar-infra # ASN, prefijo y PTR de los análisis guardados que no los tienen
```
