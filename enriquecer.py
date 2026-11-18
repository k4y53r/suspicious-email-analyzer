#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 k4y53r
"""Enriquece los IOCs de un análisis con fuentes de reputación (OTX, listas públicas, RDAP). Ver README.md."""

import argparse, datetime as dt, io, ipaddress, json, os, re, shlex, sqlite3, stat, subprocess, sys, time, urllib.error
import urllib.parse, urllib.request, zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from analizar_correo import MARCAS, PROVEEDORES_ENVIO, SUFIJOS, analizar, base, combinar  # noqa: E402

ESTADO = Path.home() / ".local/state/analista-correo"
CONFIG = Path(os.environ.get("ANALISTA_CORREO_ENV", Path.home() / ".config/analista-correo/buzon.env"))
# Una sola Auth-Key gratuita de abuse.ch (ABUSECH_AUTH_KEY en buzon.env). Sin ella se omiten.
ABUSECH = {"urlhaus_host": "https://urlhaus-api.abuse.ch/v1/host/",
           "urlhaus_url": "https://urlhaus-api.abuse.ch/v1/url/",
           "threatfox": "https://threatfox-api.abuse.ch/api/v1/", "bazaar": "https://mb-api.abuse.ch/api/v1/"}
DB = ESTADO / "analisis.db"
# Opcional: comando que, dado un valor, imprime «Apariciones en pulses de OTX: N» y una línea por pulse (ver contrib/). Sin él, OTX se omite.
OTX = shlex.split(os.environ.get("ANALISTA_CORREO_OTX_CMD", ""))
# Listas públicas de reputación (se descargan una vez al día).
LISTAS = {"tor": "https://check.torproject.org/torbulkexitlist",
          "feodo": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
          "drop": "https://www.spamhaus.org/drop/drop.txt"}
# Dominios populares: OTX y abuse.ch los meten en pulses de amenazas por cualquier mención (medido en pulses reales de plataformas populares)
# No se consultan, salvo donde cualquiera crea subdominios.
TRANCO = "https://tranco-list.eu/top-1m.csv.zip"
TOP_POPULARES = 100000
ANFITRIONES_LIBRES = {"duckdns.org", "ddns.net", "no-ip.org", "ngrok-free.app", "ngrok.io", "blogspot.com",
                      "godaddysites.com", "glitch.me", "000webhostapp.com", "r2.dev", "pages.dev", "web.app",
                      "github.io", "netlify.app", "vercel.app", "firebaseapp.com", "weebly.com", "wixsite.com"}
CADUCIDAD_DIAS = {"tranco": 7, "otx": 7, "rdap": 30, "lista": 1, "urlhaus": 7, "threatfox": 7, "bazaar": 7, "cymru": 30,
                  "cymru_as": 30, "ptr": 7, "alias_ptr": 7}
PUNTOS = {"otx_grave": 40, "otx_ip": 20, "otx_dominio": 25, "otx_leve": 10, "feodo": 40, "drop": 30, "tor": 15,
          "dominio_nuevo": 20, "dominio_reciente": 10, "dominio_no_registrado": 10,
          "abusech_grave": 40, "abusech_antiguo": 25, "ptr_marca": 25, "ptr_generico": 10, "ptr_ausente": 10,
          "prefijo_historial": 15, "asn_historial": 10, "historial_alto": 20, "info": 0}
SUELO_GRAVE = 80  # como un adjunto ejecutable
TOPE = 40  # como las URLs: el enriquecimiento suma, pero no decide solo
DIAS_NUEVO, DIAS_RECIENTE = 30, 365
SUELO_DOMINIO_HORAS = [(24, SUELO_GRAVE), (48, 60)]  # (menos de N horas, riesgo mínimo); 60 queda en sospechoso
# Historial propio: un ASN de hosting aloja de todo, así que solo cuenta si ya ha dado varios correos maliciosos
# distintos (por huella) y son al menos la mitad de los que ha dado.
DIAS_HISTORIAL, MIN_MALICIOSOS = 90, 2
# R7 (1.15): con 5 maliciosos distintos y el 85 % o más, el historial pesa 20 (indicador fuerte: sin rebaja a la mitad).
# Si algún dominio del correo tiene más de DIAS_ANTIGUO días (RDAP), vuelve a 10: es la señal contraria.
ALTO_MIN_MALICIOSOS, ALTO_PORCENTAJE, DIAS_ANTIGUO = 5, 85, 730
# PTR asignado por el proveedor, no elegido por quien envía: VPS, rangos dinámicos o la IP escrita en el nombre.
PTR_GENERICO = re.compile(r"(^|[.-])(vps|vds|vm|srv|server|host|static|dynamic|dyn|dhcp|pool|dsl|adsl|cable|cust|"
                          r"client|ip)[-.]?[0-9a-f]{6,}([.-]|$)", re.I)
PAUSA_RDAP = 2  # s; rdap.org devuelve 429 con ~10 consultas seguidas (medido)
# Muchas pulses de OTX son volcados de URLscan o listas de rastreo que incluyen dominios legítimos: solo cuentan
# las que hablan de amenazas por su nombre o etiquetas (medido en correos legítimos reales).
# Por niveles: la primera que encaje. Palabras completas donde hace falta («ec2», «karat»).
NIVELES_OTX = [
    ("grave", re.compile(r"ransom|\brats?\b|asyncrat|remcos|njrat|quasar|darkcomet|nanocore|warzone|\bc2\b|\bc&c\b|"
                         r"command.and.control|botnet|stealer|redline|lumma|vidar|raccoon|agent.?tesla|formbook|"
                         r"loader|cobalt.?strike|emotet|qakbot|qbot|icedid|trickbot|backdoor", re.I)),
    ("medio", re.compile(r"phish|malware|malicious|trojan|exploit|dropper", re.I)),
    ("leve", re.compile(r"spam|scam|fraud", re.I)),
]
# Una sola pulse grave antigua puede ser una IP de VPS reasignada: hacen falta dos, o una reciente.
DIAS_PULSE_RECIENTE = 180
# Los valores salen del correo, que controla el atacante: solo pasan a sudo si son una IPv4 o un dominio limpios.
DOMINIO = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
ESQUEMA_DB = """
CREATE TABLE IF NOT EXISTS cache_enriquecimiento (
    fuente TEXT NOT NULL,
    valor TEXT NOT NULL,
    fecha TEXT NOT NULL,
    resultado TEXT NOT NULL,
    PRIMARY KEY (fuente, valor)
);
"""


def ahora():
    return dt.datetime.now(dt.timezone.utc)


def cacheado(db, fuente, valor, consulta):
    """Resultado de la caché si no ha caducado; si no, consulta y guarda. Los errores no se guardan."""
    fila = db.execute("SELECT fecha, resultado FROM cache_enriquecimiento WHERE fuente = ? AND valor = ?",
                      (fuente, valor)).fetchone()
    if fila and ahora() - dt.datetime.fromisoformat(fila[0]) < dt.timedelta(days=CADUCIDAD_DIAS[fuente]):
        return json.loads(fila[1])
    r = consulta(valor)
    db.execute("INSERT OR REPLACE INTO cache_enriquecimiento VALUES (?, ?, ?, ?)",
               (fuente, valor, ahora().isoformat(), json.dumps(r, ensure_ascii=False)))
    db.commit()
    return r


def otx(valor):
    if not OTX:
        raise RuntimeError("OTX no configurado")
    p = subprocess.run(OTX + [valor], capture_output=True, text=True, timeout=30)
    m = re.search(r"Apariciones en pulses de OTX: (\d+)", p.stdout)
    if p.returncode or not m:
        raise RuntimeError("OTX: %s" % (p.stderr.strip().splitlines() or ["sin respuesta"])[-1][:150])
    r = {"pulses": int(m.group(1)), "grave": 0, "grave_reciente": 0, "medio": 0, "leve": 0, "nombres": []}
    for nombre, creada, tags in re.findall(r"^\s+- (.+?) \(id=\S+, creada=(\S+), tags=(.*)\)$", p.stdout, re.M):
        nivel = next((n for n, rx in NIVELES_OTX if rx.search(nombre) or rx.search(tags)), None)
        if not nivel:
            continue
        r[nivel] += 1
        if nivel == "grave" and ahora() - dt.datetime.fromisoformat(creada.rstrip(",")).replace(
                tzinfo=dt.timezone.utc) < dt.timedelta(days=DIAS_PULSE_RECIENTE):
            r["grave_reciente"] += 1
        if len(r["nombres"]) < 5:
            r["nombres"].append("%s [%s]" % (nombre, nivel))
    return r


_ultima_rdap = 0.0


def rdap(dom):
    global _ultima_rdap
    time.sleep(max(0.0, _ultima_rdap + PAUSA_RDAP - time.time()))
    _ultima_rdap = time.time()
    # El registro de .org (tras Cloudflare) da 403 al User-Agent por defecto de Python (medido).
    req = urllib.request.Request("https://rdap.org/domain/" + dom, headers={"Accept": "application/rdap+json",
                                                                         "User-Agent": "analista-correo"})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            d = json.load(r)
    except urllib.error.HTTPError as e:
        # rdap.org redirige al registro del TLD: un 404 del registro es «no existe»; uno de rdap.org, o un 501,
        # es que ese TLD no tiene RDAP (.es, .pp.ua).
        if e.code == 404 and "rdap.org" not in (e.url or ""):
            return {"registrado": False}
        if e.code in (404, 501):
            return {"sin_servicio": True}
        raise
    alta = next((e["eventDate"] for e in d.get("events", []) if e.get("eventAction") == "registration"), None)
    return {"registrado": True, "alta": alta}


def edad_alta(alta):
    """Edad del dominio según la fecha RDAP (externa y cacheada); None si falta o no es legible."""
    if not alta:
        return None
    try:
        t = dt.datetime.fromisoformat(str(alta).replace("Z", "+00:00"))
        if t.tzinfo is None:
            t = t.replace(tzinfo=dt.timezone.utc)
        return ahora() - t
    except (TypeError, ValueError):
        return None


def lista(nombre):
    """Lista pública descargada como mucho una vez al día en ESTADO/listas."""
    f = ESTADO / "listas" / (nombre + ".txt")
    if not f.exists() or time.time() - f.stat().st_mtime > CADUCIDAD_DIAS["lista"] * 86400:
        f.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with urllib.request.urlopen(LISTAS[nombre], timeout=30) as r:
            datos = r.read()
        if datos.strip():  # una descarga vacía no pisa la lista anterior
            tmp = f.with_suffix(".tmp")
            tmp.write_bytes(datos)
            tmp.replace(f)
    redes = []
    for linea in f.read_text(errors="replace").splitlines():
        linea = linea.split(";")[0].strip()
        if linea and not linea.startswith("#"):
            try:
                redes.append(ipaddress.ip_network(linea, strict=False))
            except ValueError:
                pass
    return redes


def dig(*args):
    p = subprocess.run(["dig", "+short", "+time=3", "+tries=2", *args], capture_output=True, text=True, timeout=20)
    if p.returncode:
        raise RuntimeError("dig: código %d" % p.returncode)
    return [l.strip().strip('"') for l in p.stdout.splitlines() if l.strip()]


def cymru(ip):
    """ASN de origen y prefijo por el DNS de Team Cymru, sin clave. Solo recibe IPs ya validadas."""
    a = ipaddress.ip_address(ip)
    zona = "origin.asn.cymru.com" if a.version == 4 else "origin6.asn.cymru.com"
    nombre = a.reverse_pointer.rsplit(".", 2)[0] + "." + zona  # quita in-addr.arpa / ip6.arpa
    filas = [l.split(" | ") for l in dig("TXT", nombre)]
    filas = [f for f in filas if len(f) >= 3 and f[0].split()[0].isdigit()]
    if not filas:
        return {"asn": None}
    f = max(filas, key=lambda f: int(f[1].split("/")[1]))  # el prefijo más específico
    return {"asn": int(f[0].split()[0]), "prefijo": f[1].strip(), "pais": f[2].strip()}


def cymru_as(asn):
    f = next((l.split(" | ") for l in dig("TXT", "AS%d.asn.cymru.com" % int(asn))), [])
    return {"titular": f[4].strip() if len(f) >= 5 else ""}


def ptr(ip):
    nombres = [n.rstrip(".").lower() for n in dig("-x", str(ipaddress.ip_address(ip)))]
    return {"ptr": nombres[0] if nombres else ""}


def alias_ptr(nombre):
    """CNAME del PTR: un subdominio de una web conocida que apunta a un dominio del atacante (www.tienda.example.com ->
    tienda-example.net) da a sus servidores un rDNS creíble."""
    if not DOMINIO.fullmatch(nombre):
        return {"alias": ""}  # el rDNS lo pone el dueño de la IP: nunca llega a dig sin validar
    nombres = [n.rstrip(".").lower() for n in dig("CNAME", nombre)]
    return {"alias": nombres[0] if nombres else ""}


def marca_ptr(nombre):
    """Marca conocida en el PTR, incluido su dominio propio (www.tienda.marca.com)."""
    for etiqueta in nombre.split(".")[:-1]:
        for m in MARCAS:
            if m in etiqueta and (len(m) > 3 or re.fullmatch(r"%s\d*" % m, etiqueta)):
                return m
    return ""


def ip_en_ptr(ip, nombre):
    p = ip.split(".")
    return len(p) == 4 and any(sep.join(o) in nombre for o in (p, p[::-1]) for sep in "-.")


def historial(db, tipo, valor, huella=""):
    """(correos maliciosos distintos, correos distintos) con este IOC en los últimos DIAS_HISTORIAL días."""
    desde = (ahora() - dt.timedelta(days=DIAS_HISTORIAL)).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        return db.execute("SELECT count(DISTINCT CASE WHEN a.veredicto = 'malicioso' THEN a.huella END), "
                          "count(DISTINCT a.huella) FROM iocs i JOIN analisis a ON a.id = i.analisis_id "
                          "WHERE i.tipo = ? AND i.valor = ? AND a.fecha >= ? AND a.huella != ?",
                          (tipo, valor, desde, huella or "")).fetchone()
    except sqlite3.OperationalError:
        return 0, 0  # base de datos sin tablas de buzon.py (pruebas)


def filas_infra(infra):
    """Filas de la tabla iocs: nodos del grafo; en raiz, su nodo padre (prefijo -> ASN, PTR -> dominio)."""
    filas = []
    for x in infra:
        if x.get("asn"):
            filas += [("asn", "AS%d" % x["asn"], "AS%d" % x["asn"], "origen", False),
                      ("prefijo", x["prefijo"], "AS%d" % x["asn"], "origen", False)]
        if x.get("ptr"):
            filas.append(("ptr", x["ptr"], base(x["ptr"]), "origen", False))
        if x.get("alias_ptr"):
            filas.append(("alias_ptr", x["alias_ptr"], base(x["alias_ptr"]), "origen", False))
    return filas


def populares():
    """Los TOP_POPULARES primeros de Tranco, descargados como mucho una vez por semana en ESTADO/listas."""
    f = ESTADO / "listas" / "tranco.txt"
    if not f.exists() or time.time() - f.stat().st_mtime > CADUCIDAD_DIAS["tranco"] * 86400:
        f.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with urllib.request.urlopen(TRANCO, timeout=120) as r:
            z = zipfile.ZipFile(io.BytesIO(r.read()))
        lineas = z.read(z.namelist()[0]).decode().splitlines()[:TOP_POPULARES]
        nombres = [l.split(",", 1)[1].strip().lower() for l in lineas if "," in l]
        if len(nombres) < TOP_POPULARES // 2:
            raise RuntimeError("Tranco: solo %d dominios" % len(nombres))
        tmp = f.with_suffix(".tmp")
        tmp.write_text("\n".join(nombres) + "\n")
        tmp.replace(f)
    return set(f.read_text().split())


def clave_abusech():
    try:
        if CONFIG.stat().st_mode & (stat.S_IRWXG | stat.S_IRWXO):
            return ""  # buzon.py ya se niega a arrancar así; aquí basta con no usarla
        for linea in CONFIG.read_text().splitlines():
            if linea.startswith("ABUSECH_AUTH_KEY="):
                return linea.split("=", 1)[1].strip().strip('"').strip("'")
    except OSError:
        pass
    return ""


def abusech(servicio, clave, datos=None, js=None):
    cab = {"Auth-Key": clave, "User-Agent": "analista-correo"}
    if js is not None:
        cuerpo, cab["Content-Type"] = json.dumps(js).encode(), "application/json"
    else:
        cuerpo = urllib.parse.urlencode(datos).encode()
    with urllib.request.urlopen(urllib.request.Request(ABUSECH[servicio], cuerpo, cab), timeout=20) as r:
        return json.load(r)


def reciente(fecha):
    """Fechas de abuse.ch («2026-10-07 14:57:26 UTC») de los últimos DIAS_PULSE_RECIENTE días."""
    try:
        f = dt.datetime.strptime(fecha[:19], "%Y-%m-%d %H:%M:%S").replace(tzinfo=dt.timezone.utc)
    except (TypeError, ValueError):
        return False
    return ahora() - f < dt.timedelta(days=DIAS_PULSE_RECIENTE)


# Solo se guarda si aparece y un resumen, no la respuesta entera (condiciones de uso de abuse.ch).
def urlhaus(clave, valor, tipo):
    r = abusech("urlhaus_url" if tipo == "url" else "urlhaus_host", clave, {tipo: valor})
    if r.get("query_status") != "ok":
        return {"encontrado": False}
    urls = r.get("urls") or [r]
    return {"encontrado": True, "reciente": any(u.get("url_status") == "online" or reciente(u.get("date_added"))
                                                for u in urls),
            "detalle": "%d URLs de malware (%s)" % (len(urls), ", ".join(sorted({u.get("threat") or "?"
                                                                                 for u in urls})[:3]))}


def threatfox(clave, valor):
    es_ip = bool(re.fullmatch(r"[0-9.]+|[0-9a-fA-F:]+", valor))
    # Las IPs están como «ip:puerto»: búsqueda parcial y luego comparación exacta de la IP.
    r = abusech("threatfox", clave, js={"query": "search_ioc", "search_term": valor, "exact_match": not es_ip})
    d = r.get("data") if r.get("query_status") == "ok" and isinstance(r.get("data"), list) else []
    if es_ip:
        d = [x for x in d if str(x.get("ioc", "")).rsplit(":", 1)[0].strip("[]") == valor]
    if not d:
        return {"encontrado": False}
    # ThreatFox caduca los IOCs a los 6 meses: lo que devuelve la API es reciente.
    return {"encontrado": True, "reciente": True, "detalle": "; ".join(sorted({"%s %s" % (
        x.get("threat_type") or "?", x.get("malware_printable") or "") for x in d})[:3])}


def bazaar(clave, sha256):
    r = abusech("bazaar", clave, {"query": "get_info", "hash": sha256})
    d = r.get("data") if r.get("query_status") == "ok" and isinstance(r.get("data"), list) else []
    if not d:
        return {"encontrado": False}
    return {"encontrado": True, "reciente": True, "detalle": "muestra conocida: %s %s" % (
        d[0].get("signature") or "sin familia", d[0].get("file_type") or "")}


def enriquecer(iocs, db, solo_infra=False, huella=""):
    """Consulta los IOCs no compartidos y devuelve hallazgos con puntos. Nunca visita las URLs del correo.
    solo_infra: solo ASN, prefijo y PTR de la IP de origen (para rellenar análisis antiguos).
    huella: la del correo analizado, que no cuenta en su propio historial (reanálisis, versión nueva)."""
    hallazgos, errores, consultas, infra = [], [], 0, []
    antiguo = False

    def hallar(tipo, valor, fuente, detalle, clave):
        hallazgos.append({"tipo": tipo, "valor": valor, "fuente": fuente, "detalle": detalle, "puntos": PUNTOS[clave]})

    def hallar_otx(tipo, valor, r):
        if not r:
            return
        ejemplos = "; ".join(r["nombres"][:2])
        if r["grave"] >= 2 or r["grave_reciente"]:
            hallar(tipo, valor, "otx", "%d pulses graves (%d recientes): %s" % (r["grave"], r["grave_reciente"],
                                                                              ejemplos), "otx_grave")
            hallazgos[-1]["suelo"] = SUELO_GRAVE
        elif r["grave"] or r["medio"]:
            hallar(tipo, valor, "otx", "%d pulses de amenazas: %s" % (r["grave"] + r["medio"], ejemplos),
                   "otx_ip" if tipo == "ip" else "otx_dominio")
        elif r["leve"]:
            hallar(tipo, valor, "otx", "%d pulses de spam o fraude: %s" % (r["leve"], ejemplos), "otx_leve")

    def hallar_abusech(tipo, valor, fuente, r):
        if r and r["encontrado"]:
            hallar(tipo, valor, fuente, r["detalle"] + ("" if r["reciente"] else " (antiguo)"),
                   "abusech_grave" if r["reciente"] else "abusech_antiguo")
            if r["reciente"]:
                hallazgos[-1]["suelo"] = SUELO_GRAVE

    def consultar(fuente, valor, fn):
        nonlocal consultas
        consultas += 1
        try:
            return cacheado(db, fuente, valor, fn)
        except Exception as e:
            errores.append("%s %s: %s: %s" % (fuente, valor, type(e).__name__, str(e)[:150]))
            return None

    def origen(i):
        """ASN, prefijo y PTR de la IP de origen; puntúa el PTR y el historial propio del prefijo o del ASN."""
        x = {"ip": i["ip"]}
        x.update(consultar("cymru", i["ip"], cymru) or {})
        if x.get("asn"):
            x.update(consultar("cymru_as", str(x["asn"]), cymru_as) or {})
        # El rDNS que anotó el MX al recibirlo; si no lo hay, el PTR de ahora.
        candidatos = []
        x["ptr"] = (i.get("rdns") or "").lower()
        x["ptr_fuente"] = "mx"
        if not x["ptr"] or x["ptr"] == "unknown":
            x["ptr"], x["ptr_fuente"] = (consultar("ptr", i["ip"], ptr) or {}).get("ptr", ""), "dns"
        alias = (consultar("alias_ptr", x["ptr"], alias_ptr) or {}).get("alias", "") if x["ptr"] else ""
        if alias and base(alias) != base(x["ptr"]):
            x["alias_ptr"] = alias
            hallar("ip", i["ip"], "alias_ptr", "PTR %s es hoy un alias de otro dominio: %s" % (x["ptr"], alias), "info")
        if x.get("asn"):
            hallar("ip", i["ip"], "cymru", "AS%d %s, %s (%s); PTR %s" % (
                x["asn"], x.get("titular", ""), x["prefijo"], x["pais"], x["ptr"] or "ninguno"), "info")
        m = marca_ptr(x["ptr"])
        if m and m not in x.get("titular", "").lower():
            hallar("ip", i["ip"], "ptr", "PTR %s con la marca «%s» en un ASN ajeno (%s)" % (
                x["ptr"], m, x.get("titular") or "desconocido"), "ptr_marca")
        elif x["ptr"] and (PTR_GENERICO.search(x["ptr"].split(".")[0]) or ip_en_ptr(i["ip"], x["ptr"])):
            hallar("ip", i["ip"], "ptr", "PTR genérico de proveedor: %s" % x["ptr"], "ptr_generico")
        elif not x["ptr"]:
            hallar("ip", i["ip"], "ptr", "sin PTR", "ptr_ausente")
        for tipo, valor, clave in (("prefijo", x.get("prefijo"), "prefijo_historial"),
                                   ("asn", "AS%d" % x["asn"] if x.get("asn") else None, "asn_historial")):
            if not valor:
                continue
            mal, total = historial(db, tipo, valor, huella)
            if mal >= MIN_MALICIOSOS and 2 * mal >= total:
                alto = (mal >= ALTO_MIN_MALICIOSOS and mal * 100 >= ALTO_PORCENTAJE * total
                        and base(x["ptr"]) not in PROVEEDORES_ENVIO)
                if alto or not candidatos:
                    candidatos.append((PUNTOS["historial_alto" if alto else clave], tipo, valor, mal, total, alto))
        if candidatos:  # el prefijo es más concreto, pero un ASN en el escalón alto pesa más: suma solo uno
            _, tipo, valor, mal, total, alto = max(candidatos, key=lambda c: c[0])
            hallar(tipo, valor, "historial", "%d de %d correos de los últimos %d días con este %s fueron "
                   "maliciosos" % (mal, total, DIAS_HISTORIAL, tipo), "historial_alto" if alto else
                   ("prefijo_historial" if tipo == "prefijo" else "asn_historial"))
            if alto:
                hallazgos[-1]["alto"] = True
        return x

    ips = [i for i in iocs["ips"] if not i.get("compartido")]
    if solo_infra:
        infra = [origen(i) for i in ips if i.get("rol") == "origen"]
        return {"hallazgos": hallazgos, "errores": errores, "infraestructura": infra}
    try:
        redes = {n: lista(n) for n in LISTAS}
    except Exception as e:
        redes = {}
        errores.append("listas: %s: %s" % (type(e).__name__, str(e)[:150]))
    for i in ips:
        ip = ipaddress.ip_address(i["ip"])
        for n, rs in redes.items():
            if any(ip in r for r in rs):
                hallar("ip", i["ip"], n, "en la lista %s" % n, n)
        if ip.version == 4:
            hallar_otx("ip", i["ip"], consultar("otx", i["ip"], otx))
        if i.get("rol") == "origen":
            infra.append(origen(i))
    raices = sorted({d["raiz"] for d in iocs["dominios"] if not d["compartido"] and DOMINIO.fullmatch(d["raiz"])})
    try:
        pop = populares()
    except Exception as e:
        pop = set()
        errores.append("tranco: %s: %s" % (type(e).__name__, str(e)[:150]))
    exentos = [r for r in raices if r in pop and r not in ANFITRIONES_LIBRES]
    raices = [r for r in raices if r not in exentos]
    for raiz in raices:
        hallar_otx("dominio", raiz, consultar("otx", raiz, otx))
        if ".".join(raiz.split(".")[-2:]) in SUFIJOS:
            continue  # uk.com, pp.ua…: rdap.org pregunta al registro de .com o .ua, que no los conoce
        r = consultar("rdap", raiz, rdap)
        if not r or r.get("sin_servicio"):
            continue
        edad = edad_alta(r.get("alta"))
        if edad is not None and edad.days > DIAS_ANTIGUO:
            antiguo = True
        if not r["registrado"]:
            hallar("dominio", raiz, "rdap", "ya no está registrado", "dominio_no_registrado")
        elif edad is not None:
            dias = edad.days
            horas = edad.total_seconds() // 3600
            suelo = next((s for h, s in SUELO_DOMINIO_HORAS if horas < h), 0)
            if suelo:
                hallar("dominio", raiz, "rdap", "registrado hace %d horas" % horas, "dominio_nuevo")
                hallazgos[-1]["suelo"] = suelo
            elif dias < DIAS_NUEVO:
                hallar("dominio", raiz, "rdap", "registrado hace %d días" % dias, "dominio_nuevo")
            elif dias < DIAS_RECIENTE:
                hallar("dominio", raiz, "rdap", "registrado hace %d días" % dias, "dominio_reciente")
    clave = clave_abusech()
    if clave:
        for i in ips:
            hallar_abusech("ip", i["ip"], "threatfox", consultar("threatfox", i["ip"], lambda v: threatfox(clave, v)))
            hallar_abusech("ip", i["ip"], "urlhaus", consultar("urlhaus", i["ip"],
                                                               lambda v: urlhaus(clave, v, "host")))
        for raiz in raices:
            hallar_abusech("dominio", raiz, "threatfox", consultar("threatfox", raiz, lambda v: threatfox(clave, v)))
            hallar_abusech("dominio", raiz, "urlhaus", consultar("urlhaus", raiz, lambda v: urlhaus(clave, v, "host")))
        # En alojamiento compartido el IOC es la URL. Sin consulta ni fragmento: suelen llevar el usuario o un token.
        compartidos = {d["dominio"] for d in iocs["dominios"] if d["compartido"]}
        urls = sorted({urllib.parse.urlsplit(u)._replace(query="", fragment="").geturl() for u in iocs.get("urls", [])
                       if (urllib.parse.urlsplit(u).hostname or "") in compartidos})
        for u in urls[:10]:
            hallar_abusech("url", u, "urlhaus", consultar("urlhaus", u, lambda v: urlhaus(clave, v, "url")))
        for h in iocs.get("hashes", []):
            hallar_abusech("sha256", h["sha256"], "malwarebazaar", consultar("bazaar", h["sha256"],
                                                                             lambda v: bazaar(clave, v)))
    for h in hallazgos:
        if h.pop("alto", False) and antiguo:
            h["puntos"], h["detalle"] = PUNTOS["prefijo_historial" if h["tipo"] == "prefijo" else "asn_historial"], h["detalle"] + " (dominio de más de 2 años: sin escalón alto)"
    return {"hallazgos": hallazgos, "puntos": min(TOPE, sum(h["puntos"] for h in hallazgos)),
            "suelo": max([h.get("suelo", 0) for h in hallazgos], default=0), "consultas": consultas,
            "errores": errores, "infraestructura": infra, "populares": exentos}


def abrir_db(ruta):
    db = sqlite3.connect(ruta)
    db.executescript(ESQUEMA_DB)
    return db


def iocs_de_tabla(db, analisis_id):
    iocs = {"ips": [], "dominios": [], "hashes": []}
    for tipo, valor, raiz, rol, comp in db.execute(
            "SELECT tipo, valor, raiz, rol, compartido FROM iocs WHERE analisis_id = ?", (analisis_id,)):
        if tipo == "ip":
            iocs["ips"].append({"ip": valor, "rol": rol, "compartido": bool(comp)})
        elif tipo == "dominio":
            iocs["dominios"].append({"dominio": valor, "raiz": raiz, "compartido": bool(comp)})
    return iocs


def rellenar_infra(db):
    """Añade ASN, prefijo y PTR a los análisis guardados que no los tienen. Sin rDNS del MX guardado, el PTR es el
    de hoy."""
    for aid, guardado in db.execute(
            "SELECT id, resultado FROM analisis a WHERE EXISTS (SELECT 1 FROM iocs i WHERE i.analisis_id = a.id AND "
            "i.tipo = 'ip' AND i.rol = 'origen' AND i.compartido = 0) AND NOT EXISTS (SELECT 1 FROM iocs i WHERE "
            "i.analisis_id = a.id AND i.tipo IN ('asn', 'ptr')) ORDER BY id").fetchall():
        rdns = {i["ip"]: i.get("rdns", "") for i in json.loads(guardado).get("iocs", {}).get("ips", [])}
        iocs = iocs_de_tabla(db, aid)
        for i in iocs["ips"]:
            i["rdns"] = rdns.get(i["ip"], "")
        e = enriquecer(iocs, db, solo_infra=True)
        filas = filas_infra(e["infraestructura"])
        db.executemany("INSERT OR IGNORE INTO iocs (analisis_id, tipo, valor, raiz, rol, compartido) "
                       "VALUES (?, ?, ?, ?, ?, ?)", [(aid, t, v, r, rol, int(c)) for t, v, r, rol, c in filas])
        db.commit()
        print("#%d %s" % (aid, "; ".join(h["detalle"] for h in e["hallazgos"]) or "sin datos"),
              *("error: " + x for x in e["errores"]))


def simular(db):
    """Qué cambiaría en los análisis guardados si el enriquecimiento sumara al riesgo técnico."""
    for aid, guardado in db.execute("SELECT id, resultado FROM analisis ORDER BY id").fetchall():
        r = json.loads(guardado)
        if r.get("enriquecimiento") is not None:
            continue  # desde la 1.2 ya va sumado en riesgo_tecnico
        e = enriquecer(iocs_de_tabla(db, aid), db)
        riesgo, veredicto = combinar(min(100, r["riesgo_tecnico"] + e["puntos"]), r["modelo"], r["adjuntos"],
                                     e["suelo"])
        print("#%d %s\n   ahora: %s %d (técnico %d) -> con enriquecimiento: %s %d (+%d, %d consultas)" % (
            aid, r["correo"]["subject"][:70], r["veredicto"], r["riesgo"], r["riesgo_tecnico"], veredicto, riesgo,
            e["puntos"], e["consultas"]))
        for h in e["hallazgos"]:
            print("   +%d %s %s (%s): %s" % (h["puntos"], h["tipo"], h["valor"], h["fuente"], h["detalle"]))
        for x in e["errores"]:
            print("   error: %s" % x)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--simular", action="store_true", help="aplica el enriquecimiento a los análisis guardados "
                    "sin modificarlos")
    ap.add_argument("--rellenar-infra", action="store_true", help="añade ASN, prefijo y PTR a los análisis "
                    "guardados que no los tienen")
    ap.add_argument("--reenviado", action="store_true", help="con eml: reenvío sin cabeceras del original")
    ap.add_argument("eml", nargs="*", type=Path, help="enriquece los IOCs de estos .eml (sin modelo)")
    a = ap.parse_args()
    db = abrir_db(DB)
    if a.simular:
        simular(db)
        return
    if a.rellenar_infra:
        rellenar_infra(db)
        return
    for f in a.eml:
        r = analizar(f.read_bytes(), a.reenviado, usar_modelo=False)
        print(json.dumps({"fichero": str(f), **enriquecer(r["iocs"], db)}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
