#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 k4y53r
"""Lee del buzón los correos reenviados para análisis, los analiza y responde con el JSON. Ver README.md."""

import argparse, datetime as dt, email, functools, hashlib, imaplib, json, os, re, smtplib, sqlite3, ssl, stat, sys, time
from email import policy
from email.message import EmailMessage
from email.utils import formatdate, make_msgid, parseaddr
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from analizar_correo import VERSION, analizar, autenticacion, base  # noqa: E402
from enriquecer import ESQUEMA_DB as ESQUEMA_ENRIQUECER, alias_ptr, cacheado, enriquecer, filas_infra  # noqa: E402
try:  # opcional: contrib/graylog (exportación de IOCs a Graylog)
    import exportar_graylog  # noqa: E402
except ImportError:
    exportar_graylog = None

CONFIG = Path(os.environ.get("ANALISTA_CORREO_ENV", Path.home() / ".config/analista-correo/buzon.env"))
ESTADO = Path.home() / ".local/state/analista-correo"
DB = ESTADO / "analisis.db"
MAX_POR_PASADA = 6         # ~1-2 min por correo más la pausa: cabe de sobra en el timeout de 25 min de run.sh
# Pausa entre correos para que la CPU se enfríe cuando el modelo corre en un equipo sin refrigeración holgada.
PAUSA_ENTRE_CORREOS = 60
# ANALISTA_CORREO_SIN_ENRIQUECER=1: no consulta ningún servicio externo (abuse.ch, listas públicas, RDAP, OTX); solo reglas y modelo local.
SIN_ENRIQUECER = os.environ.get("ANALISTA_CORREO_SIN_ENRIQUECER", "") not in ("", "0")
# Solo vale el Authentication-Results del MX del buzón (MX_BUZON en buzon.env): es el primero; los de debajo los puede escribir el remitente.
ESQUEMA_DB = """
CREATE TABLE IF NOT EXISTS analisis (
    id INTEGER PRIMARY KEY,
    fecha TEXT NOT NULL,
    version TEXT NOT NULL,
    huella TEXT NOT NULL,
    message_id TEXT NOT NULL,
    asunto TEXT NOT NULL,
    modo TEXT NOT NULL,
    veredicto TEXT NOT NULL,
    riesgo INTEGER NOT NULL,
    resultado TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS analisis_huella ON analisis (huella);
CREATE INDEX IF NOT EXISTS analisis_message_id ON analisis (message_id);
CREATE TABLE IF NOT EXISTS envios (
    id INTEGER PRIMARY KEY,
    fecha TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    remitente TEXT NOT NULL,
    asunto TEXT NOT NULL,
    analisis_id INTEGER NOT NULL REFERENCES analisis (id),
    reutilizado INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS iocs (
    id INTEGER PRIMARY KEY,
    analisis_id INTEGER NOT NULL REFERENCES analisis (id),
    tipo TEXT NOT NULL,
    valor TEXT NOT NULL,
    raiz TEXT NOT NULL,
    rol TEXT NOT NULL,
    compartido INTEGER NOT NULL,
    UNIQUE (analisis_id, tipo, valor)
);
CREATE INDEX IF NOT EXISTS iocs_valor ON iocs (valor);
CREATE INDEX IF NOT EXISTS iocs_raiz ON iocs (raiz);
"""


def log(msg):
    print("%s %s" % (time.strftime("%Y-%m-%dT%H:%M:%S"), msg), flush=True)


def cargar_config():
    if not CONFIG.exists():
        sys.exit("falta %s: copia buzon.env.example a esa ruta, edítalo y ponle chmod 600 (o usa ANALISTA_CORREO_ENV)" % CONFIG)
    if CONFIG.stat().st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        sys.exit("%s debe ser 600: contiene la contraseña del buzón" % CONFIG)
    cfg = {}
    for linea in CONFIG.read_text().splitlines():
        if "=" in linea and not linea.lstrip().startswith("#"):
            k, v = linea.split("=", 1)
            cfg[k.strip()] = v.strip().strip('"').strip("'")
    faltan = {"IMAP_HOST", "SMTP_HOST", "MAIL_USER", "MAIL_PASS", "REMITENTES"} - cfg.keys()
    if faltan:
        sys.exit("faltan en %s: %s" % (CONFIG, ", ".join(sorted(faltan))))
    cfg["REMITENTES"] = {r.strip().lower() for r in cfg["REMITENTES"].split(",") if r.strip()}
    return cfg


DOMINIO_EN_TEXTO = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b", re.I)


def desactivar(s):
    """URLs y dominios del correo sin enlace al leer la respuesta: hxxp y [.] (Gmail enlaza cualquier dominio)."""
    s = re.sub(r"\bhttp(s?)://", r"hxxp\1://", str(s or ""), flags=re.I)
    return DOMINIO_EN_TEXTO.sub(lambda m: m.group(0).replace(".", "[.]"), s)


def texto_resumen(r):
    c, e = r["correo"], r["reenvio"]
    lineas = ["Correo analizado:",
              "  Asunto: %s" % (desactivar(c["subject"]) or "(sin asunto)"),
              "  Remitente: %s" % (desactivar(c["from"]) or "no disponible (reenvío sin cabeceras del original)"),
              "  Fecha: %s" % (c["date"] or "no disponible"),
              "Tu envío: \"%s\" (%s)" % (desactivar(e["asunto"]), e["fecha"]),
              "Referencia: %s" % r["sha256"][:12]]
    v = e.get("verificacion")
    if v:
        lineas.append("Tu envío: %s (%s)" % ("verificado" if v["verificado"] else "NO VERIFICADO", v["detalle"]))
    lineas.append("")
    if r.get("duplicado"):
        lineas += ["YA ANALIZADO el %s: se reenvía el resultado guardado sin volver a analizarlo." %
                   r["duplicado"]["fecha"], ""]
    lineas += ["Veredicto: %s (riesgo %d/100)" % (r["veredicto"].upper(), r["riesgo"]), r["recomendacion"], ""]
    m = r.get("modelo") or {}
    if m.get("explicacion"):
        lineas += ["Modelo (%s): %s, %s" % (m["nombre"], m["clasificacion"], desactivar(m["explicacion"])), ""]
    if r["indicadores"]:
        lineas.append("Indicadores técnicos:")
        lineas += ["- %s" % desactivar(i["texto"]) for i in r["indicadores"]]
        lineas.append("")
    lineas += ["Aviso: %s" % desactivar(a) for a in r["avisos"]]
    lineas += ["", "El análisis completo va adjunto como analisis.json. Es automático y puede equivocarse."]
    return "\n".join(lineas)


def respuesta(cfg, original, r):
    msg = EmailMessage()
    asunto = (r["correo"]["subject"] or r["reenvio"]["asunto"])[:120]
    msg["Subject"] = "[%s %d/100] %s" % (r["veredicto"], r["riesgo"], desactivar(asunto))
    msg["From"] = cfg["MAIL_USER"]
    msg["To"] = parseaddr(str(original.get("From")))[1]
    msg["Message-ID"] = make_msgid(domain=cfg["MAIL_USER"].split("@")[-1])
    if original.get("Message-ID"):
        msg["In-Reply-To"] = msg["References"] = str(original["Message-ID"])
    msg["Date"] = formatdate(localtime=True)  # sin Date, algunos proveedores rechazan con 550 5.7.1 (ver README)
    msg["Auto-Submitted"] = "auto-replied"
    msg.set_content(texto_resumen(r))
    msg.add_attachment(json.dumps(r, ensure_ascii=False, indent=2).encode(), maintype="application",
                       subtype="json", filename="analisis.json")
    return msg


def guardar(raw):
    d = ESTADO / "correos"
    d.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(d / (hashlib.sha256(raw).hexdigest() + ".eml"), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(raw)


def abrir_db(ruta):
    if ruta != ":memory:":
        ruta.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    db = sqlite3.connect(ruta)
    db.executescript(ESQUEMA_DB + ESQUEMA_ENRIQUECER)
    return db


def buscar(db, previo):
    """Análisis guardado del mismo correo con la versión actual. El Message-ID solo cuenta junto al asunto:
    hay campañas que lo falsifican."""
    c = previo["correo"]
    return db.execute("SELECT id, fecha, resultado FROM analisis WHERE version = ? AND (huella = ? OR "
                      "(message_id != '' AND message_id = ? AND asunto = ?)) ORDER BY id DESC LIMIT 1",
                      (VERSION, previo["huella"], c["message_id"], c["subject"])).fetchone()


def guardar_iocs(db, analisis_id, iocs, enr=None):
    filas = [("ip", i["ip"], i["ip"], i["rol"], i.get("compartido", False)) for i in iocs["ips"]]
    filas += filas_infra((enr or {}).get("infraestructura", []))
    filas += [("dominio", d["dominio"], d["raiz"], ",".join(d["roles"]), d["compartido"]) for d in iocs["dominios"]]
    filas += [("url", u, "", "url", False) for u in iocs["urls"]]
    filas += [("direccion", a, a.split("@")[-1], "remitente", False) for a in iocs["direcciones"]]
    filas += [("sha256", h["sha256"], "", h["nombre"], False) for h in iocs["hashes"]]
    filas += filas_campana(iocs)
    db.executemany("INSERT OR IGNORE INTO iocs (analisis_id, tipo, valor, raiz, rol, compartido) "
                   "VALUES (?, ?, ?, ?, ?, ?)", [(analisis_id, t, v, r, rol, int(c)) for t, v, r, rol, c in filas])


def filas_campana(iocs):
    return [(m["tipo"], m["valor"], m["raiz"], "campana", False) for m in iocs.get("campana", [])]


def rellenar_campana(db):
    """Añade plantilla, kit y alias del PTR a los análisis guardados, desde la copia del .eml y sin modelo. El alias
    es el de hoy, no el del día en que llegó el correo."""
    pendientes = db.execute("SELECT a.id, (SELECT sha256 FROM envios e WHERE e.analisis_id = a.id LIMIT 1) "
                            "FROM analisis a WHERE NOT EXISTS (SELECT 1 FROM iocs i WHERE i.analisis_id = a.id "
                            "AND i.rol = 'campana') ORDER BY a.id")
    for analisis_id, sha in pendientes.fetchall():
        f = ESTADO / "correos" / ("%s.eml" % sha)
        if not sha or not f.exists():
            log("sin copia del correo para el análisis %d" % analisis_id)
            continue
        filas = filas_campana(analizar(f.read_bytes(), reenviado=True, usar_modelo=False)["iocs"])
        for (nombre,) in db.execute("SELECT valor FROM iocs WHERE analisis_id = ? AND tipo = 'ptr'",
                                    (analisis_id,)).fetchall():
            alias = cacheado(db, "alias_ptr", nombre, alias_ptr).get("alias", "")
            if alias and base(alias) != base(nombre):
                filas.append(("alias_ptr", alias, base(alias), "origen", False))
        db.executemany("INSERT OR IGNORE INTO iocs (analisis_id, tipo, valor, raiz, rol, compartido) "
                       "VALUES (?, ?, ?, ?, ?, ?)", [(analisis_id, t, v, r, rol, int(c)) for t, v, r, rol, c in filas])
        db.commit()
        print("#%d %s" % (analisis_id, ", ".join("%s %s" % (t, v[:60]) for t, v, *_ in filas) or "nada"))


def reanalizar_guardados(db, ids):
    """Vuelve a analizar estos análisis desde la copia del .eml, con modelo y sin responder. El nuevo sustituye al
    anterior para la exportación a Graylog (vale el último del mismo correo)."""
    for aid in ids:
        fila = db.execute("SELECT (SELECT sha256 FROM envios e WHERE e.analisis_id = a.id LIMIT 1), a.veredicto, "
                          "a.riesgo, a.version FROM analisis a WHERE a.id = ?", (aid,)).fetchone()
        f = ESTADO / "correos" / ("%s.eml" % (fila[0] if fila else ""))
        if not fila or not f.exists():
            log("sin copia del correo para el análisis %d" % aid)
            continue
        r = analizar(f.read_bytes(), reenviado=True, enriquecer=None if SIN_ENRIQUECER else functools.partial(enriquecer, db=db))
        c = r["correo"]
        nuevo = db.execute(
            "INSERT INTO analisis (fecha, version, huella, message_id, asunto, modo, veredicto, riesgo, resultado) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (ahora(), r["version"], r["huella"], c["message_id"], c["subject"], r["modo"], r["veredicto"],
             r["riesgo"], json.dumps(r, ensure_ascii=False))).lastrowid
        guardar_iocs(db, nuevo, r["iocs"], r.get("enriquecimiento"))
        db.commit()
        log("reanalizado #%d (%s, %s %d) como #%d: %s %d" % (aid, fila[3], fila[1], fila[2], nuevo, r["veredicto"],
                                                           r["riesgo"]))
        if aid != ids[-1]:
            time.sleep(PAUSA_ENTRE_CORREOS)
    if exportar_graylog:
        exportar_graylog.escribir(exportar_graylog.recoger(db), exportar_graylog.SALIDA)


def rellenar_iocs(db):
    """Saca los IOCs de los análisis anteriores a la tabla, desde la copia del .eml y sin llamar al modelo."""
    pendientes = db.execute("SELECT a.id, (SELECT sha256 FROM envios e WHERE e.analisis_id = a.id LIMIT 1) "
                            "FROM analisis a WHERE NOT EXISTS (SELECT 1 FROM iocs i WHERE i.analisis_id = a.id)")
    for analisis_id, sha in pendientes.fetchall():
        f = ESTADO / "correos" / ("%s.eml" % sha)
        if not sha or not f.exists():
            log("sin copia del correo para el análisis %d" % analisis_id)
            continue
        guardar_iocs(db, analisis_id, analizar(f.read_bytes(), reenviado=True, usar_modelo=False)["iocs"])
    db.commit()


def ahora():
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def verificar_remitente(original, remitente, mx_buzon):
    """DKIM del reenvío según el MX del buzón: pass y del dominio del From (o un subdominio suyo)."""
    auth = autenticacion(original)
    if not mx_buzon or not auth.get("fuente", "").lower().startswith(mx_buzon.lower()):
        return {"verificado": False, "detalle": "sin Authentication-Results de %s" % (mx_buzon or "MX_BUZON (no configurado)")}
    dom, d = remitente.rsplit("@", 1)[-1], auth.get("dkim_dominio", "")
    ok = auth["dkim"] == "pass" and (d == dom or d.endswith("." + dom))
    return {"verificado": ok, "detalle": "DKIM %s, dominio %s" % (auth["dkim"], d or "ninguno")}


def procesar(cfg, raw, enviar, db, copia=True, reanalizar=False):
    original = email.message_from_bytes(raw, policy=policy.default)
    remitente = parseaddr(str(original.get("From")))[1].lower()
    if remitente not in cfg["REMITENTES"]:
        log("ignorado: remitente no autorizado (%s)" % remitente)
        return False
    if str(original.get("Auto-Submitted", "no")).lower() != "no":
        log("ignorado: respuesta automática de %s" % remitente)
        return False
    verificacion = verificar_remitente(original, remitente, cfg.get("MX_BUZON", ""))
    if not verificacion["verificado"]:
        if cfg.get("EXIGIR_DKIM", "no").lower() in ("si", "sí", "yes", "1"):
            log("ignorado: remitente %s sin verificar (%s)" % (remitente, verificacion["detalle"]))
            return False
        log("aviso: remitente %s sin verificar (%s)" % (remitente, verificacion["detalle"]))
    # Sin modelo es instantáneo: basta para sacar huella y Message-ID antes de decidir si hace falta el modelo.
    fila = None if reanalizar else buscar(db, analizar(raw, reenviado=True, usar_modelo=False))
    if fila:
        analisis_id, fecha, guardado = fila
        r = json.loads(guardado)
        r["duplicado"] = {"analisis_id": analisis_id, "fecha": fecha}
    else:
        r = analizar(raw, reenviado=True, enriquecer=None if SIN_ENRIQUECER else functools.partial(enriquecer, db=db))
        c = r["correo"]
        analisis_id = db.execute(
            "INSERT INTO analisis (fecha, version, huella, message_id, asunto, modo, veredicto, riesgo, resultado) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (ahora(), r["version"], r["huella"], c["message_id"], c["subject"], r["modo"], r["veredicto"],
             r["riesgo"], json.dumps(r, ensure_ascii=False))).lastrowid
        guardar_iocs(db, analisis_id, r["iocs"], r.get("enriquecimiento"))
        db.commit()  # antes de enviar: si el SMTP falla, el reintento reutiliza el análisis
    r["reenvio"] = {"asunto": str(original.get("Subject") or ""), "fecha": str(original.get("Date") or ""),
                    "message_id": str(original.get("Message-ID") or ""), "verificacion": verificacion}
    if copia:
        guardar(raw)
    log("%s %s: %s %d (%s)" % ("reutilizado" if fila else "analizado", r["sha256"][:12], r["veredicto"],
                               r["riesgo"], r["modo"]))
    enviar(respuesta(cfg, original, r))
    db.execute("INSERT INTO envios (fecha, sha256, remitente, asunto, analisis_id, reutilizado) "
               "VALUES (?, ?, ?, ?, ?, ?)", (ahora(), hashlib.sha256(raw).hexdigest(), remitente,
                                             r["reenvio"]["asunto"], analisis_id, int(bool(fila))))
    db.commit()
    return "reutilizado" if fila else "analizado"


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--eml", type=Path, nargs="+", help="prueba sin IMAP/SMTP y con base de datos en memoria (consulta los servicios de enriquecimiento salvo ANALISTA_CORREO_SIN_ENRIQUECER=1): procesa estos .eml en "
                    "orden e imprime las respuestas")
    ap.add_argument("--reanalizar", action="store_true", help="analiza aunque el correo ya esté en la base de datos")
    ap.add_argument("--uid", action="append", default=[], help="procesa solo estos UID sin leer (repetible)")
    ap.add_argument("--rellenar-iocs", action="store_true", help="extrae los IOCs de los análisis ya guardados y sale")
    ap.add_argument("--reanalizar-guardado", type=int, nargs="+", metavar="ID", help="vuelve a analizar estos "
                    "análisis guardados desde su .eml, sin responder, y regenera los CSV de Graylog")
    ap.add_argument("--rellenar-campana", action="store_true", help="añade plantilla, kit y alias del PTR a los "
                    "análisis ya guardados y sale")
    a = ap.parse_args()
    os.umask(0o077)
    if a.rellenar_iocs:
        rellenar_iocs(abrir_db(DB))
        return
    if a.reanalizar_guardado:
        reanalizar_guardados(abrir_db(DB), a.reanalizar_guardado)
        return
    if a.rellenar_campana:
        rellenar_campana(abrir_db(DB))
        return
    if a.eml:
        db = abrir_db(":memory:")
        for f in a.eml:
            raw = f.read_bytes()
            cfg = {"MAIL_USER": "analista@localhost", "REMITENTES": {
                parseaddr(str(email.message_from_bytes(raw, policy=policy.default)["From"]))[1].lower()}}
            procesar(cfg, raw, lambda m: print(m.as_string(policy=policy.SMTP.clone(linesep="\n"))), db,
                     copia=False, reanalizar=a.reanalizar)
        return
    cfg = cargar_config()
    db = abrir_db(DB)

    def enviar(m):
        with smtplib.SMTP_SSL(cfg["SMTP_HOST"], int(cfg.get("SMTP_PORT", 465)),
                              context=ssl.create_default_context()) as s:
            s.login(cfg["MAIL_USER"], cfg["MAIL_PASS"])
            s.send_message(m)

    try:
        with imaplib.IMAP4_SSL(cfg["IMAP_HOST"], int(cfg.get("IMAP_PORT", 993)),
                               ssl_context=ssl.create_default_context()) as im:
            im.login(cfg["MAIL_USER"], cfg["MAIL_PASS"])
            im.select("INBOX")
            _, datos = im.uid("SEARCH", None, "UNSEEN")
            uids = datos[0].split()
            if a.uid:
                uids = [u for u in uids if u.decode() in a.uid]
            uids = uids[:MAX_POR_PASADA]
            if uids:
                log("%d correos sin leer a procesar" % len(uids))
            anterior, nuevos = None, 0
            for uid in uids:
                if anterior == "analizado":
                    time.sleep(PAUSA_ENTRE_CORREOS)
                _, partes = im.uid("FETCH", uid, "(BODY.PEEK[])")
                raw = next(p[1] for p in partes if isinstance(p, tuple))
                try:
                    anterior = procesar(cfg, raw, enviar, db, reanalizar=a.reanalizar)
                    nuevos += anterior == "analizado"
                except Exception as e:
                    anterior = "analizado"  # pudo llegar a usar el modelo
                    log("error con UID %s: %s: %s" % (uid.decode(), type(e).__name__, e))
                    continue  # queda sin leer y se reintenta en la siguiente pasada
                im.uid("STORE", uid, "+FLAGS", r"(\Seen)")
            im.logout()
        if nuevos and exportar_graylog:
            try:
                exportar_graylog.escribir(exportar_graylog.recoger(db), exportar_graylog.SALIDA)
            except Exception as e:
                log("exportación para Graylog falló: %s: %s" % (type(e).__name__, e))
    except (OSError, imaplib.IMAP4.error) as e:
        # Fallos pasajeros (DNS, "Temporary authentication failure" del proveedor): los correos siguen sin leer.
        log("buzón no disponible: %s: %s" % (type(e).__name__, e))
        sys.exit(75)


if __name__ == "__main__":
    main()
