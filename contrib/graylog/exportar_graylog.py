#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 k4y53r
"""Genera los CSV de IOCs de correos maliciosos para las lookup tables de Graylog. Ver README.md."""

import argparse, csv, datetime as dt, ipaddress, json, os, re, sqlite3, sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from enriquecer import ANFITRIONES_LIBRES, populares  # noqa: E402

ESTADO = Path.home() / ".local/state/analista-correo"
DB = ESTADO / "analisis.db"
SALIDA = ESTADO / "graylog"  # de aquí los recoge tu proceso de carga hacia Graylog
EXCLUSION = Path.home() / ".config/analista-correo/no-exportar.txt"
SIEMPRE_EXCLUIDOS = {d.strip().lower() for d in os.environ.get("DOMINIOS_PROPIOS", "").split(",") if d.strip()}  # tus dominios
DIAS = {"ip": 90, "dominio": 180}  # las IPs de VPS se reasignan antes que los dominios
MAX_FILAS = 5000
# Papeles en los que el dominio es del remitente. Los de enlaces necesitan una señal propia: un phishing puede
# enlazar a webs legítimas (el banco real) para parecer creíble.
ROLES_REMITENTE = {"from", "return_path", "reply_to", "dkim"}
DOMINIO = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


def tranco():
    """Dominios populares de Tranco; si no se puede descargar, la última copia aunque haya caducado."""
    try:
        return populares()
    except Exception:
        f = ESTADO / "listas" / "tranco.txt"
        return set(f.read_text().split()) if f.exists() else set()


def excluidos():
    lista = set(SIEMPRE_EXCLUIDOS)
    if EXCLUSION.exists():
        lista |= {l.strip().lower().strip(".") for l in EXCLUSION.read_text().splitlines()
                  if l.strip() and not l.lstrip().startswith("#")}
    return lista


def excluido(dom, lista):
    return any(dom == e or dom.endswith("." + e) for e in lista)


def con_senal(r, dominio, raiz):
    """El dominio de un enlace tiene algún indicador propio (generado, marca ajena, TLD…) o del enriquecimiento."""
    hosts = {dominio, raiz}
    for i in r.get("indicadores", []):
        if i["origen"] in ("urls", "enriquecimiento") and any(
                i["texto"].startswith(h + ":") or (" %s:" % h) in i["texto"] for h in hosts):
            return True
    return False


def recoger(db):
    ahora = dt.datetime.now(dt.timezone.utc)
    lista = excluidos()
    filas = {"ip": {}, "dominio": {}}
    pop = tranco()
    # Si el mismo correo se volvió a analizar (otra versión), vale el último veredicto.
    for aid, fecha, riesgo, guardado in db.execute(
            "SELECT id, fecha, riesgo, resultado FROM analisis a WHERE veredicto = 'malicioso' AND NOT EXISTS "
            "(SELECT 1 FROM analisis b WHERE b.huella = a.huella AND b.id > a.id)"):
        r = json.loads(guardado)
        edad = (ahora - dt.datetime.fromisoformat(fecha.replace("Z", "+00:00"))).days
        iocs = db.execute("SELECT tipo, valor, raiz, rol FROM iocs WHERE analisis_id = ? AND compartido = 0 "
                          "AND tipo IN ('ip', 'dominio')", (aid,)).fetchall()
        campana = next((raiz for t, v, raiz, rol in iocs if t == "dominio" and "from" in rol.split(",")), "")
        for tipo, valor, raiz, rol in iocs:
            if edad > DIAS[tipo]:
                continue
            if tipo == "ip":
                if rol != "origen" or not ipaddress.ip_address(valor).is_global:
                    continue
                clave = valor
            else:
                roles = set(rol.split(","))
                if not (roles & ROLES_REMITENTE or con_senal(r, valor, raiz)):
                    continue
                clave = raiz
                if not DOMINIO.fullmatch(clave) or excluido(clave, lista):
                    continue
                if clave in pop and clave not in ANFITRIONES_LIBRES:
                    continue  # un falso positivo con paypal.com haría saltar la alerta DNS a cada visita
            e = filas[tipo].setdefault(clave, {"riesgo": 0, "fecha": "", "correos": set(), "campana": campana})
            e["riesgo"] = max(e["riesgo"], riesgo)
            e["fecha"] = max(e["fecha"], fecha[:10])
            e["correos"].add(aid)
    return filas


def escribir(filas, directorio):
    """Escribe los CSV y devuelve cuántas filas tiene cada uno."""
    total = {}
    directorio.mkdir(parents=True, exist_ok=True, mode=0o700)
    for tipo, datos in filas.items():
        ruta = directorio / ("correo_iocs_%s.csv" % tipo)
        orden = sorted(datos.items(), key=lambda kv: kv[1]["fecha"], reverse=True)[:MAX_FILAS]
        tmp = ruta.with_suffix(".tmp")
        with open(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow([tipo, "info"])
            for clave, e in orden:
                # Solo campos nuestros: el asunto o el texto los escribe el atacante.
                w.writerow([clave, "malicioso %d; campana %s; visto %s; %d correos" % (
                    e["riesgo"], e["campana"] or "-", e["fecha"], len(e["correos"]))])
        os.replace(tmp, ruta)
        total[tipo] = len(orden)
    return total


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--salida", type=Path, default=SALIDA)
    a = ap.parse_args()
    if not DB.exists():
        sys.exit("no existe %s" % DB)
    for tipo, n in escribir(recoger(sqlite3.connect(DB)), a.salida).items():
        print("%s: %d" % (a.salida / ("correo_iocs_%s.csv" % tipo), n))


if __name__ == "__main__":
    main()
