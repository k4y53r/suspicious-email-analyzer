#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 k4y53r
"""Totales de analisis.db en line protocol de InfluxDB para Telegraf (dashboard de Grafana). Ver README.md."""

import argparse, datetime as dt, hashlib, json, os, sqlite3, sys, tempfile
from collections import Counter, defaultdict
from email.utils import parseaddr
from pathlib import Path

DB = Path.home() / ".local/state/analista-correo/analisis.db"
GRAYLOG = Path.home() / ".local/state/analista-correo/graylog"
SALIDA = Path("/var/lib/analista-correo-metricas/metricas.lp")  # fuera del home (700): Telegraf no entra
VEREDICTOS = ("legitimo", "spam", "sospechoso", "malicioso")
# Todos con su cero: un valor que deja de salir se quedaría con el número viejo en InfluxDB.
ORIGENES = ("cabeceras", "cuerpo", "adjuntos", "urls", "enriquecimiento")
RESULTADOS = ("pass", "fail", "softfail", "neutral", "none", "ausente")
# Nodos que unen envíos de una campaña; los kit no: los comparten correos legítimos (concentradores).
NODOS_CAMPANA = "(rol = 'campana' AND tipo IN ('plantilla', 'enlace')) OR tipo = 'alias_ptr'"


def ns(fecha):
    return int(dt.datetime.fromisoformat(fecha.replace("Z", "+00:00")).timestamp()) * 10**9


def dia(fecha):
    return fecha[:10] + "T00:00:00Z"


def linea(medida, tags, campos, t):
    """Solo etiquetas y campos nuestros (veredictos, orígenes, hashes): nada del texto del atacante."""
    et = "".join(",%s=%s" % kv for kv in sorted(tags.items()))
    cs = ",".join("%s=%s" % (k, ("%di" % v) if isinstance(v, int) and not isinstance(v, bool) else
                             ("%.3f" % v)) for k, v in sorted(campos.items()))
    return "%s%s %s %d" % (medida, et, cs, t)


def correos(db):
    """Un correo por huella, con su último análisis; los reanálisis de otra versión no cuentan dos veces."""
    out = {}
    for aid, fecha, huella, modo, veredicto, riesgo, guardado in db.execute(
            "SELECT id, fecha, huella, modo, veredicto, riesgo, resultado FROM analisis ORDER BY id"):
        r = json.loads(guardado)
        c = out.setdefault(huella, {"primera": fecha, "ids": []})
        c.update(ultimo=aid, fecha=fecha, modo=modo, veredicto=veredicto, riesgo=riesgo, r=r)
        c["ids"].append(aid)
    return out


def campanas(db, cs):
    """Grupos de correos unidos por nodos de campaña y enviados desde dos direcciones o más."""
    de = {aid: h for h, c in cs.items() for aid in c["ids"]}
    padre = {h: h for h in cs}

    def raiz(h):
        while padre[h] != h:
            padre[h] = padre[padre[h]]
            h = padre[h]
        return h
    por_nodo = defaultdict(set)
    for aid, tipo, valor in db.execute("SELECT analisis_id, tipo, valor FROM iocs WHERE " + NODOS_CAMPANA):
        if aid in de:
            por_nodo[(tipo, valor)].add(de[aid])
    for hs in por_nodo.values():
        a, *resto = sorted(hs)
        for b in resto:
            padre[raiz(b)] = raiz(a)
    grupos = defaultdict(list)
    for h in cs:
        grupos[raiz(h)].append(h)
    out = []
    for hs in grupos.values():
        if len(hs) < 2:
            continue
        dirs = {parseaddr(cs[h]["r"].get("correo", {}).get("from", ""))[1].lower() for h in hs} - {""}
        if len(dirs) < 2:
            continue
        doms = {d.rsplit("@", 1)[-1] for d in dirs}
        asns = {i.get("asn") for h in hs for i in cs[h]["r"].get("enriquecimiento", {}).get("infraestructura", [])
                if i.get("asn")}
        primero = min(hs, key=lambda h: cs[h]["primera"])
        out.append({"id": hashlib.sha256(primero.encode()).hexdigest()[:8], "correos": len(hs), "direcciones": len(dirs),
                    "dominios": len(doms), "asn": len(asns), "primera": min(cs[h]["primera"] for h in hs),
                    "ultima": max(cs[h]["primera"] for h in hs), "riesgo_max": max(cs[h]["riesgo"] for h in hs),
                    "maliciosos": sum(cs[h]["veredicto"] == "malicioso" for h in hs)})
    return out


def generar(db):
    cs = correos(db)
    # Los totales llevan la hora del último cambio: así el fichero no cambia si no hay nada nuevo.
    t = ns(max([c["fecha"] for c in cs.values()] + [f for f, in db.execute("SELECT fecha FROM envios")],
               default="1970-01-01T00:00:00Z"))
    lineas = []
    por_dia = defaultdict(lambda: {v: 0 for v in VEREDICTOS})
    riesgo = defaultdict(list)
    origen = defaultdict(Counter)
    for c in cs.values():
        d = dia(c["primera"])
        por_dia[d][c["veredicto"]] += 1
        riesgo[d].append(c["riesgo"])
        for i in c["r"].get("indicadores", []):
            origen[d][i.get("origen")] += 1
    for d, n in por_dia.items():
        lineas.append(linea("correo_dia", {}, dict(n, correos=sum(n.values()), riesgo_medio=sum(riesgo[d]) / len(riesgo[d]),
                                                    riesgo_max=max(riesgo[d])), ns(d)))
        lineas.append(linea("correo_indicador", {}, dict({o: origen[d][o] for o in ORIGENES},
                                                          otros=sum(k for o, k in origen[d].items() if o not in ORIGENES)), ns(d)))
    envios = defaultdict(lambda: [0, 0])
    for fecha, reutilizado in db.execute("SELECT fecha, reutilizado FROM envios"):
        envios[dia(fecha)][0] += 1
        envios[dia(fecha)][1] += bool(reutilizado)
    for d, (n, r) in envios.items():
        lineas.append(linea("correo_envios", {}, {"envios": n, "reutilizados": r}, ns(d)))
    segundos = defaultdict(list)
    for (guardado, fecha) in db.execute("SELECT resultado, fecha FROM analisis"):
        s = (json.loads(guardado).get("modelo") or {}).get("segundos")
        if isinstance(s, (int, float)):
            segundos[dia(fecha)].append(float(s))
    for d, ss in segundos.items():
        lineas.append(linea("correo_modelo", {}, {"segundos_medio": sum(ss) / len(ss), "segundos_max": max(ss),
                                                   "llamadas": len(ss)}, ns(d)))
    auth = defaultdict(Counter)
    for c in cs.values():
        a = c["r"].get("autenticacion", {})
        if a.get("fuente"):
            for p in ("spf", "dkim", "dmarc"):
                res = a.get(p) or "none"
                auth[p][res if res in RESULTADOS else "otro"] += 1
    for p in ("spf", "dkim", "dmarc"):
        lineas.append(linea("correo_autenticacion", {"prueba": p}, {r: auth[p][r] for r in RESULTADOS + ("otro",)}, t))
    total = Counter(c["veredicto"] for c in cs.values())
    camp = campanas(db, cs)
    iocs = {}
    for tipo in ("ip", "dominio"):
        f = GRAYLOG / ("correo_iocs_%s.csv" % tipo)
        iocs["iocs_graylog_" + tipo] = max(0, sum(1 for _ in f.open(encoding="utf-8")) - 1) if f.exists() else 0
    ultimo = max((c["fecha"] for c in cs.values()), default=None)
    lineas.append(linea("correo_total", {}, dict({v: total[v] for v in VEREDICTOS}, correos=len(cs), campanas=len(camp),
                                                 envios=sum(n for n, _ in envios.values()),
                                                 ultimo_analisis=ns(ultimo) // 10**9 if ultimo else 0, **iocs), t))
    for c in camp:
        lineas.append(linea("correo_campana", {"campana": c["id"]},
                            {k: (ns(v) // 10**9 if k in ("primera", "ultima") else v) for k, v in c.items() if k != "id"}, t))
    return lineas


def escribir(lineas, ruta):
    """Solo reescribe si cambia: Telegraf lo relee cada minuto y los puntos llevan su hora."""
    texto = "\n".join(sorted(lineas)) + "\n"
    if ruta.exists() and ruta.read_text(encoding="utf-8") == texto:
        return False
    fd, tmp = tempfile.mkstemp(dir=ruta.parent, prefix=".metricas.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(texto)
        os.chmod(tmp, 0o644)
        os.replace(tmp, ruta)
    except BaseException:
        os.unlink(tmp)
        raise
    return True


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--salida", type=Path, default=SALIDA)
    a = ap.parse_args()
    if not DB.exists() or not a.salida.parent.is_dir():
        sys.exit("falta %s o %s" % (DB, a.salida.parent))
    db = sqlite3.connect("file:%s?mode=ro" % DB, uri=True)
    escribir(generar(db), a.salida)


if __name__ == "__main__":
    main()
