#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 k4y53r
"""Pruebas del RDAP directo al registro (catálogo de IANA) en enriquecer.py: catálogo validado, ruta por TLD,
semántica de 404, caída a rdap.org y no bajar de https a http. Sin red ni disco real.
Uso: python3 -I pruebas/probar_rdap.py"""
import io, json, os, sys, tempfile, time, urllib.error
from pathlib import Path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import enriquecer as en  # noqa: E402

fallos = []


def comprobar(nombre, ok):
    if not ok:
        fallos.append(nombre)
    print(("OK   " if ok else "FALLA"), nombre)


class Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class Opener:
    """respuestas: lista (una por llamada) de bytes o excepciones; llamadas guarda las URL pedidas."""
    def __init__(self, respuestas):
        self.respuestas, self.llamadas = list(respuestas), []

    def open(self, req, timeout=0):
        self.llamadas.append(req.full_url if hasattr(req, "full_url") else req)
        r = self.respuestas.pop(0)
        if isinstance(r, Exception):
            raise r
        return Resp(r)


def catalogo(extra=None, n=150):
    servicios = [[["com", "net"], ["https://rdap.verisign.com/com/v1/"]], [["org"], ["https://rdap.pir.example/rdap"]],
                 [["mal"], ["http://inseguro.example/"]], [["xx"], ["https://-malo-.example/"]]]
    servicios += [[["t%03d" % i], ["https://r%03d.example/" % i]] for i in range(n)]
    return json.dumps({"services": servicios + (extra or [])}).encode()


def nuevo_estado():
    en.ESTADO = Path(tempfile.mkdtemp())
    en._catalogo_rdap = None
    en.PAUSA_RDAP = 0


def http_error(url, code):
    return urllib.error.HTTPError(url, code, "x", {}, io.BytesIO(b""))


# catálogo
nuevo_estado()
en._opener = Opener([catalogo()])
s = en.servidores_rdap()
comprobar("catálogo: com y org", s["com"] == "https://rdap.verisign.com/com/v1/" and s["org"] == "https://rdap.pir.example/rdap/")
comprobar("catálogo: descarta http y hosts inválidos", "mal" not in s and "xx" not in s)
comprobar("catálogo: una sola descarga y en disco", len(en._opener.llamadas) == 1 and (en.ESTADO / "listas" / "rdap-dns.json").exists())
en._opener = Opener([])
comprobar("catálogo reciente: sin descarga", en.servidores_rdap() == s)

f = en.ESTADO / "listas" / "rdap-dns.json"
for nombre, malo in (("vacío", b"{}"), ("no JSON", b"<html>"), ("muy reducido", catalogo(n=10))):
    os.utime(f, (time.time() - 8 * 86400,) * 2)
    en._catalogo_rdap = None
    en._opener = Opener([malo])
    comprobar("catálogo %s: queda el anterior" % nombre, en.servidores_rdap() == s)
os.utime(f, (time.time() - 8 * 86400,) * 2)
en._catalogo_rdap = None
en._opener = Opener([b"x" * (en.RDAP_MAX_BYTES + 5)])
comprobar("catálogo demasiado grande: queda el anterior", en.servidores_rdap() == s)

# sin catálogo y sin red: vacío, se marca y no se insiste
nuevo_estado()
en._opener = Opener([urllib.error.URLError("sin red")])
comprobar("sin catálogo y sin red: vacío", en.servidores_rdap() == {})
en._catalogo_rdap = None
en._opener = Opener([])
comprobar("y no se reintenta de inmediato", en.servidores_rdap() == {} and en._opener.llamadas == [])
os.utime(en.ESTADO / "listas" / "rdap-dns.fallo", (time.time() - 3700,) * 2)
en._catalogo_rdap = None
en._opener = Opener([catalogo()])
comprobar("a la hora se reintenta y se recupera", len(en.servidores_rdap()) > 100 and not (en.ESTADO / "listas" / "rdap-dns.fallo").exists())
en._catalogo_rdap = None
(en.ESTADO / "listas" / "rdap-dns.json").write_bytes(b"[1, 2]")
en._opener = Opener([])
comprobar("catálogo local con estructura rara no rompe", en.servidores_rdap() == {} or True)
en._opener = Opener([b"x" * (en.RDAP_MAX_BYTES + 5)])
en._catalogo_rdap = {"com": "https://rdap.verisign.com/com/v1/"}
try:
    en._consulta_rdap("https://rdap.verisign.com/com/v1/domain/a.com")
    comprobar("respuesta RDAP demasiado grande se rechaza", False)
except RuntimeError:
    comprobar("respuesta RDAP demasiado grande se rechaza", True)

# rdap(): ruta por TLD
nuevo_estado()
alta = json.dumps({"events": [{"eventAction": "registration", "eventDate": "2020-01-02T00:00:00Z"}]}).encode()
en._opener = Opener([catalogo(), alta])
r = en.rdap("ejemplo.com")
comprobar("registro directo del TLD", r == {"registrado": True, "alta": "2020-01-02T00:00:00Z"}
          and en._opener.llamadas[1] == "https://rdap.verisign.com/com/v1/domain/ejemplo.com")
en._opener = Opener([])
comprobar("TLD sin servidor en el catálogo: sin_servicio y sin consulta", en.rdap("ejemplo.es") == {"sin_servicio": True} and en._opener.llamadas == [])
en._opener = Opener([http_error("https://rdap.verisign.com/com/v1/domain/x.com", 404)])
comprobar("404 del registro: no registrado", en.rdap("x.com") == {"registrado": False})
en._opener = Opener([http_error("https://rdap.verisign.com/com/v1/domain/x.com", 429)])
try:
    en.rdap("x.com")
    comprobar("429 del registro se propaga", False)
except urllib.error.HTTPError as e:
    comprobar("429 del registro se propaga", e.code == 429)
en._opener = Opener([urllib.error.URLError("ssl: certificate verify failed"), alta])
r = en.rdap("y.com")
comprobar("fallo de TLS del registro: cae a rdap.org", r["registrado"] and en._opener.llamadas[-1] == "https://rdap.org/domain/y.com")
en._opener = Opener([urllib.error.URLError("a"), urllib.error.URLError("b")])
try:
    en.rdap("z.com")
    comprobar("si también falla rdap.org, error", False)
except OSError:
    comprobar("si también falla rdap.org, error", True)
en._opener = Opener([http_error("https://rdap.org/domain/q.com", 404)])
en._catalogo_rdap = {}
(en.ESTADO / "listas" / "rdap-dns.json").write_bytes(b"")
comprobar("sin catálogo: rdap.org y su 404 es sin_servicio", en.rdap("q.com") == {"sin_servicio": True})

# no bajar de https a http
h = en.SoloHttps()
req = en.urllib.request.Request("https://a.example/x")
comprobar("redirección a http rechazada", h.redirect_request(req, None, 302, "x", {}, "http://a.example/y") is None)
comprobar("redirección a https admitida", h.redirect_request(req, None, 302, "x", {}, "https://b.example/y") is not None)

print("\n%s" % ("TODO OK" if not fallos else "FALLAN: %s" % ", ".join(fallos)))
sys.exit(1 if fallos else 0)
