#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 k4y53r
"""Pruebas de las listas de IFIN en enriquecer.py (1.16): coincidencia, descarga validada, copia vieja y 0 puntos.
Sin red ni disco real: urlopen y ESTADO simulados. Uso: python3 -I pruebas/probar_ifin.py"""
import io, os, sys, tempfile, time, urllib.error
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


def simular(respuestas):
    """respuestas: lista de bytes o excepciones, una por llamada a urlopen."""
    llamadas = []

    def urlopen(url, timeout=0):
        llamadas.append(url)
        r = respuestas.pop(0)
        if isinstance(r, Exception):
            raise r
        return Resp(r)
    return urlopen, llamadas


tmp = Path(tempfile.mkdtemp())
en.ESTADO = tmp

# coincidencia
L = {"cash": {"000webhostapp.com", "a.free.pinggy.link"}, "pastes": {"pastebin.com"}}
comprobar("host exacto", en.en_ifin("pastebin.com", L) == ("pastes", "pastebin.com"))
comprobar("subdominio", en.en_ifin("x.y.000webhostapp.com", L) == ("cash", "000webhostapp.com"))
comprobar("entrada con subdominio", en.en_ifin("z.a.free.pinggy.link", L) == ("cash", "a.free.pinggy.link"))
comprobar("no por sufijo de texto", en.en_ifin("notpastebin.com", L) is None)
comprobar("padre no listado", en.en_ifin("free.pinggy.link", L) is None)
comprobar("mayúsculas y punto final", en.en_ifin("PasteBin.com.", L) == ("pastes", "pastebin.com"))

# descarga validada
uo, llam = simular([b"pastebin.com\nrentry.co\nno es dominio!\n\nEXAMPLE.org\n"])
en.urllib.request.urlopen = uo
d = en.ifin("paste-bins")
comprobar("filtra lo que no es dominio y pasa a minúsculas", d == {"pastebin.com", "rentry.co", "example.org"})
comprobar("URL con el slug", llam == ["https://lists.ifin.network/lists/paste-bins/paste-bins_domain.txt"])
d2 = en.ifin("paste-bins")
comprobar("copia reciente: sin nueva descarga", d2 == d and len(llam) == 1)

# lista vacía o muy reducida no pisa la copia
f = tmp / "listas" / "ifin-paste-bins.txt"
os.utime(f, (time.time() - 8 * 86400,) * 2)
uo, llam = simular([b"\n\n"])
en.urllib.request.urlopen = uo
comprobar("descarga vacía: queda la vieja", en.ifin("paste-bins") == d)
comprobar("y se reintenta en una semana (mtime renovado)", time.time() - f.stat().st_mtime < 60)
os.utime(f, (time.time() - 8 * 86400,) * 2)
uo, llam = simular([b"solo.example\n"])
en.urllib.request.urlopen = uo
comprobar("reducida a menos de la mitad: queda la vieja", en.ifin("paste-bins") == d)
os.utime(f, (time.time() - 8 * 86400,) * 2)
uo, llam = simular([b"pastebin.com\nrentry.co\nexample.org\notra.example\n"])
en.urllib.request.urlopen = uo
comprobar("lista nueva válida la sustituye", en.ifin("paste-bins") == {"pastebin.com", "rentry.co", "example.org", "otra.example"})
os.utime(f, (time.time() - 8 * 86400,) * 2)
uo, llam = simular([b"x" * (en.IFIN_MAX_BYTES + 5)])
en.urllib.request.urlopen = uo
comprobar("demasiado grande: queda la vieja", len(en.ifin("paste-bins")) == 4)

# sin copia y sin red: error una vez y vacío después
uo, llam = simular([urllib.error.URLError("sin red")])
en.urllib.request.urlopen = uo
try:
    en.ifin("chat-hooks")
    comprobar("sin copia y sin red lanza", False)
except OSError:
    comprobar("sin copia y sin red lanza", True)
uo, llam = simular([])
en.urllib.request.urlopen = uo
comprobar("siguiente llamada: vacía y sin red", en.ifin("chat-hooks") == set() and llam == [])

# integración: 0 puntos, sin cambiar el total y sin insistir si no hay red
tmp2 = Path(tempfile.mkdtemp())
en.ESTADO = tmp2
(tmp2 / "listas").mkdir(mode=0o700)
(tmp2 / "listas" / "ifin-commonly-abused-site-hosts.txt").write_text("000webhostapp.com\n")
(tmp2 / "listas" / "ifin-paste-bins.txt").write_text("pastebin.com\n")
for s in en.IFIN_LISTAS:
    (tmp2 / "listas" / ("ifin-%s.txt" % s)).touch()
en.lista = lambda n: []
en.populares = lambda: set()
en.otx = lambda v: None
en.rdap = lambda d: {"sin_servicio": True}
en.clave_abusech = lambda: None
db = en.abrir_db(str(tmp2 / "a.db"))
iocs = {"ips": [], "dominios": [{"dominio": "tienda.000webhostapp.com", "raiz": "000webhostapp.com", "compartido": True, "roles": []},
                              {"dominio": "ejemplo.org", "raiz": "ejemplo.org", "compartido": False, "roles": []}],
        "urls": ["https://pastebin.com/raw/abc123?x=1", "https://ejemplo.org/a", "http://[abc/x"], "hashes": []}
os.utime(tmp2 / "listas" / "ifin-commonly-abused-site-hosts.txt", None)
os.utime(tmp2 / "listas" / "ifin-paste-bins.txt", None)
r = en.enriquecer(iocs, db)
h = [x for x in r["hallazgos"] if x["fuente"] == "ifin"]
comprobar("dos hallazgos IFIN (CASH y pastebin)", sorted(x["valor"] for x in h) == ["pastebin.com", "tienda.000webhostapp.com"])
comprobar("todos con 0 puntos", all(x["puntos"] == 0 for x in h) and r["puntos"] == 0 and r["suelo"] == 0)
comprobar("sin errores", not [e for e in r["errores"] if e.startswith("ifin")])
comprobar("el detalle dice que no suma", all("no suma" in x["detalle"] for x in h))

print("\n%s" % ("TODO OK" if not fallos else "FALLAN: %s" % ", ".join(fallos)))
sys.exit(1 if fallos else 0)
