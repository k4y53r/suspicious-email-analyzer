# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 k4y53r
"""Genera los sintéticos de adjuntos (1.12-1.13; contenidos inertes, sin código). Uso: python3 -I pruebas/generar_adjuntos.py pruebas/sinteticos"""
import io, struct, sys, zipfile
from email.message import EmailMessage
from pathlib import Path

FIN, LIBRE, FAT_SECTOR, NADA = 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFD, 0xFFFFFFFF


def zipear(entradas, cifrado=False):
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as z:
        for nombre, datos in entradas:
            z.writestr(zipfile.ZipInfo(nombre, (2026, 10, 1, 9, 0, 0)), datos)
    d = bytearray(b.getvalue())
    if cifrado:  # solo la marca de cifrado (bit 0) en las cabeceras local y central: el contenido no está cifrado
        for firma, pos in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
            i = d.find(firma)
            while i >= 0:
                d[i + pos] |= 1
                i = d.find(firma, i + 4)
    return bytes(d)


def ole(entradas):
    """OLE2 versión 3 (sectores de 512, miniflujo de 64 por debajo de 4096). entradas: [(ruta, datos o None si es
    almacenamiento)], con los almacenamientos antes que su contenido. Árbol: cada hijo enlaza al siguiente por la derecha."""
    sectores, fat = [], []

    def guardar(datos, tabla, almacen, tam):
        if not datos:
            return FIN
        primero = len(almacen)
        trozos = [datos[i:i + tam].ljust(tam, b"\x00") for i in range(0, len(datos), tam)]
        for k, t in enumerate(trozos):
            almacen.append(t)
            tabla.append(primero + k + 1 if k + 1 < len(trozos) else FIN)
        return primero

    nodos = [{"nombre": "Root Entry", "tipo": 5, "hijos": [], "inicio": FIN, "tam": 0}]
    por_ruta, mini, minifat = {(): 0}, [], []
    for ruta, datos in entradas:
        n = {"nombre": ruta[-1], "tipo": 1 if datos is None else 2, "hijos": [], "inicio": FIN, "tam": len(datos or b"")}
        if datos is not None:
            n["inicio"] = guardar(datos, minifat, mini, 64) if len(datos) < 4096 else guardar(datos, fat, sectores, 512)
        por_ruta[tuple(ruta)] = len(nodos)
        nodos[por_ruta[tuple(ruta[:-1])]]["hijos"].append(len(nodos))
        nodos.append(n)
    nodos[0]["inicio"], nodos[0]["tam"] = guardar(b"".join(mini), fat, sectores, 512), len(mini) * 64
    primer_minifat = guardar(struct.pack("<%dI" % len(minifat), *minifat), fat, sectores, 512)
    derecha = {h: hs[i + 1] for n in nodos for hs in [n["hijos"]] for i, h in enumerate(hs[:-1])}
    dir_bytes = b""
    for i, n in enumerate(nodos):
        nombre = (n["nombre"] + "\x00").encode("utf-16-le")
        dir_bytes += (nombre.ljust(64, b"\x00") + struct.pack("<HBBIII", len(nombre), n["tipo"], 1, NADA,
                      derecha.get(i, NADA), n["hijos"][0] if n["hijos"] else NADA) + b"\x00" * 36
                      + struct.pack("<IQ", n["inicio"], n["tam"]))
    while len(dir_bytes) % 512:
        dir_bytes += b"\x00" * 64 + struct.pack("<HBBIII", 0, 0, 0, NADA, NADA, NADA) + b"\x00" * 36 + struct.pack("<IQ", 0, 0)
    primer_dir = guardar(dir_bytes, fat, sectores, 512)
    n_fat = 1
    while n_fat * 128 < len(sectores) + n_fat:
        n_fat += 1
    ids_fat = list(range(len(sectores), len(sectores) + n_fat))
    fat += [FAT_SECTOR] * n_fat
    fat += [LIBRE] * (n_fat * 128 - len(fat))
    sectores += [struct.pack("<128I", *fat[i * 128:(i + 1) * 128]) for i in range(n_fat)]
    cab = (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 16 + struct.pack("<HHHHH", 0x3e, 3, 0xfffe, 9, 6)
           + b"\x00" * 6 + struct.pack("<IIIIIIIII", 0, n_fat, primer_dir, 0, 4096, primer_minifat if minifat else FIN,
                                       len(minifat) * 4 // 512 + (1 if len(minifat) * 4 % 512 else 0), FIN, 0)
           + struct.pack("<109I", *(ids_fat + [LIBRE] * (109 - n_fat))))
    return cab + b"".join(sectores)


def biff(hojas, filepass=False):
    """Flujo Workbook mínimo de Excel 97: BOF, [FILEPASS], una BOUNDSHEET por hoja (nombre, estado, tipo) y EOF.
    estado: 0 visible, 1 oculta, 2 muy oculta; tipo: 0 hoja de cálculo, 1 hoja de macros XLM."""
    reg = lambda t, d: struct.pack("<HH", t, len(d)) + d
    w = reg(0x0809, struct.pack("<HHHHII", 0x0600, 0x0005, 0x0dbb, 0x07cc, 0, 0))
    if filepass:
        w += reg(0x002f, struct.pack("<HHH", 0, 1, 1) + b"\x00" * 48)
    for nombre, estado, tipo in hojas:
        w += reg(0x0085, struct.pack("<IBBBB", 0, estado, tipo, len(nombre), 0) + nombre.encode("latin-1"))
    return w + reg(0x000a, b"")


def doc(macros):
    e = [(("WordDocument",), b"\xec\xa5" + b"\x00" * 5000), (("1Table",), b"\x00" * 600)]
    if macros:
        e += [(("Macros",), None), (("Macros", "VBA"), None), (("Macros", "VBA", "_VBA_PROJECT"), b"\xcc\x61" + b"\x00" * 5),
              (("Macros", "VBA", "dir"), b"\x00" * 40), (("Macros", "PROJECT"), b'ID="{prueba}"\r\n')]
    return ole(e)


def correo(dest, fichero, de, asunto, cuerpo, adjuntos, auth):
    m = EmailMessage()
    m["From"], m["To"], m["Subject"] = de, "analista@example.org", asunto
    m["Authentication-Results"] = auth
    m["Message-ID"] = "<%s@sintetico.invalid>" % fichero
    m["Date"] = "Sat, 10 Oct 2026 10:00:00 +0200"
    m.set_content(cuerpo)
    for nombre, tipo, datos in adjuntos:
        m.add_attachment(datos, maintype=tipo.split("/")[0], subtype=tipo.split("/")[1], filename=nombre)
    m.set_boundary("sintetico-" + fichero)  # fijo: regenerar no cambia los ficheros
    (dest / fichero).write_bytes(bytes(m))


def main(dest):
    # Cuenta legítima comprometida: autenticación correcta, para que el adjunto sea la única señal.
    malo = "mx.example.org; spf=pass smtp.mailfrom=%s; dkim=pass header.d=%s; dmarc=pass"
    bueno = "mx.example.org; spf=pass smtp.mailfrom=empresa-ejemplo.example; dkim=pass header.d=empresa-ejemplo.example; dmarc=pass"
    xls, docx_tipo = "application/vnd.ms-excel", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    pe = bytearray(b"MZ" + b"\x00" * 0x3a + (0x40).to_bytes(4, "little") + b"PE\x00\x00")
    pe += b"fichero de prueba, no ejecutable".ljust(64, b"\x00")
    correo(dest, "adjunto-pe-disfrazado.eml", "Contabilidad <admin@suministros-ejemplo.example>", "Factura septiembre 2026",
           "Buenos días,\n\nAdjunto la factura de septiembre. Ábrala hoy para evitar el recargo.\n\nContabilidad",
           [("Factura_septiembre.pdf", "application/pdf", bytes(pe))], malo % (("suministros-ejemplo.example",) * 2))
    correo(dest, "adjunto-zip-lnk.eml", "Pedidos <pedidos@transportes-ejemplo.example>", "Pedido 4471 retenido en aduana",
           "Su pedido 4471 está retenido. Descargue el documento adjunto y confirme los datos de entrega.",
           [("Pedido_4471.zip", "application/zip", zipear([("Pedido_4471/Pedido_4471.pdf.lnk", b"L\x00\x00\x00prueba")]))],
           malo % (("transportes-ejemplo.example",) * 2))
    docx = [("[Content_Types].xml", b"<Types/>"), ("word/document.xml", b"<w:document/>"), ("word/vbaProject.bin", b"prueba")]
    correo(dest, "adjunto-docx-macros.eml", "RRHH <rrhh@asesoria-ejemplo.example>", "Nómina de octubre",
           "Le enviamos su nómina. Si el documento no se ve bien, pulse «Habilitar contenido».",
           [("Nomina_octubre.docx", docx_tipo, zipear(docx))], malo % (("asesoria-ejemplo.example",) * 2))
    correo(dest, "adjunto-zip-cifrado.eml", "Notaría <avisos@notaria-ejemplo.example>", "Documentación pendiente de firma",
           "Adjuntamos la documentación pendiente. Contraseña del archivo: 4471",
           [("Documentacion.zip", "application/zip", zipear([("Documentacion/contrato.pdf", b"%PDF-1.4 prueba")], True))],
           malo % (("notaria-ejemplo.example",) * 2))
    sano = [("[Content_Types].xml", b"<Types/>"), ("word/document.xml", b"<w:document/>"), ("word/media/image1.png", b"\x89PNG")]
    correo(dest, "legitimo-adjuntos.eml", "Ana López <ana@empresa-ejemplo.example>", "Acta de la reunión del jueves",
           "Hola,\n\nTe paso el acta del jueves y el presupuesto que comentamos. Mírala cuando puedas.\n\nUn saludo,\nAna",
           [("Acta_jueves.docx", docx_tipo, zipear(sano)),
            ("Presupuesto.pdf", "application/pdf", b"%PDF-1.4\n% prueba\n%%EOF\n"),
            ("Fotos_obra.zip", "application/zip", zipear([("obra/foto1.jpg", b"\xff\xd8\xff"), ("obra/foto2.jpg", b"\xff\xd8\xff")]))],
           bueno)
    # 1.13: Office antiguo (OLE2)
    correo(dest, "adjunto-xls-xlm.eml", "Compras <compras@ferreteria-ejemplo.example>", "Pedido de octubre",
           "Buenos días,\n\nLe adjunto el pedido de octubre. Para ver los importes pulse «Habilitar contenido».\n\nCompras",
           [("Pedido_octubre.xls", xls, ole([(("Workbook",), biff([("Hoja1", 0, 0), ("Macro1", 2, 1)]))]))],
           malo % (("ferreteria-ejemplo.example",) * 2))
    correo(dest, "adjunto-doc-vba.eml", "Administración <admin@gestoria-ejemplo.example>", "Contrato de servicios",
           "Adjunto el contrato para su firma. Si aparece un aviso de seguridad, pulse «Habilitar edición».",
           [("Contrato_servicios.doc", "application/msword", doc(True))], malo % (("gestoria-ejemplo.example",) * 2))
    correo(dest, "adjunto-docx-cifrado.eml", "Facturación <facturas@electricidad-ejemplo.example>", "Factura 2026-1182",
           "Adjuntamos su factura. Por seguridad va protegida; la contraseña es 1182.",
           [("Factura_2026-1182.docx", docx_tipo, ole([(("EncryptionInfo",), b"\x04\x00\x04\x00" + b"\x00" * 200),
                                                       (("EncryptedPackage",), b"\x00" * 6000)]))],
           malo % (("electricidad-ejemplo.example",) * 2))
    correo(dest, "legitimo-office-antiguo.eml", "Ana López <ana@empresa-ejemplo.example>", "Presupuesto y acta antiguos",
           "Hola,\n\nTe paso el presupuesto en el Excel de siempre y el acta en Word. Mírala cuando puedas.\n\nUn saludo,\nAna",
           [("Presupuesto.xls", xls, ole([(("Workbook",), biff([("Hoja1", 0, 0), ("Hoja2", 1, 0)]))])),
            ("Acta.doc", "application/msword", doc(False))], bueno)


if __name__ == "__main__":
    main(Path(sys.argv[1]))
