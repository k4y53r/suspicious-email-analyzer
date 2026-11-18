# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 k4y53r
"""Genera los sintéticos de cebo íntimo y sus controles (1.15). Todo inventado: dominios .example, IP 192.0.2.0/24.
Uso: python3 -I pruebas/generar_sinteticos.py pruebas/sinteticos"""
import sys
from email.message import EmailMessage
from pathlib import Path

CSS = "<style>@media only screen and (max-width:660px) { .estrecho { width: 100%!important; } } .caja { color: #333; }</style>"


def auth(dominio, dmarc="pass"):
    return "mx.example.org; spf=pass smtp.mailfrom=%s; dkim=pass header.d=%s; dmarc=%s" % (dominio, dominio, dmarc)


def correo(dest, fichero, de, asunto, texto, html=None, extra=None, dominio="dominio-a.example", ip="192.0.2.15",
           adjunto=None, para="analista@example.org"):
    m = EmailMessage()
    m["From"], m["To"], m["Subject"] = de, para, asunto
    m["Authentication-Results"] = auth(dominio)
    m["Received"] = "from mail.%s (mail.%s [%s]) by mx.example.org; Sat, 10 Oct 2026 10:00:00 +0200" % (dominio, dominio, ip)
    m["Message-ID"] = "<%s@sintetico.invalid>" % fichero
    m["Date"] = "Sat, 10 Oct 2026 10:00:00 +0200"
    for k, v in (extra or {}).items():
        m[k] = v
    m.set_content(texto)
    if html:
        m.add_alternative(html, subtype="html")
    if adjunto:
        m.add_attachment(adjunto[1], maintype="image", subtype="jpeg", filename=adjunto[0], disposition="inline")
    if m.is_multipart():
        m.set_boundary("sintetico-" + fichero)  # fijo: regenerar no cambia los ficheros
    (dest / fichero).write_bytes(bytes(m))


def main(dest):
    uuid = "5d3c9a1e-7b24-4f60-9c1d-0a8e2f4b6c37"
    # Cebos (3): sospechoso o malicioso
    nl_texto = ("Hoi Gebruiker4821, met Lotte. Hier zijn de foto's van Anna waar ik het over had.\n"
                "Dit blijft tussen ons, niemand anders mag ze zien.\n"
                "https://dominio-a.example/?id=%s&u=1&t={tag}\n\nGroeten,\nLotte" % uuid)
    nl_html = ("<html><head>" + CSS + "</head><body><p>Hoi Gebruiker4821, met Lotte. Hier zijn de foto's van Anna waar ik het "
               "over had.</p><p>Dit blijft tussen ons, niemand anders mag ze zien.</p>"
               "<p><a href=\"https://dominio-a.example/?id=%s&u=1&t={tag}\">FOTO_001.JPG</a></p>"
               "<p>Groeten,<br>Lotte</p></body></html>" % uuid)
    correo(dest, "cebo-intimo-nl.eml", '"Mira Jansen" <postmaster@dominio-a.example>', "Fwd: Foto's", nl_texto, nl_html,
           {"Reply-To": "postmaster@dominio-a.example", "Return-Path": "<postmaster@dominio-a.example>",
            "List-Unsubscribe": "<https://dominio-a.example/baja?id=%s>" % uuid})
    correo(dest, "cebo-intimo-es.eml", '"Lucía Prado" <noreply@dominio-b.example>', "Las fotos que te prometí",
           "Hola Cliente7731, soy Marta. Aquí tienes las fotos de Paula que te comenté.\n"
           "Esto queda entre nosotros, nadie más debe verlas.\nhttps://dominio-b.example/ver?x=1\n\nUn abrazo,\nMarta",
           dominio="dominio-b.example", ip="192.0.2.27")
    correo(dest, "cebo-intimo-sin-enlace.eml", '"Lucía Prado" <noreply@dominio-b.example>', "Las fotos que te prometí",
           "Hola Cliente7731, soy Marta. Tengo las fotos de Paula que te comenté.\n"
           "Esto queda entre nosotros, nadie más debe saberlo. Respóndeme si las quieres.\n\nUn abrazo,\nMarta",
           dominio="dominio-b.example", ip="192.0.2.27")
    # Controles legítimos (7)
    correo(dest, "boletin-uuid-baja.eml", "Tienda Ejemplo <boletin@tienda-ejemplo.example>", "Novedades de noviembre",
           "Hola, estas son las novedades del mes.\nhttps://tienda-ejemplo.example/novedades?r=%s\nPara darte de baja pulsa aquí." % uuid,
           "<html><body><p>Hola, estas son las novedades del mes.</p><p><a href=\"https://tienda-ejemplo.example/novedades?r=%s\">Ver novedades</a></p>"
           "<p><a href=\"https://tienda-ejemplo.example/baja?r=%s\">Darse de baja</a></p></body></html>" % (uuid, uuid),
           {"List-Unsubscribe": "<https://tienda-ejemplo.example/baja?r=%s>" % uuid}, "tienda-ejemplo.example", "192.0.2.41")
    correo(dest, "notificacion-noreply-uuid.eml", "Servicio de Estado <noreply@estado-ejemplo.example>", "Tu pedido ha cambiado de estado",
           "Tu pedido está en reparto.\nhttps://estado-ejemplo.example/pedido/%s\nGestiona tus avisos: https://estado-ejemplo.example/avisos?u=%s" % (uuid, uuid),
           None, {"List-Unsubscribe": "<https://estado-ejemplo.example/avisos?u=%s>" % uuid}, "estado-ejemplo.example", "192.0.2.42")
    correo(dest, "personal-apodo-firma.eml", "Roberto <roberto@correo-amigo.example>", "Esta tarde",
           "Hola,\n\n¿Quedamos esta tarde para el café de siempre? Dime la hora que te viene bien.\n\nSaludos,\nRober",
           dominio="correo-amigo.example", ip="192.0.2.43")
    correo(dest, "personal-idioma-ajeno.eml", "Femke de Vries <femke@correo-amigo.example>", "Tot zaterdag",
           "Hoi, ik hoop dat het goed met je gaat. We komen zaterdag langs voor een kopje koffie, "
           "als dat voor jullie ook past. Laat maar weten, dan nemen we iets lekkers mee voor de kinderen.\n\nGroeten,\nFemke",
           dominio="correo-amigo.example", ip="192.0.2.43")
    correo(dest, "codigo-llaves.eml", "Ana López <ana@empresa-ejemplo.example>", "Ejemplo de configuración",
           "Hola,\n\nEl ejemplo que comentamos:\n\nconfig = { x }\n{\"nombre\": \"prueba\", \"valor\": 1}\na{color:red}\n"
           "function(){return 1}\n\nCuando puedas lo revisas.\n\nUn saludo,\nAna",
           dominio="empresa-ejemplo.example", ip="192.0.2.44")
    correo(dest, "fotos-amiga.eml", "Carmen Soto <carmen@correo-amigo.example>", "Las fotos de la boda",
           "Hola, te mando las fotos de la boda. Por favor no se lo digas a nadie hasta que se lo cuente yo.\n\nUn beso,\nCarmen",
           dominio="correo-amigo.example", ip="192.0.2.43", adjunto=("boda.jpg", b"\xff\xd8\xff\xe0" + b"0" * 20))
    correo(dest, "postmaster-it.eml", '"Postmaster IT" <postmaster@empresa-ejemplo.example>', "Mantenimiento del servidor de correo",
           "Esta noche habrá mantenimiento del servidor de correo entre las 02:00 y las 03:00.\n\nEquipo de sistemas",
           dominio="empresa-ejemplo.example", ip="192.0.2.44")


if __name__ == "__main__":
    main(Path(sys.argv[1]))
