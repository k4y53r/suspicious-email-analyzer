# Seguridad

## Qué hace y qué no hace el programa
- Analiza correos hostiles: desmonta el `.eml` y sus adjuntos **en memoria**, sin ejecutarlos; los adjuntos no se escriben en disco (en modo buzón sí se guarda el `.eml` recibido, con permisos 600, en `correos/`), con topes de tamaño y de memoria para los formatos que lo permiten (ZIP, OLE, OOXML).
- No abre enlaces. Las URLs y dominios que salen en las respuestas van desactivados (`hxxp`, `[.]`).
- El texto del correo llega a un modelo local (Ollama). Un correo puede intentar manipularlo (inyección de instrucciones): el programa puntúa esas frases y el texto oculto aparte, y el modelo no puede rebajar los indicadores técnicos fuertes. Aun así, el veredicto es una segunda opinión, no una garantía.
- `buzon.env` contiene la contraseña del buzón: el programa se niega a arrancar si no tiene permisos 600. Usa una contraseña de aplicación, no la principal.
- Las consultas de enriquecimiento (abuse.ch, listas públicas, RDAP, OTX opcional) envían a terceros IP y dominios del correo analizado.

## Cómo informar de una vulnerabilidad
Abre un aviso de seguridad privado en GitHub (pestaña *Security* → *Report a vulnerability*) o, si no está disponible, un issue **sin** el correo ni datos personales: describe el tipo de fichero y el efecto, y se pide el ejemplo por un canal privado. No publiques muestras de malware real; para reproducir, usa ficheros sintéticos como los de `pruebas/`.

Es un proyecto personal mantenido sin garantías de plazo; se intenta responder en unos días.

---

# Security (English)

## What the program does and does not do
- It analyses hostile mail: it takes the `.eml` and its attachments apart **in memory** without executing them; attachments are not written to disk (in mailbox mode the received `.eml` is stored, mode 600, in `correos/`), with size and memory caps for the formats that allow it (ZIP, OLE, OOXML).
- It does not open links. URLs and domains in the replies are defanged (`hxxp`, `[.]`).
- The text of the mail reaches a local model (Ollama). A mail can try to manipulate it (prompt injection): the program scores those phrases and hidden text separately, and the model cannot lower the strong technical indicators. Still, the verdict is a second opinion, not a guarantee.
- `buzon.env` holds the mailbox password: the program refuses to start unless its mode is 600. Use an app password, not your main one.
- The enrichment lookups (abuse.ch, public lists, RDAP, optional OTX) send the IPs and domains of the analysed mail to third parties.

## Reporting a vulnerability
Open a private security advisory on GitHub (*Security* tab → *Report a vulnerability*) or, if it is not available, an issue **without** the mail or personal data: describe the file type and the effect, and the sample is requested through a private channel. Do not post real malware samples; to reproduce, use synthetic files like those in `pruebas/`.

This is a personal project maintained with no response-time guarantees; the aim is to reply within a few days.
