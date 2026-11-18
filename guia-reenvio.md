# Reenvío automático del spam al analista desde Thunderbird (o Gmail)

Guía para que Thunderbird reenvíe **como adjunto** al buzón del analista cada correo nuevo que su filtro adaptativo
clasifica como correo basura. Como adjunto llegan las cabeceras originales (SPF, DKIM, DMARC, IP de origen) y el
analista trabaja en modo `adjunto_rfc822`, el más completo; reenviado en el cuerpo pierde todo eso.

En los ejemplos, `analista@example.org` es la dirección del buzón del analista.

Comprobado en el código de Thunderbird (comm-central), no solo en la documentación:

| Qué | Dónde |
|---|---|
| La acción de filtro «Reenviar mensaje a» usa el modo de reenvío por defecto | `mailnews/search/src/nsMsgFilterService.cpp` (`kForwardAsDefault`) |
| `mail.forward_message_mode = 0` es adjunto; cualquier otro valor, en el cuerpo | `mailnews/compose/src/nsMsgComposeService.cpp` (`ForwardMessage`) |
| `mail.filters.forward.enabled = false` desactiva los reenvíos de filtros; si no existe, cuenta como `true` | mismo fichero |
| Los filtros «después de la clasificación» solo se aplican al correo nuevo | `mailnews/base/src/nsMsgDBFolder.cpp` (`CallFilterPlugins`, `OnMessageClassified`) |

## 1. Requisitos en el analista

- La dirección con la que reenvía cada cuenta de Thunderbird (su identidad por defecto) debe estar en
  `REMITENTES` de `buzon.py`.
- El reenvío debe salir por el servidor SMTP de esa cuenta, para que llegue firmado con DKIM de su dominio. Sin firma
  válida, `buzon.py` lo marca «sin verificar» y lo ignora si `EXIGIR_DKIM=si`.
- Cada correo reenviado genera una respuesta y una pasada del modelo (~1 min, 6 por pasada como máximo). Con mucho
  spam habrá cola.

## 2. Ajuste global de Thunderbird (una vez)

Ajustes → General → Editor de configuración:

| Preferencia | Valor | Notas |
|---|---|---|
| `mail.forward_message_mode` | `0` | Reenvío como adjunto. Afecta también al botón «Reenviar» normal; el reenvío en el cuerpo sigue en Mensaje → Reenviar como → En línea. |
| `mail.filters.forward.enabled` | no crearla | Si aparece como `false`, ponerla a `true`. |

No hay forma de que solo el filtro use adjunto: lee el mismo ajuste global.

## 3. En cada cuenta

Los filtros son por cuenta (cada una tiene su `msgFilterRules.dat`). Las cuentas IMAP necesitan cada una su filtro;
las POP que entregan en la «Bandeja de entrada global (Carpetas locales)» usan los filtros de Carpetas locales.

1. **Correo basura activado**: Configuración de la cuenta → Correo basura → «Activar los controles adaptativos de
   correo basura para esta cuenta». Sin esto nada se clasifica y el filtro no actúa.
2. **Lista blanca**: añadir `analista@example.org` a la libreta de direcciones marcada en «No marcar como basura los
   correos de remitentes en…», para que las respuestas del analista no se clasifiquen como basura.
3. **Filtro**: Herramientas → Filtros de mensajes → elegir la cuenta → Nuevo:
   - Nombre: `Spam al analista`.
   - Aplicar el filtro cuando: **Obtener correo nuevo → Filtrar después de la clasificación de correo basura**.
     Desmarcar «Ejecutar manualmente» si no se quiere poder lanzarlo a mano (ver 6.2).
   - Coincidir con **todas** las condiciones:
     - «Estado de correo basura» **es** «Correo basura».
     - «Remitente» **no contiene** `analista@example.org` (evita el bucle: respuesta clasificada como basura →
       reenviada → nueva respuesta…).
   - Acción: **Reenviar mensaje a** `analista@example.org`.
   - Sin más acciones en el mismo filtro: mover o borrar lo deja la configuración de correo basura (bug 1071628:
     reenviar y mover en el mismo filtro daba problemas con el reenvío en el cuerpo).

Thunderbird no copia filtros entre cuentas: hay que repetirlo a mano.

## 4. Comprobar

1. Enviar a una de las cuentas un correo que Thunderbird vaya a marcar como basura (o esperar al primero real).
2. En la cuenta: el correo debe quedar con el estado «Reenviado» (icono de flecha). Si no, Herramientas → Registro
   de filtros (activarlo antes) dice si el filtro se aplicó.
3. En el equipo del analista, el análisis debe salir como `adjunto_rfc822` y con la verificación del remitente en `pass`:

   ```
   tail -5 ~/.local/state/analista-correo/run.log
   sqlite3 ~/.local/state/analista-correo/analisis.db "SELECT fecha, modo, veredicto, riesgo FROM analisis ORDER BY id DESC LIMIT 5"
   ```

   Un «aviso: remitente … sin verificar» en `run.log` indica que la dirección no firma con DKIM o que no salió por su
   SMTP; «ignorado: remitente no autorizado» indica que falta en `REMITENTES`.

## 5. Límites

- Thunderbird tiene que estar abierto: los filtros se ejecutan en el cliente, no en el servidor.
- Marcar un correo como basura a mano **no** dispara el filtro: solo se aplica al correo nuevo clasificado al llegar.
- El correo que el servidor (Gmail, por ejemplo) ya manda a su carpeta Spam no pasa por la bandeja de entrada ni por
  el clasificador de Thunderbird: este filtro no lo ve. Para ese caso, ver 6.1.
- Los falsos positivos del clasificador también se reenvían. Se quedan en tu equipo, pero el enriquecimiento (si lo activas)
  consulta sus dominios e IPs en abuse.ch, listas públicas y RDAP.
- Sin comprobar: errores abiertos con los filtros «después de la clasificación» en Linux e IMAP (bugs 1245157 y
  1661989), y un hilo de soporte de 2021 sobre reenvíos de filtros que fallaban con mensajes con adjuntos.

## 6. Alternativas

### 6.1 Gmail: Apps Script sobre la carpeta Spam

Para el spam que Gmail ya aparta (la configuración de Gmail no sirve: el reenvío automático de la cuenta excluye el
spam, «Marcar como spam» solo manda copia a Google, y los filtros no tienen operador documentado para Spam).

- Un script en script.google.com con un activador por tiempo (mínimo 1 min; 10-15 min basta) que recorra
  `GmailApp.getSpamThreads()`, adjunte cada mensaje con `getRawContent()` como `message/rfc822` en
  `GmailApp.sendEmail(...)` a `analista@example.org` y marque lo enviado (etiqueta o propiedad) para no repetirlo.
  `GmailMessage.forward()` no está documentado como adjunto: no usarlo.
- Corre en Google: no necesita Thunderbird abierto. Sale de la dirección de Gmail con DKIM de `gmail.com`.
- Cuotas de cuenta personal: 100 destinatarios al día y 90 min diarios de activadores.
- Requiere dar al script permiso sobre todo el correo. El script no está incluido aquí: escribirlo y revisarlo antes
  de autorizarlo.

### 6.2 Thunderbird: el spam marcado a mano

- Reenvío manual: seleccionar el correo → Mensaje → Reenviar como → Adjunto, a `analista@example.org`.
- Por lotes: el mismo filtro con «Ejecutar manualmente» marcado, y en la carpeta Correo basura Herramientas →
  Ejecutar filtros en la carpeta. Reenvía todo lo que haya en ella: el analista reconoce los ya analizados (responde
  «YA ANALIZADO» sin modelo), pero cada uno genera una respuesta.
- Los filtros periódicos (cada 10 min por defecto) solo se describen en foros para la bandeja de entrada: sin
  confirmar en la carpeta Correo basura.

### 6.3 Complementos de Thunderbird

No hay ninguno actual que reenvíe automáticamente el correo marcado como basura (consulta de la fecha de redacción;
addons.thunderbird.net no se pudo abrir, compatibilidades sin comprobar):

- FiltaQuilla: acciones extra de filtro, sin reenvío como adjunto.
- Habu y KnujOn: botón para reenviar el spam de la carpeta abierta; antiguos, probablemente incompatibles.
- Forward: elige adjunto o en el cuerpo en el reenvío normal; no es para spam.

No se recomienda ninguno.
