# Reglas de detección de la 1.15

[← README](../README.es.md) · [English](detection-rules.md) · **Castellano**
Motivo: un correo de cebo íntimo (fotos y un secreto, con enlace) puede salir «legítimo» con riesgo bajo si solo suma una señal de enriquecimiento y el modelo local responde «conversación normal», porque esa respuesta rebaja los puntos a la mitad. Todas las reglas son genéricas (sin dominios ni nombres propios) y ninguna alcanza sola el umbral de sospechoso.

| Regla | Dónde | Puntos | Señal |
|---|---|---|---|
| R1 | `evaluar` | 15 en enlace, 10 en texto | marcador de plantilla sin sustituir (`{tag}`, `{{x}}`, `%%x%%`, `[[x]]`, `${x}`, `<%= x %>`, también codificado en el enlace); el CSS de `<style>` que arrastra el texto visible se ignora |
| R2 | `evaluar` | 10 + 5 (tope 15) | nombre del From distinto del de la firma o presentación («Saludos, X», «soy X», «met X»); saludo por alias («Hola Gebruiker4821») |
| R3 | `evaluar` | 10 | parte local de sistema (postmaster, noreply, admin…) con nombre de persona de 2+ palabras |
| R5 | `evaluar` + modelo | 15 (sin rebaja a la mitad) + 25 del modelo | fotos/vídeos/archivos y fórmula de secreto a menos de 400 caracteres, con enlace o adjunto no inline y cuerpo de menos de 800 caracteres; el modelo tiene la pregunta `cebo_intimo_o_chantaje` (rasgo, no clase) |
| R6 | `evaluar` | 0 | idioma dominante (palabras funcionales) fuera de `ANALISTA_CORREO_IDIOMAS` (por defecto `es,en`); solo abre la puerta de R4 |
| R4 | `combinar` | suelo 40 | el modelo dice legítimo + conversación normal, hay `List-Unsubscribe` o UUID en un enlace del dominio del From **y** al menos otra señal independiente (R1, R2, R3, R5, R6, dominio de menos de un año, historial propio, cebo del modelo). Anula la rebaja a la mitad. No se aplica a remitente propio |
| R7 | `enriquecer.py` | 20 (antes 10/15) | ASN o prefijo con 5+ maliciosos y 85 % o más en 90 días; cuenta como indicador fuerte. Vuelve a 10/15 si la PTR es de una plataforma de envío o algún dominio del correo tiene más de 2 años |

R2, R3 y R6 no se aplican si el remitente es propio autenticado (`no_propio` en el indicador). Las señales sin puntos que ve el modelo (`List-Unsubscribe`, UUID de seguimiento, idioma dominante, contradicción) van en `senales_info` del JSON, no en `indicadores`, para no alterar `metricas.py` ni el resumen. Prompt: `conversacion_normal` ya no vale para un boletín con baja o un mensaje por alias.
Pruebas: `python3 -I pruebas/probar_reglas.py` (tablas SÍ/NO, `combinar`, R7 con sqlite en memoria, y los 10 sintéticos con el modelo simulado como «conversación normal»); `pruebas/generar_sinteticos.py pruebas/sinteticos` regenera los sintéticos nuevos.
Límites: R2 cree «Alejandro» y «Alex» el mismo nombre (prefijo de 3 letras) y no distingue apodos sin prefijo común (Robert/Bob dispara +10). Marcha atrás: volver a la versión anterior de tu copia; la base no se revierte (las filas guardadas llevan `version` 1.15).
