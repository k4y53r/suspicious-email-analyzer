# Cambios

## Sin publicar
- Licencia: AGPL-3.0-only (antes MIT en el borrador; nunca se publicó con MIT). Cabecera SPDX y copyright en los `.py` y `.sh`.
- `contrib/despliegue/`: `crear-lxc.sh` (LXC en Proxmox) e `instalar.sh` (Debian 12/13) despliegan el analizador con Ollama, el modelo y un temporizador de systemd; solo hay que dar el `buzon.env`.
- El modelo de Ollama se elige con `ANALISTA_CORREO_MODELO` (buzón y línea de comandos) o `--modelo` en `analizar_correo.py`; por defecto sigue siendo `qwen2.5:7b`.

## 1.15 (primera publicación)
- Reglas de detección R1-R7 (ver README, «Reglas de detección de la 1.15»): marcador de plantilla sin sustituir, nombre distinto de la firma y saludo por alias, remitente de sistema con nombre de persona, cebo íntimo (regla de respaldo y pregunta nueva al modelo), idioma ajeno (solo puerta), contradicción «conversación normal» frente a envío masivo con suelo 40, y escalón alto (20) del historial propio de ASN y prefijo.
- Prompt: `conversacion_normal` redefinida; pregunta `cebo_intimo_o_chantaje` (rasgo de 25 puntos, no clase); el modelo ve señales informativas sin puntos.
- `combinar` admite `masivo` y `puerta` (opcionales). `senales_info` nuevo en el JSON.
- Pruebas: tablas SÍ/NO por regla, `combinar` y R7 con sqlite en memoria en `probar_reglas.py`; 10 sintéticos nuevos (3 cebos y 7 controles) en `pruebas/sinteticos/` y `corpus.tsv`.

## 1.14 (versión interna, no publicada; resumen de lo que incluye la 1.15)
- Versión interna 1.14 del analizador: indicadores técnicos deterministas (autenticación, enlaces, adjuntos por dentro, texto oculto, frases de inyección), segunda opinión de un modelo local y respuesta por correo con el JSON.
- Regla de captación (1.14): un Reply-To de otro dominio que el From **y** una imagen adjunta (no inline) suman 20 puntos más; cuenta como indicador fuerte y el modelo no puede rebajar el correo a legítimo. No se aplica a imágenes inline ni a Reply-To de plataformas de envío.
- Pruebas: `pruebas/probar_reglas.py` (121 comprobaciones en la 1.14; 231 en la 1.15; sin modelo ni red) y `pruebas/probar.sh` (corpus sintético con modelo).
- Lo específico del autor para Graylog y Grafana queda en `contrib/`; las claves y comandos opcionales de enriquecimiento (abuse.ch, OTX) se configuran por entorno.
- El historial de desarrollo anterior no se publica: la primera publicación de este repositorio es la 1.15.
