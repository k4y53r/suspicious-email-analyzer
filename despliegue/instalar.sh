#!/bin/bash -p
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 k4y53r
# Instala analista-correo dentro de un Debian 12/13 (el LXC o cualquier máquina), como root. Simula por defecto.
umask 077
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
unset BASH_ENV ENV CDPATH LD_PRELOAD LD_LIBRARY_PATH PYTHONPATH PYTHONHOME
export LC_ALL=C.UTF-8 DEBIAN_FRONTEND=noninteractive
set -Eeuo pipefail
cd /
{
readonly USUARIO="analista"
readonly HOME_U="/home/$USUARIO"
readonly DESTINO="$HOME_U/analista-correo"
readonly ENV_DEST="$HOME_U/.config/analista-correo/buzon.env"
MODELO="qwen2.5:7b"; FUENTE=""; ENV_ORIGEN=""; EJECUTAR=0; SIN_PRUEBA=0; TMP_OLLAMA=""
trap 'rc=$?; [[ -z "$TMP_OLLAMA" ]] || rm -f "$TMP_OLLAMA"; info "fin rc=$rc"' EXIT

die()  { echo "ERROR: $*" >&2; exit 1; }
info() { echo "$(date -u +%FT%TZ) >> $*"; }
hacer() { if (( EJECUTAR )); then info "ejecuto: $*"; "$@"; else info "simularía: $*"; fi; }
como_u() { runuser -u "$USUARIO" -- "$@"; }

ayuda() {
  cat <<A
Uso: $0 [--fuente <https://…repo.git | .tgz | directorio>] [--env <buzon.env>] [--modelo <modelo ollama>] [--sin-prueba] [--ejecutar]
  --fuente   repositorio git (https), .tgz con el directorio analista-correo/ dentro o directorio; por defecto, el repositorio donde está este script.
  --env      fichero buzon.env ya relleno (se copia con 600). Sin él no se activa el temporizador.
  --modelo   modelo de Ollama (por defecto $MODELO; qwen2.5:3b si vas justo de memoria).
  --sin-prueba  no ejecuta las pruebas ni el análisis de ejemplo al final.
Sin --ejecutar solo muestra lo que haría. Ollama se instala con su script oficial (https://ollama.com/install.sh).
A
}

while (( $# )); do
  case "$1" in
    --fuente) FUENTE="${2:?}"; shift 2 ;;
    --env) ENV_ORIGEN="${2:?}"; shift 2 ;;
    --modelo) MODELO="${2:?}"; shift 2 ;;
    --sin-prueba) SIN_PRUEBA=1; shift ;;
    --ejecutar) EJECUTAR=1; shift ;;
    -h|--help) ayuda; exit 0 ;;
    *) ayuda >&2; die "opción desconocida: $1" ;;
  esac
done

[[ "$(id -u)" == 0 ]] || die "ejecútalo como root."
. /etc/os-release
[[ "${ID:-}" == debian && "${VERSION_ID:-}" =~ ^(12|13)$ ]] || die "solo Debian 12 o 13 (hay ${ID:-?} ${VERSION_ID:-?})."
AQUI="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[[ -n "$FUENTE" || ! -f "$AQUI/../analizar_correo.py" ]] || FUENTE="$(cd "$AQUI/.." && pwd)"   # por defecto, este repositorio
[[ -n "$FUENTE" ]] || { ayuda >&2; die "falta --fuente."; }
[[ "$FUENTE" == https://* || -f "$FUENTE" || -d "$FUENTE" ]] || die "--fuente: una URL https://, un .tgz o un directorio existentes."
[[ "$MODELO" =~ ^[A-Za-z0-9][A-Za-z0-9._:/-]*$ ]] || die "nombre de modelo no válido."
[[ -z "$ENV_ORIGEN" || -f "$ENV_ORIGEN" ]] || die "--env: no existe $ENV_ORIGEN."
[[ -z "$ENV_ORIGEN" ]] || ! grep -q -E 'example\.org|cambia-esto' "$ENV_ORIGEN" || die "$ENV_ORIGEN aún tiene los valores de ejemplo."
(( EJECUTAR )) || info "SIMULACIÓN (usa --ejecutar para aplicar)."

info "paquetes"
hacer apt-get update -qq
hacer apt-get install -y -qq python3 git bind9-dnsutils jq curl zstd ca-certificates util-linux

info "usuario $USUARIO"
id "$USUARIO" >/dev/null 2>&1 || hacer useradd -m -s /bin/bash "$USUARIO"

info "Ollama y modelo $MODELO"
if ! { command -v ollama >/dev/null 2>&1 && systemctl cat ollama.service >/dev/null 2>&1; }; then
  if (( EJECUTAR )); then
    TMP_OLLAMA="$(mktemp)"; curl -fsSL https://ollama.com/install.sh -o "$TMP_OLLAMA"; ( umask 022; sh "$TMP_OLLAMA" )
  else info "simularía: descargar y ejecutar https://ollama.com/install.sh"; fi
fi
if (( EJECUTAR )); then
  for _ in $(seq 1 30); do ollama list >/dev/null 2>&1 && break; sleep 2; done
  ollama list >/dev/null 2>&1 || die "el servicio de Ollama no responde."
  for i in 1 2 3 4 5; do ollama pull "$MODELO" && break; (( i < 5 )) || die "no se pudo descargar $MODELO."; info "reintento $i"; sleep 20; done
else info "simularía: ollama pull $MODELO (hasta 5 intentos)"; fi

info "código en $DESTINO"
if [[ -e "$DESTINO" ]]; then
  [[ -f "$DESTINO/analizar_correo.py" && -f "$DESTINO/buzon.py" ]] || die "$DESTINO existe pero está incompleto (instalación a medias): bórralo (rm -rf $DESTINO) y repite."
  info "ya existe y está completo: no se toca (para actualizarlo, ver el README de despliegue)"
else
  NUEVO="$HOME_U/.analista-correo.nuevo"   # se prepara aparte y se mueve entero: nunca queda una copia a medias en $DESTINO
  hacer rm -rf "$NUEVO"
  if [[ "$FUENTE" == https://* ]]; then
    hacer runuser -u "$USUARIO" -- git clone --quiet -- "$FUENTE" "$NUEVO"
  elif [[ -d "$FUENTE" ]]; then
    if (( EJECUTAR )); then
      runuser -u "$USUARIO" -- mkdir -m 755 "$NUEVO"
      tar -C "$FUENTE" --exclude=./.git --exclude='*.env' --exclude='*.env.[!e]*' --exclude='*.prev' --exclude='*.antes' \
        --exclude=__pycache__ --exclude=./.venv --exclude=./resultados -cf - . | runuser -u "$USUARIO" -- tar xf - -C "$NUEVO" --no-same-owner
    else info "simularía: copiar $FUENTE en $NUEVO"; fi
  else
    if (( EJECUTAR )); then
      runuser -u "$USUARIO" -- mkdir -m 755 "$NUEVO"
      runuser -u "$USUARIO" -- tar xzf - -C "$NUEVO" --no-same-owner --strip-components=1 < "$FUENTE"
    else info "simularía: extraer $FUENTE en $NUEVO"; fi
  fi
  if (( EJECUTAR )); then
    [[ -f "$NUEVO/analizar_correo.py" && -f "$NUEVO/buzon.py" ]] || die "la fuente no contiene el analizador (¿es el repositorio o un .tgz con una carpeta raíz?)."
    mv -- "$NUEVO" "$DESTINO"
  else info "simularía: mover $NUEVO a $DESTINO"; fi
fi

info "configuración del buzón"
if [[ -n "$ENV_ORIGEN" ]]; then
  hacer runuser -u "$USUARIO" -- mkdir -p -m 700 "$(dirname "$ENV_DEST")"
  hacer install -m 600 -o "$USUARIO" -g "$USUARIO" "$ENV_ORIGEN" "$ENV_DEST"
else info "sin --env: copia buzon.env.example a $ENV_DEST, edítalo y activa el temporizador a mano."; fi

if (( EJECUTAR && ! SIN_PRUEBA )); then
  info "pruebas"
  salida="$(como_u python3 -I "$DESTINO/pruebas/probar_reglas.py")" || die "fallan las pruebas."
  echo "$salida" | tail -1
  grep -q ' 0 fallos' <<<"$salida" || die "las pruebas no dicen «0 fallos»."
  if ! como_u env ANALISTA_CORREO_MODELO="$MODELO" ANALISTA_CORREO_SIN_ENRIQUECER=1 python3 "$DESTINO/analizar_correo.py" "$DESTINO/pruebas/sinteticos/malware-adjunto.eml" >/dev/null; then die "falla el análisis de ejemplo."; fi
  info "análisis de ejemplo OK"
fi
info "temporizador (cada 2 minutos)"
if (( EJECUTAR )); then
  ( umask 022; cat > /etc/systemd/system/analista-correo.service <<U
[Unit]
Description=analista-correo: una pasada por el buzon
After=network-online.target ollama.service
[Service]
Type=oneshot
User=$USUARIO
Environment=ANALISTA_CORREO_MODELO=$MODELO
ExecStart=$DESTINO/run.sh
Nice=10
U
  )
  ( umask 022; cat > /etc/systemd/system/analista-correo.timer <<U
[Unit]
Description=analista-correo cada 2 minutos
[Timer]
OnBootSec=2min
OnUnitActiveSec=2min
[Install]
WantedBy=timers.target
U
  )
  systemctl daemon-reload
  if [[ -n "$ENV_ORIGEN" ]]; then systemctl enable --now analista-correo.timer; else info "temporizador creado pero NO activado (falta --env)."; fi
else info "simularía: crear analista-correo.service/.timer y activarlo si hay --env"; fi

exit 0
}
