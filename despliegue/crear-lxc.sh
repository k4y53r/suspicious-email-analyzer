#!/bin/bash -p
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 k4y53r
# Crea un LXC Debian 13 en este nodo Proxmox y despliega analista-correo dentro con instalar.sh. Simula por defecto. Ejecútalo como root en el nodo.
umask 022   # pct crea /var/lib/lxc/<id> con este umask: con 077 el tar sin privilegios no puede abrirlo; los secretos van con pct push --perms 600
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
unset BASH_ENV ENV CDPATH LD_PRELOAD LD_LIBRARY_PATH PYTHONPATH PYTHONHOME
export LC_ALL=C.UTF-8
set -Eeuo pipefail
{
VMID=""; NOMBRE="analista-correo"; ALMACEN="local-lvm"; PLANTILLAS="local"; PUENTE="vmbr0"
NUCLEOS=4; MEMORIA=8192; DISCO=24; FUENTE=""; TGZ=""; ENV_ORIGEN=""; MODELO="qwen2.5:7b"; EJECUTAR=0; ONBOOT=0; CREADO=0
AQUI="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
trap 'rc=$?; [[ -z "$TGZ" ]] || rm -f "$TGZ"; (( CREADO )) && [[ -n "$ENV_ORIGEN" ]] && pct exec "$VMID" -- rm -f /root/buzon.env >/dev/null 2>&1; (( rc == 0 || ! CREADO )) || info "falló con el CT $VMID creado; para deshacer: pct stop $VMID; pct destroy $VMID --purge"; info "fin rc=$rc"' EXIT

die()  { echo "ERROR: $*" >&2; exit 1; }
info() { echo "$(date -u +%FT%TZ) >> $*"; }
hacer() { if (( EJECUTAR )); then info "ejecuto: $*"; "$@"; else info "simularía: $*"; fi; }

ayuda() {
  cat <<A
Uso: $0 [--env buzon.env] [--fuente <https://…repo.git | /ruta/analista-correo.tgz>] [--vmid N] [--nombre X] [--almacen X]
        [--puente vmbr0] [--nucleos 4] [--memoria 8192] [--disco 24] [--modelo qwen2.5:7b] [--onboot] [--ejecutar]
Sin --fuente despliega este mismo repositorio. --modelo cambia el modelo de Ollama (qwen2.5:14b o mayores si tienes memoria: sube --memoria y --nucleos). Por defecto: LXC sin privilegios, DHCP, $ALMACEN, 4 vCPU, 8 GiB, 24 GB. Necesita instalar.sh junto a este script.
Sin --ejecutar solo muestra lo que haría. Sin --env el temporizador queda sin activar.
A
}
while (( $# )); do
  case "$1" in
    --fuente) FUENTE="${2:?}"; shift 2 ;;     --env) ENV_ORIGEN="${2:?}"; shift 2 ;;
    --vmid) VMID="${2:?}"; shift 2 ;;         --nombre) NOMBRE="${2:?}"; shift 2 ;;
    --almacen) ALMACEN="${2:?}"; shift 2 ;;   --plantillas) PLANTILLAS="${2:?}"; shift 2 ;;
    --puente) PUENTE="${2:?}"; shift 2 ;;     --nucleos) NUCLEOS="${2:?}"; shift 2 ;;
    --memoria) MEMORIA="${2:?}"; shift 2 ;;   --disco) DISCO="${2:?}"; shift 2 ;;
    --modelo) MODELO="${2:?}"; shift 2 ;;     --onboot) ONBOOT=1; shift ;; --ejecutar) EJECUTAR=1; shift ;;
    -h|--help) ayuda; exit 0 ;;
    *) ayuda >&2; die "opción desconocida: $1" ;;
  esac
done

[[ "$(id -u)" == 0 ]] || die "ejecútalo como root en el nodo Proxmox."
for b in pct pveam pvesm pvesh; do command -v "$b" >/dev/null || die "falta $b: ¿es un nodo Proxmox VE?"; done
[[ -f "$AQUI/instalar.sh" ]] || die "falta instalar.sh junto a este script."
if [[ -z "$FUENTE" ]]; then       # por defecto, este mismo repositorio (sin .git ni tu buzon.env)
  REPO="$(cd "$AQUI/.." && pwd)"
  [[ -f "$REPO/analizar_correo.py" ]] || die "no encuentro el repositorio junto a este script: usa --fuente."
  if (( EJECUTAR )); then
    TGZ="$(mktemp)"
    tar czf "$TGZ" --exclude=./.git --exclude='*.env' --exclude='*.env.[!e]*' --exclude=__pycache__ --exclude=./.venv --transform 's,^\.,analista-correo,' -C "$REPO" .
    FUENTE="$TGZ"
  else FUENTE="(este repositorio, empaquetado)"; fi
fi
[[ "$FUENTE" == https://* || -f "$FUENTE" || "$FUENTE" == "(este repositorio"* ]] || die "--fuente: una URL https:// o un .tgz existente."
[[ -z "$ENV_ORIGEN" || -f "$ENV_ORIGEN" ]] || die "--env: no existe $ENV_ORIGEN."
[[ -z "$ENV_ORIGEN" ]] || ! grep -q -E 'example\.org|cambia-esto' "$ENV_ORIGEN" || die "$ENV_ORIGEN aún tiene los valores de ejemplo."
[[ "$FUENTE" != https://*@* ]] || die "la URL de --fuente no puede llevar usuario ni token."
[[ "$MODELO" =~ ^[A-Za-z0-9][A-Za-z0-9._:/-]*$ ]] || die "nombre de modelo no válido."
[[ "$NOMBRE" =~ ^[a-z0-9-]+$ && "$NUCLEOS$MEMORIA$DISCO" =~ ^[0-9]+$ ]] || die "nombre o tamaños no válidos."
[[ "$ALMACEN$PLANTILLAS$PUENTE" =~ ^[A-Za-z0-9._-]+$ ]] || die "almacén, plantillas o puente no válidos."
pvesm status --content rootdir | awk -v a="$ALMACEN" 'NR>1 && $1==a {f=1} END{exit !f}' || die "el almacén $ALMACEN no admite discos de contenedor."
ip link show "$PUENTE" >/dev/null 2>&1 || die "no existe el puente $PUENTE."
[[ -n "$VMID" ]] || VMID="$(pvesh get /cluster/nextid)"
[[ "$VMID" =~ ^[0-9]+$ ]] || die "vmid no válido."
{ pct status "$VMID" >/dev/null 2>&1 || qm status "$VMID" >/dev/null 2>&1; } && die "el id $VMID ya existe."
(( EJECUTAR )) || info "SIMULACIÓN (usa --ejecutar para aplicar). Id elegido: $VMID."

PLANTILLA="$(pveam list "$PLANTILLAS" 2>/dev/null | awk '/debian-13-standard.*amd64/{print $1}' | sort -V | tail -1 || true)"
if [[ -z "$PLANTILLA" ]]; then
  info "plantilla Debian 13 no descargada"
  hacer pveam update
  NOMBRE_TPL="$(pveam available --section system | awk '/debian-13-standard.*amd64/{print $2}' | sort -V | tail -1)"
  [[ -n "$NOMBRE_TPL" ]] || { (( EJECUTAR )) && die "no hay plantilla debian-13 disponible."; NOMBRE_TPL="debian-13-standard_*"; }
  hacer pveam download "$PLANTILLAS" "$NOMBRE_TPL"
  PLANTILLA="$PLANTILLAS:vztmpl/$NOMBRE_TPL"
fi

hacer pct create "$VMID" "$PLANTILLA" --hostname "$NOMBRE" --cores "$NUCLEOS" --memory "$MEMORIA" --swap 0 \
  --rootfs "$ALMACEN:$DISCO" --net0 "name=eth0,bridge=$PUENTE,ip=dhcp" --unprivileged 1 \
  --onboot "$ONBOOT" --description "analista-correo ($(date -u +%F))"
(( EJECUTAR )) && CREADO=1
hacer pct start "$VMID"
if (( EJECUTAR )); then
  info "espero la red del CT"
  for _ in $(seq 1 30); do pct exec "$VMID" -- getent hosts deb.debian.org >/dev/null 2>&1 && break; sleep 2; done
  pct exec "$VMID" -- getent hosts deb.debian.org >/dev/null 2>&1 || die "el CT no resuelve nombres (¿DHCP y DNS del puente $PUENTE?)."
fi

hacer pct push "$VMID" "$AQUI/instalar.sh" /root/instalar.sh --perms 700
ARGS=(--modelo "$MODELO" --ejecutar)
if [[ "$FUENTE" == https://* ]]; then ARGS+=(--fuente "$FUENTE")
else hacer pct push "$VMID" "$FUENTE" /root/analista-correo.tgz --perms 644; ARGS+=(--fuente /root/analista-correo.tgz); fi
if [[ -n "$ENV_ORIGEN" ]]; then hacer pct push "$VMID" "$ENV_ORIGEN" /root/buzon.env --perms 600; ARGS+=(--env /root/buzon.env); fi

info "instalación dentro del CT (tarda unos 15 minutos: Ollama y el modelo)"
if (( EJECUTAR )); then
  pct exec "$VMID" -- /root/instalar.sh "${ARGS[@]}"
  info "CT $VMID listo: $(pct exec "$VMID" -- hostname -I 2>/dev/null | cut -d' ' -f1)"
else info "simularía: pct exec $VMID -- /root/instalar.sh ${ARGS[*]}"; fi
exit 0
}
