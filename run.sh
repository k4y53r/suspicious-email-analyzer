#!/usr/bin/env bash
# Una pasada por el buzón, sin solaparse con la anterior. Lánzalo desde cron o un timer de systemd cada pocos minutos.
set -uo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATE="$HOME/.local/state/analista-correo"
mkdir -p -m 700 "$STATE"
exec 9>"$STATE/lock"
flock -n 9 || exit 0
# Con 6 correos como máximo por pasada y ~1-2 min cada uno sobra; evita que una pasada colgada bloquee las siguientes.
timeout 25m python3 "$DIR/buzon.py" "$@"
rc=$?
[ $rc -ne 0 ] && echo "$(date -Is) buzon.py rc=$rc"
exit $rc
