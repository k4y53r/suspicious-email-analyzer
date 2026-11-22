#!/usr/bin/env bash
# Una pasada por el buzón, sin solaparse con la anterior. Lánzalo desde cron o un timer de systemd cada pocos minutos.
set -uo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATE="$HOME/.local/state/analista-correo"
mkdir -p -m 700 "$STATE"
exec 9>"$STATE/lock"
# Cron o timer (sin argumentos): con otra pasada en marcha se sale en silencio. A mano (--uid…): espera hasta 5 min al lock, en vez de no hacer nada sin avisar.
if [ $# -eq 0 ]; then
    flock -n 9 || exit 0
else
    flock -w 300 9 || { echo "$(date -u +%FT%TZ) run.sh: otra pasada tiene el lock desde hace más de 5 min"; exit 1; }
fi
# Con 6 correos como máximo por pasada y ~1-2 min cada uno sobra; evita que una pasada colgada bloquee las siguientes (-k: SIGKILL a los 30 s si ignora SIGTERM).
timeout -k 30 25m python3 "$DIR/buzon.py" "$@"
rc=$?
[ $rc -ne 0 ] && echo "$(date -u +%FT%TZ) buzon.py rc=$rc"
exit $rc
