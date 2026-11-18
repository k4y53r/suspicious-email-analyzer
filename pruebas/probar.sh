#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 k4y53r
# Pasa el corpus por el analizador y compara con lo esperado. Uso: probar.sh [modelo] [salida.jsonl]
set -uo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODELO="${1:-qwen2.5:7b}"
OUT="${2:-/dev/stdout}"
PAUSA="${PAUSA:-60}"  # enfría la CPU entre correos: sin pausa, una tanda larga puede disparar la temperatura
: > "$OUT" 2>/dev/null || true
grep -v '^#' "$DIR/corpus.tsv" | while IFS=$'\t' read -r f modo esperado; do
  [ -n "${primero:-}" ] && sleep "$PAUSA"; primero=no
  f="${f/#\~/$HOME}"
  [[ "$f" == /* ]] || f="$DIR/../$f"   # rutas relativas a la raíz del repositorio
  op=(); [ "$modo" = reenviado ] && op=(--reenviado)
  python3 "$DIR/../analizar_correo.py" "${op[@]}" --enriquecer --modelo "$MODELO" "$f" \
    | jq -c --arg e "$esperado" '{f: (.fichero|split("/")|.[-3:]|join("/")), esperado: $e, veredicto, riesgo, tecnico: .riesgo_tecnico,
        llm: (.modelo|if .error then .error else [.clasificacion, .puntos, .rasgos, .marca, .segundos] end),
        ok: (.veredicto as $v | $e == "dudoso" or ($e|split("|")|index([$v])) != null), explicacion: .modelo.explicacion}' >> "$OUT"
done
