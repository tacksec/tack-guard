#!/usr/bin/env bash
# Writes a progress.json file every ~8s from the live cost log, so a dashboard
# can render a live progress banner. Exits once the sweep is done.
# Override the output path with PROGRESS_OUT, and the interpreter with ADOJO_PY.
cd "$(dirname "$0")"
PY="${ADOJO_PY:-/tmp/adojo-venv/bin/python}"
OUT="${PROGRESS_OUT:-./progress.json}"

for i in $(seq 1 1400); do
  if $PY progress_json.py > "$OUT.tmp" 2>/dev/null; then
    mv "$OUT.tmp" "$OUT"
    if grep -q '"status": "done"' "$OUT"; then
      echo "sweep done — watcher exiting"
      break
    fi
  fi
  sleep 8
done
