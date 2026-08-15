#!/usr/bin/env bash
#
# run_gui.sh — boot the Coreline web console.
#
# Starts a local Streamlit server on http://localhost:8501 and opens your browser.
# Everything is point-and-click: declare an incident, drag evidence onto the dropzone,
# watch the timeline + integrity gates update live. No command line, no flags.
#
#   ./run_gui.sh
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

PYTHON="${CORELINE_PYTHON:-$ROOT/.venv/bin/python}"
if [[ ! -x "$PYTHON" ]]; then PYTHON="python3"; fi

# Ensure the web deps are present (first run only).
if ! "$PYTHON" -c "import streamlit" 2>/dev/null; then
  echo "[coreline] installing web dependencies (first run)…"
  "$PYTHON" -m pip install -q streamlit
fi

# Shared incident store — same files the CLI uses. Override with CORELINE_HOME.
export CORELINE_HOME="${CORELINE_HOME:-$ROOT/coreline-incidents}"
mkdir -p "$CORELINE_HOME"

echo "[coreline] incident store : $CORELINE_HOME"
echo "[coreline] opening        : http://localhost:8501"
exec "$PYTHON" -m streamlit run "$ROOT/interfaces/gui/app.py" \
  --server.port 8501 \
  --browser.gatherUsageStats false
