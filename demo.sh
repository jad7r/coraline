#!/usr/bin/env bash
#
# demo.sh — Coreline 3-minute live incident runbook.
#
# Runs a full SEV1 incident end-to-end through the `coreline` CLI on this laptop:
# declare -> collect + cryptographically seal evidence -> timeline -> status ->
# post-incident report -> tamper-detection finale. No network, no AI.
#
#   ./demo.sh                # run the whole thing
#   DEMO_PACE=0 ./demo.sh    # no pauses (fastest)
#   DEMO_PACE=1.5 ./demo.sh  # slower pauses for a live audience
#
set -euo pipefail

# --- locate repo + python ----------------------------------------------------- #
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
PYTHON="${CORELINE_PYTHON:-$ROOT/.venv/bin/python}"
if [[ ! -x "$PYTHON" ]]; then PYTHON="python3"; fi

PACE="${DEMO_PACE:-0.6}"

# --- isolated, inspectable demo store ----------------------------------------- #
export CORELINE_HOME="$ROOT/coreline-demo/incidents"
export CORELINE_ACTOR="alice@example.com"
EV="$ROOT/coreline-demo/evidence-source"
rm -rf "$ROOT/coreline-demo"
mkdir -p "$CORELINE_HOME" "$EV"

coreline() { "$PYTHON" -m interfaces.cli.coreline "$@"; }

banner() {
  printf '\n\033[1;36m╔══════════════════════════════════════════════════════════════════╗\033[0m\n'
  printf   '\033[1;36m║\033[0m  \033[1m%-62s\033[0m\033[1;36m║\033[0m\n' "$1"
  printf   '\033[1;36m╚══════════════════════════════════════════════════════════════════╝\033[0m\n'
  sleep "$PACE"
}
say() { printf '\033[2m$ %s\033[0m\n' "$1"; sleep "$PACE"; }

# --- fabricate realistic evidence --------------------------------------------- #
cat > "$EV/siem_alert.log" <<'LOG'
2026-08-05T14:58:11Z ALERT rule=DATA_EXFIL sev=critical
  src=10.0.0.5 dst=185.220.101.4:4521 proto=tcp bytes=45219840
  user=svc_reporting table=customers query="SELECT * FROM customers"
LOG
printf '\xd4\xc3\xb2\xa1\x02\x00\x04\x00 fake pcap: 10.0.0.5 -> 185.220.101.4 exfil session ' > "$EV/session.pcap"
cat > "$EV/db_audit.log" <<'LOG'
2026-08-05T14:57:02Z db=prod-customers user=svc_reporting rows_returned=2144908
2026-08-05T14:57:03Z db=prod-customers user=svc_reporting export=/tmp/c.csv
LOG

clear || true
banner "Coreline — LIVE SEV1 INCIDENT  (DB Exfiltration Alert)"

# --- 1. declare --------------------------------------------------------------- #
banner "1/6  DECLARE THE INCIDENT"
say 'coreline declare --title "DB Exfiltration Alert" --severity SEV1'
coreline declare --title "DB Exfiltration Alert" --severity SEV1

# --- 2. collect + seal evidence ----------------------------------------------- #
banner "2/6  COLLECT & CRYPTOGRAPHICALLY SEAL EVIDENCE"
say 'coreline evidence add --file siem_alert.log --note "SIEM: outbound to TOR exit"'
coreline evidence add --file "$EV/siem_alert.log" --note "SIEM: 43MB outbound to TOR exit node"
say 'coreline evidence add --file session.pcap --note "packet capture of exfil session"'
coreline evidence add --file "$EV/session.pcap" --note "packet capture of exfil session"
say 'coreline evidence add --file db_audit.log --note "DB audit: 2.1M rows exported"'
coreline evidence add --file "$EV/db_audit.log" --note "DB audit: 2.1M customer rows exported"

# --- 3. timeline -------------------------------------------------------------- #
banner "3/6  RECONSTRUCT THE TIMELINE (hash-linked audit log)"
say 'coreline timeline show'
coreline timeline show

# --- 4. status ---------------------------------------------------------------- #
banner "4/6  INCIDENT STATUS + QUALITY GATES"
say 'coreline status'
coreline status

# --- 5. report ---------------------------------------------------------------- #
banner "5/6  GENERATE THE POST-INCIDENT REPORT (PIR)"
say 'coreline report'
coreline report

# --- 6. tamper-detection finale ----------------------------------------------- #
banner "6/6  TAMPER-EVIDENCE  (alter sealed evidence, watch Coreline catch it)"
INC="$(cat "$CORELINE_HOME/CURRENT")"
say "an attacker edits the sealed audit log at $CORELINE_HOME/$INC/audit.jsonl ..."
"$PYTHON" - "$CORELINE_HOME/$INC/audit.jsonl" <<'PY'
import json, sys
p = sys.argv[1]
lines = open(p).read().splitlines()
d = json.loads(lines[0]); d["actor"] = "mallory@evil.tld"       # forge the record
lines[0] = json.dumps(d, sort_keys=True)
open(p, "w").write("\n".join(lines) + "\n")
print(f"  tampered: rewrote seq-1 actor -> mallory@evil.tld")
PY
sleep "$PACE"
say 'coreline status   # integrity gates re-checked against the crypto core'
coreline status

banner "DEMO COMPLETE"
printf '\033[1;32m✓ Full SEV1 incident: declared, evidence SHA-256 hashed + Ed25519 sealed,\n'
printf '  timeline reconstructed, PIR generated, tampering detected.\033[0m\n'
printf '\033[2mAll artifacts are on disk and inspectable:\033[0m\n'
printf '  \033[36m%s/%s/\033[0m\n' "$CORELINE_HOME" "$INC"
printf '    state.json · audit.jsonl · manifest.json · manifest.sig · signer.json · report.md · store/\n\n'
