# Installing the Coreline skill

Coreline v3 is a **Claude Desktop skill** plus one offline Python script. No service to
deploy, no Slack token for Python.

## 1. Install the skill

**Claude Desktop and Claude Code discover skills differently**, so the install step
differs. Coreline is driven from **Claude Desktop**, so that's the primary path.

### Claude Desktop (primary — the Coreline driver)

Desktop loads skills from your **Claude account**, not from any local directory. You
package the skill as a ZIP and upload it. The folder inside the ZIP must be named
`coreline` (lowercase) to match the `name:` field in `SKILL.md` — Desktop rejects a
mismatch with *"Skill folder name doesn't match the skill name."* Because the repo
folder is `Coreline`, stage a correctly-named copy first (on case-insensitive macOS you
can't make an `coreline` sibling of `Coreline`, so stage it under `/tmp`):

```bash
# run from the secops-tools repo root
mkdir -p /tmp/coreline-pkg && cp -R coreline /tmp/coreline-pkg/coreline
( cd /tmp/coreline-pkg && zip -r coreline.zip coreline )
```

Then in Claude Desktop: **Customize → Skills → `+` → Upload a skill**, choose
`/tmp/coreline-pkg/coreline.zip`, and toggle it on. It appears under **Customize → Skills**.
No restart needed.

> On Team/Enterprise plans an admin can provision Coreline org-wide (Organization
> settings → Skills) so all four of us get it automatically. On other plans each
> person uploads it themselves.

### Claude Code (CLI — optional)

Code scans the filesystem, so a copy is all it takes (no upload, no restart — it's
detected live). The folder must be lowercase `coreline`:

```bash
# run from the secops-tools repo root
mkdir -p ~/.claude/skills
cp -R coreline ~/.claude/skills/coreline
```

> ⚠️ Claude **Desktop does not read** `~/.claude/skills/`. Copying the folder there
> makes the skill show up in Claude Code only — not in Desktop. (Local-filesystem
> skill loading for Desktop is an open, unimplemented feature request.) For Desktop,
> use the ZIP upload above.

## 2. Connectors used

The skill drives these connectors you already have:

- **Slack** — send messages, create/update canvas, schedule messages, read
  channels/threads/reactions. (Cannot create channels — see below.)
- **Jira / Confluence** — create + update the incident ticket.
- **Google Drive** — incident doc and evidence preservation.

## 3. The one manual step

The Slack connector can't create channels, so the IC creates the channel by hand.
Coreline gives the exact name to paste, then does all remaining setup. (If you later want
this automated too, the smallest IT ask is a Slack app with **only** `channels:manage`
scope — far narrower than the old broad bot token.)

## 4. Use it

- **Kick off:** *"Declare a SEV1 ransomware incident on prod-webservers, I'm IC."*
- **Evidence:** team reacts 📌 in-channel; later say *"pull the evidence."*
- **Timeline:** *"build the forensic timeline for `sec-ir-...`"* — Claude gathers
  events and runs `build_timeline.py`.
- **Handoff / PIR:** *"handoff to Bob"* · *"write the PIR."*

## 5. Python script (standalone)

Works on its own, stdlib only (no pip install). Run it straight from your repo clone —
this path always exists, regardless of how (or whether) the skill is installed:

```bash
# from the secops-tools repo root
python3 coreline/scripts/build_timeline.py \
  --events events.jsonl --incident sec-ir-2026-06-26-ransomware-prod-webservers \
  --output timeline.md --csv timeline.csv --gap-minutes 30
```

> **Why the repo clone and not the skill install?** Whether Claude Desktop runs a
> skill's bundled Python locally or server-side isn't publicly documented, and code
> execution may depend on plan tier. Running the script from the clone is the
> guaranteed-offline path — no Claude, no network. (Open item: confirm Desktop's
> execution model with Anthropic support if we want the timeline to auto-run.)

## What changed from v2 → v3

| | v2 (Python-heavy) | v3 (this) |
|---|---|---|
| Driver | Python scripts + microservices + daemons | Claude Desktop skill |
| Slack | Bot token, broad scopes, evidence daemon | Your OAuth connector; 📌 pulled on demand |
| Channel creation | Automated (needed broad token) | Manual (10s); skill does the rest |
| Python's job | Everything | Forensic timeline only — no token, deterministic |
| Deploy / maintain | Secrets, enclave, GCP, webhooks | Nothing to run |

**Dropped from the core path (by design):** GCP WORM bucket, secure enclave, Grafana
sync, IOC tracker, dashboard server. If WORM-grade immutable retention is required for
a specific incident, that still needs the GCP path — flag it when it matters.
