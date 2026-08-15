#!/usr/bin/env python3
"""
Coreline forensic timeline builder.

Deterministic, reproducible timeline assembly from a frozen events file. Claude (in
Claude Desktop) reads Slack / Jira / Drive via the user's connectors and writes the
events; this script does the ordering, de-duplication, and gap detection so the result
is defensible as evidence. No network access, no Slack token, stdlib only.

INPUT — events.jsonl, one JSON object per line:
    {
      "ts":       "2026-06-26T14:03:00Z"  | "1750000000.000200" (Slack epoch),
      "source":   "slack" | "jira" | "drive" | "manual",
      "actor":    "alice@example.com" | "Alice",
      "type":     "message" | "state_change" | "evidence" | "jira_comment" | "action",
      "text":     "free text",
      "ref":      "https://permalink"   (optional),
      "evidence": true | false          (optional, default false)
    }

USAGE:
    python3 build_timeline.py --events events.jsonl --incident <id> \
        --output timeline.md [--csv timeline.csv] [--gap-minutes 30]

EXIT CODES: 0 ok · 1 usage/IO error · 2 no valid events parsed.
"""

import argparse
import csv
import json
import sys
from datetime import datetime, timezone

GAP_DEFAULT_MIN = 30

TYPE_ICON = {
    "message": "💬",
    "state_change": "🔀",
    "evidence": "📌",
    "jira_comment": "🗒️",
    "action": "⚙️",
}


def parse_ts(raw):
    """Return a timezone-aware UTC datetime from ISO-8601 or a Slack epoch string."""
    if raw is None:
        raise ValueError("missing ts")
    if isinstance(raw, (int, float)):
        return datetime.fromtimestamp(float(raw), tz=timezone.utc)
    s = str(raw).strip()
    # Slack epoch like "1750000000.000200" (or plain integer seconds)
    try:
        if s.replace(".", "", 1).isdigit():
            return datetime.fromtimestamp(float(s), tz=timezone.utc)
    except (ValueError, OSError):
        pass
    # ISO-8601, tolerate trailing Z
    iso = s.replace("Z", "+00:00")
    dt = datetime.fromisoformat(iso)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def load_events(path):
    events, errors = [], 0
    with open(path, "r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                obj["_dt"] = parse_ts(obj.get("ts"))
                obj.setdefault("source", "manual")
                obj.setdefault("actor", "unknown")
                obj.setdefault("type", "message")
                obj.setdefault("text", "")
                obj["evidence"] = bool(obj.get("evidence", False)) or obj.get("type") == "evidence"
                events.append(obj)
            except (json.JSONDecodeError, ValueError, OSError, TypeError) as exc:
                errors += 1
                sys.stderr.write(f"  ! skipped line {lineno}: {exc}\n")
    return events, errors


def dedupe(events):
    """Drop exact duplicates keyed on (timestamp, actor, normalized text)."""
    seen, out = set(), []
    for e in events:
        key = (e["_dt"].isoformat(), e.get("actor"), " ".join(e.get("text", "").split()))
        if key in seen:
            continue
        seen.add(key)
        out.append(e)
    return out


def fmt(dt):
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


def build_markdown(events, incident, gap_min):
    lines = [f"# Forensic Timeline — `{incident}`", ""]
    if not events:
        lines.append("_No events._")
        return "\n".join(lines)

    start, end = events[0]["_dt"], events[-1]["_dt"]
    dur = end - start
    ev_count = sum(1 for e in events if e["evidence"])

    lines += [
        f"- **Window:** {fmt(start)} → {fmt(end)}",
        f"- **Duration:** {format_duration(dur.total_seconds())}",
        f"- **Events:** {len(events)}  ·  **Evidence (📌):** {ev_count}",
        f"- **Generated:** {fmt(datetime.now(timezone.utc))}  ·  gap threshold: {gap_min} min",
        "",
        "| Time (UTC) | Δ | Source | Actor | Event |",
        "|---|---|---|---|---|",
    ]

    prev = None
    gap_secs = gap_min * 60
    gaps = []
    for e in events:
        delta = ""
        if prev is not None:
            d = (e["_dt"] - prev).total_seconds()
            if d >= gap_secs:
                mins = int(d // 60)
                gaps.append((prev, e["_dt"], mins))
                lines.append(
                    f"| | | | | ⚠️ **gap — {mins} min no recorded activity** |"
                )
            delta = short_delta(d)
        icon = TYPE_ICON.get(e["type"], "•")
        mark = " 📌" if e["evidence"] else ""
        text = " ".join(e.get("text", "").split())
        ref = e.get("ref")
        if ref:
            text = f"{text} ([link]({ref}))"
        text = text.replace("|", "\\|")
        lines.append(
            f"| {fmt(e['_dt'])} | {delta} | {e.get('source')} | "
            f"{e.get('actor')} | {icon} {text}{mark} |"
        )
        prev = e["_dt"]

    if ev_count:
        lines += ["", "## Evidence index (📌)", ""]
        for e in (x for x in events if x["evidence"]):
            ref = f" — {e['ref']}" if e.get("ref") else ""
            lines.append(f"- `{fmt(e['_dt'])}` · {e.get('actor')}: "
                         f"{' '.join(e.get('text','').split())}{ref}")

    if gaps:
        lines += ["", "## Timeline gaps (≥ %d min)" % gap_min, ""]
        for a, b, m in gaps:
            lines.append(f"- ⚠️ {fmt(a)} → {fmt(b)} ({m} min)")

    lines += ["", "---", "_Assembled by Coreline build_timeline.py from a frozen events "
              "file. Re-running on the same input reproduces this exact timeline._"]
    return "\n".join(lines)


def short_delta(secs):
    secs = int(secs)
    if secs < 60:
        return f"+{secs}s"
    if secs < 3600:
        return f"+{secs // 60}m"
    return f"+{secs // 3600}h{(secs % 3600) // 60:02d}m"


def format_duration(secs):
    secs = int(secs)
    h, rem = divmod(secs, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h}h {m}m"
    if m:
        return f"{m}m {s}s"
    return f"{s}s"


def write_csv(events, path):
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["timestamp_utc", "source", "actor", "type", "evidence", "text", "ref"])
        for e in events:
            w.writerow([
                e["_dt"].isoformat(), e.get("source"), e.get("actor"),
                e.get("type"), e["evidence"],
                " ".join(e.get("text", "").split()), e.get("ref", ""),
            ])


def main(argv=None):
    ap = argparse.ArgumentParser(description="Coreline forensic timeline builder")
    ap.add_argument("--events", required=True, help="path to events.jsonl")
    ap.add_argument("--incident", required=True, help="incident id (e.g. sec-ir-...)")
    ap.add_argument("--output", required=True, help="output markdown path")
    ap.add_argument("--csv", help="optional CSV output path")
    ap.add_argument("--gap-minutes", type=int, default=GAP_DEFAULT_MIN)
    args = ap.parse_args(argv)

    try:
        events, errors = load_events(args.events)
    except OSError as exc:
        sys.stderr.write(f"error: cannot read {args.events}: {exc}\n")
        return 1

    if not events:
        sys.stderr.write("error: no valid events parsed.\n")
        return 2

    events = dedupe(events)
    events.sort(key=lambda e: e["_dt"])

    md = build_markdown(events, args.incident, args.gap_minutes)
    try:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(md + "\n")
    except OSError as exc:
        sys.stderr.write(f"error: cannot write {args.output}: {exc}\n")
        return 1

    if args.csv:
        write_csv(events, args.csv)

    start, end = events[0]["_dt"], events[-1]["_dt"]
    ev_count = sum(1 for e in events if e["evidence"])
    print(f"✅ Timeline: {args.output}")
    if args.csv:
        print(f"✅ CSV:      {args.csv}")
    print(f"   {len(events)} events · {ev_count} evidence · "
          f"{format_duration((end - start).total_seconds())} "
          f"({fmt(start)} → {fmt(end)})")
    if errors:
        print(f"   ⚠️ {errors} malformed line(s) skipped — review stderr.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
