# `connectors/` — connector framework

A uniform interface over external systems (Slack, Jira/Confluence, Google Drive, Grafana,
…) that `core/` depends on. Each connector is an adapter behind a common contract so the
platform is not bound to any one vendor or transport.

Notes:
- Two credential modes (ADR-0002 trade-off): **assisted mode** rides the operator's OAuth
  connectors inside Claude Desktop (zero standing tokens); **headless mode** uses the
  platform's own credentials via a dedicated secrets layer (the Gen-2/3
  `services/shared/secrets_manager.py` dual-mode pattern is the starting point).
- The Gen-2/3 `collectors/` (Jira, Slack) and `lib/grafana_irm.py` in the fossil are
  candidate sources to generalize here.

> **Phase 0 status:** skeleton only. Built in Phase 2.
