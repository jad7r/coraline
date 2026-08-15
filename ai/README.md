# `ai/` — replaceable LLM provider plugins (advisory only)

Per [ADR-0002](../docs/adr/0002-ai-independent-platform.md), LLMs are **replaceable,
advisory plugins** behind one narrow interface. They provide reasoning, planning,
summarization, and recommendations — and **never** become the system of record.

- `provider` interface (to be defined in Phase 3): `reason()`, `plan()`, `summarize()`,
  `recommend()` — and nothing else.
- `providers/` — interchangeable implementations: `claude`, `openai`, `gemini`, `local`.

Rules:
- Provider output is **advisory** and is captured as a provenance-tagged artifact
  (provider, model, timestamp, input hash) in `core/audit/`. It becomes an action or a
  state change only when a human or a deterministic policy accepts it.
- **AI is optional:** the platform must run fully with no provider configured.

> **Phase 0 status:** skeleton only. The provider contract and implementations are Phase 3.
