# Coreline Session Summary - 2026-09-19

## Starting point

Read the September 18 checkpoint. Trusted CLI verification is implemented;
its uncommitted changes were preserved. Continued the documented next step:
reconcile service documentation and environment examples.

## Completed

- Added `services/README.md` with shared CORELINE_ settings, exact secret names,
  resolver precedence, keychain namespaces, and repo-root startup instructions.
- Replaced stale service README deployment and compliance claims with current
  implementation descriptions and links to configuration source.
- Added Jira and brain environment templates; corrected Slack's template.
  Templates are shell-compatible and are exported explicitly so secret resolvers
  see credentials without relying on Pydantic dotenv loading.
- Documented the brain collector placeholders, credential-required HTTP startup,
  and readiness limitations for keychain-only credentials.
- Updated the root README baseline and linked shared service setup.

## Validation

Full baseline: **386 passed, 1 skipped, 17 warnings, 6 subtests passed** in 28.29s.
Each template was loaded into an isolated environment and validated with its
service Settings class. Shell syntax and `git diff --check` passed.
No live integrations or container deployments were exercised.
Changes remain uncommitted.

## Follow-up implementation: shared secrets and readiness

Implemented shared CORELINE_ secret resolution for Jira, Slack, and brain.
Prefixed environment values win over unprefixed aliases, then the Coreline
keychain, then legacy secops-secure-enclave entries. Both Anthropic and Claude
API-key aliases remain supported. Removed the brain service's duplicate resolver;
startup, provider selection, and readiness now use services/shared/secrets.py.
Readiness accepts keychain-only credentials and still fails for missing
credentials or unavailable Redis. Updated service docs and environment templates.

Validation: full baseline **396 passed, 1 skipped, 17 warnings, 6 subtests passed**
in 26.40s. After adding a provider-selection regression, the focused secret suite
passed **11 tests**. Tests isolate environment/keychain access and use fake Redis
and provider clients. No live integrations were exercised. Changes are uncommitted.

## Next steps

1. Define and implement explicit offline HTTP startup for the brain service;
   keep fake collector output clearly identified as advisory placeholder data.
2. Revisit container deployment and the older Jira TESTING guide against actual
   runtime behavior before treating the integrations as production-ready.
