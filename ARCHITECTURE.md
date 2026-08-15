# Coreline — Architecture

**Coreline** (Automated Response & Evidence System) is a single-file macOS desktop
client that lets a security incident commander declare an incident and, in one
action, provision the three artifacts every response needs: a **Google Doc**
record, a dedicated **Slack channel**, and an immutable **WORM evidence
manifest** in Google Cloud Storage.

This document describes how Coreline is built, why it is built that way, and the
operational and security boundaries it lives within. For installation and
day-to-day use, see [`README.md`](./README.md).

---

## 1. Design principles

Coreline is deliberately small. Every decision below trades cleverness for
operability.

| Principle | What it means in practice |
|---|---|
| **Single operator mode** | Coreline acts as the signed-in human. No service accounts, no "team"/"dry-run"/"local" modes, no privileged daemon. |
| **Identity-first security** | Authentication is the operator's own Google/Okta SSO via the system browser. Coreline holds no long-lived credentials except a Keychain-stored refresh token. |
| **Secrets never touch disk in plaintext** | All secrets live in the macOS Keychain via `keyring`. The on-disk config file holds non-secret values only. |
| **Resilient, silent failure** | No raw Python traceback ever reaches the operator. Every backend exception is funnelled through one translator into a calm, actionable message. |
| **Zero duct-tape** | No placeholder functions, no `TODO`s, no half-wired buttons. Each control performs a complete operation. |
| **Operator-centric UX** | Looks and behaves like an enterprise macOS app, not a developer script. Network work never blocks the UI. |

---

## 2. Component overview

Coreline is four Python modules plus a small set of external services.

```
┌──────────────────────────────────────────────────────────────────────┐
│                              gui.py                                     │
│  ┌────────────┐  ┌──────────────┐  ┌──────────────────────────────┐    │
│  │    App     │  │  SetupScreen │  │           MainView           │    │
│  │ controller │  │ (first run)  │  │  Declare Incident · Settings │    │
│  └─────┬──────┘  └──────┬───────┘  └───────────────┬──────────────┘    │
│        │                │                          │                    │
│        │        ┌───────┴──────────────────────────┴───────┐           │
│        │        │            IncidentServices               │           │
│        │        │  Drive · Docs · GCS(WORM) · Slack hooks    │           │
│        │        └───────┬───────────────┬───────────────────┘           │
│        │                │               │                               │
│   widget factories      │               │   friendly_error()            │
│   (CustomTkinter / Tk)  │               │   (exception translator)      │
└────────────────────────┼───────────────┼───────────────────────────────┘
                         │               │
                ┌────────┴──────┐  ┌─────┴───────────────────────────┐
                │   auth.py     │  │           storage.py            │
                │ CorelineAuthManager│  │          CorelineStorage            │
                │ browser OAuth │  │ Keychain secrets + JSON config  │
                └───────┬───────┘  └─────┬───────────────────────────┘
                        │                │
        ┌───────────────┴───┐   ┌────────┴──────────┐
        │ Google OAuth /    │   │  macOS Keychain    │
        │ Okta SSO (browser)│   │  ~/.config/coreline/   │
        └───────────────────┘   └───────────────────┘

External services: Google Drive, Google Docs, Google Cloud Storage, Slack.
```

### 2.1 `storage.py` — `CorelineStorage`

The persistence boundary. Two stores, strictly separated by sensitivity:

- **Non-secret config** — a JSON file at `~/.config/coreline/config.json`.
  Methods: `initialize_storage()`, `load_config()`, `save_config(dict)` (merge
  semantics). Holds operator profile, Drive folder ID, WORM bucket name, Slack
  team ID, and the `setup_complete` flag.
- **Secrets** — the macOS Keychain under service name `Coreline`, via the
  `keyring` library. Methods: `set_secret(key, value)`, `get_secret(key)`.
  Keychain errors are caught and re-raised as friendly `RuntimeError`s (writes)
  or swallowed to `None` (reads).
- **`clear_all()`** — purges the config file and deletes both known secret keys
  (`google_refresh_token`, `slack_bot_token`). Backs the "Reset Coreline" action.

`storage.py` knows nothing about Google, Slack, or the UI. It is the only module
that touches the filesystem or the Keychain.

### 2.2 `auth.py` — `CorelineAuthManager`

The authentication boundary. Implements the desktop OAuth flow and credential
hydration. All methods are static; the class is a namespace.

- **`run_oauth_flow() -> str`** — builds an `InstalledAppFlow`
  `from_client_config`, opens the system browser (`run_local_server(port=0)`),
  and the browser completes Google/Okta SSO. Uses `access_type="offline"` +
  `prompt="consent"` so a refresh token is *always* returned, even when
  re-authenticating after a scope change. On success it stores the refresh
  token in the Keychain and returns the operator email (best-effort).
- **`get_google_credentials() -> Optional[Credentials]`** — rehydrates a
  `google.oauth2.credentials.Credentials` object from the Keychain refresh token
  plus the resolved client config. Returns `None` if not signed in. Google's
  client libraries refresh the access token silently from this object.
- **`is_provisioned() -> bool`** — true if an OAuth client is available without
  operator interaction; lets the UI render a clean "not provisioned" message
  instead of failing mid-flow.

**OAuth client resolution** (see §6) is internal and never exposed to the
operator.

### 2.3 `gui.py` — presentation + orchestration

The single-file application. Logically it contains five layers:

1. **Toolkit abstraction.** A set of widget factories (`frame`, `card`,
   `label`, `button`, `entry`, `textbox`, `option_menu`, `checkbox`) plus
   `ScrollFrame`, `TabView`, and `ActivityLog`. Each factory branches on a
   single global, `USING_CTK`, so all layout code is written once and runs on
   either CustomTkinter or native `tkinter`. See §5.
2. **`App` controller.** Owns the root window and a single content container.
   `show_start()` reads `setup_complete` and mounts either `SetupScreen` or
   `MainView`. Provides the threading primitive `run_async(work, on_ok, on_err)`
   and the main-thread marshal `ui_call(fn)`.
3. **`SetupScreen`.** The first-run, single-screen configuration gate (§4.1).
4. **`MainView`.** The operational console: a `Declare Incident` tab and a
   `Settings` tab (§4.2, §4.3).
5. **`IncidentServices` + helpers.** The API orchestration hooks plus the pure
   helpers (`extract_drive_folder_id`, `extract_bucket_name`,
   `sanitize_channel`, `build_doc_template`) and the exception translator
   `friendly_error`.

### 2.4 `reset_google_auth.py` — operational utility

A standalone CLI to clear cached auth. Default mode deletes only the Google
refresh token (forces fresh sign-in, preserves config); `--all` calls
`CorelineStorage.clear_all()`. Used after a scope change or to recover from a
revoked token.

---

## 3. `IncidentServices` — the orchestration core

`IncidentServices` is the only place that talks to Google and Slack. It is
constructed per-operation (cheap), reads the current config, and lazily caches
a single `Credentials` object for its lifetime.

Backend clients are imported **lazily inside methods**, never at module load, so
the window always opens — even on a partial dependency install — and surfaces a
friendly message instead of crashing on import.

### 3.1 Credential & client plumbing

| Method | Builds | Notes |
|---|---|---|
| `creds()` | `Credentials` | Via `CorelineAuthManager.get_google_credentials()`; raises `CorelineError` if not signed in. Cached on the instance. |
| `_drive()` | Drive v3 client | `googleapiclient.discovery.build`, `cache_discovery=False`. |
| `_docs()` | Docs v1 client | Same. |
| `_gcs()` | GCS client | `google.cloud.storage.Client` with a **placeholder project** (`GCS_CLIENT_PROJECT`) — bucket-scoped object ops don't need a real project, so the operator is never asked for one. |
| `_slack()` | Slack `WebClient` | Token read from Keychain; raises `CorelineError` if unset. |

### 3.2 Validators (used by setup & settings)

- `validate_drive_folder(folder_id) -> name` — `files().get(...,
  supportsAllDrives=True)`, asserts the mime type is a folder, returns the name.
- `validate_bucket(bucket_name) -> {create, read}` — calls
  `bucket.test_iam_permissions([...])` and reports whether the operator holds
  `storage.objects.create` (and `…get`). No object is written during
  validation.
- `validate_slack(token) -> {team, team_id, user}` — `auth_test()`.

### 3.3 Incident operations

- `create_doc(title, body)` — creates a Google Doc **directly inside** the
  configured Drive folder (`files().create` with `parents=[folder_id]` and the
  Google-Doc mime type), then inserts a structured incident template via the
  Docs API `batchUpdate`. Returns `{id, url}`.
- `create_channel(name, topic, intro)` — `conversations_create`, sets the topic
  and posts the commander brief (both best-effort), returns `{id, name, url}`.
- `write_manifest(incident_id, manifest)` — uploads
  `incidents/<id>/manifest.json` to the WORM bucket via `upload_from_string`.
  Returns `{uri, url}`.

---

## 4. Screens and flows

### 4.1 Setup (first run)

`SetupScreen` is a **single scrollable screen** that locks the app until Coreline is
fully configured. It asks for exactly five fields and exposes five actions:

| Field | Action button | Backed by |
|---|---|---|
| Operator name | — | config |
| Operator email | — | config |
| (Google identity) | **Sign in with Google** | `run_oauth_flow()` |
| Google Drive folder URL or ID | **Validate Drive Folder** | `validate_drive_folder` |
| GCP WORM bucket name | **Validate WORM Bucket** | `validate_bucket` |
| Slack bot token (`xoxb-…`) | **Save Slack Token and Test** | `validate_slack` → Keychain |
| | **Finish Setup** | persists config, sets `setup_complete` |

`Finish Setup` is disabled until the operator name is present **and** Google is
signed in **and** the Drive folder validated **and** the WORM bucket confirmed
writable **and** the Slack token saved+tested. Each validator persists its
result as it succeeds (`drive_folder_id`, `worm_bucket`, `slack_team_id`), so a
re-run resumes from saved values.

```
Operator name/email
        │
        ▼
Sign in with Google ──browser──► Google/Okta SSO ──► refresh token → Keychain
        │
        ▼
Validate Drive Folder ──► Drive API files().get ──► folder name shown
        │
        ▼
Validate WORM Bucket ──► GCS testIamPermissions ──► storage.objects.create ✓/⚠
        │
        ▼
Save Slack Token and Test ──► Slack auth_test ──► token → Keychain
        │
        ▼
Finish Setup ──► setup_complete=true ──► MainView
```

### 4.2 Declare Incident

A two-column tab: a form (left) and a live `ActivityLog` (right). The operator
sets a title, severity (SEV1–SEV4), an initial summary, a Slack channel name
(auto-suggested and sanitized), and three independent toggles — *Create Google
Doc*, *Create Slack channel*, *Write WORM manifest*.

On **Declare Incident**, Coreline mints an `INC-YYYYMMDD-HHMMSS` ID and runs the
selected steps **on a background thread**, streaming progress into the log with
clickable result links. Each step is independently `try`/`except`-wrapped: a
failure in one step (e.g. Slack) does not abort the others, and the manifest
records whichever artifacts were created. This is deliberate — partial success
is still useful during a live incident.

### 4.3 Settings

Edit the operator profile; **Reconnect Google** (re-runs the OAuth flow if auth
fails or was revoked); re-validate the Drive folder and WORM bucket; replace and
re-test the Slack token; and a **Reset Coreline** action (`clear_all()` → back to
Setup).

---

## 5. Rendering: CustomTkinter with a native fallback

Coreline prefers **CustomTkinter** for a modern look but must run wherever the
operator's Python lands. At import time it **probes** CustomTkinter — it
constructs and renders a throwaway `CTk()` root — because a successful `import`
does not guarantee runtime compatibility with the host's Tk build. If the probe
raises, Coreline sets `USING_CTK = False` and the same UI renders with native
`tkinter`/`ttk`.

All widgets are created through factory functions that branch on `USING_CTK`, so
there is exactly one copy of the layout logic. Multi-line text and the activity
log use plain `tk.Text` in both modes for uniform behavior (tag binding,
clickable links).

> **Environment note.** Homebrew's default Python ships without Tk. Coreline is run
> from a virtualenv built on a Python that has Tk (`brew install python-tk`
> provides it). CustomTkinter renders correctly on Tk 9.0 in this setup; the
> probe makes the fallback automatic if a given machine differs.

---

## 6. Security model

### 6.1 Identity & the OAuth client

Coreline authenticates the **operator**, never a service account. The flow is a
standard desktop OAuth installed-app flow; the browser transparently handles
the corporate Okta ↔ Google SSO handshake.

The application's OAuth *client* (the `client_id`/`client_secret` identifying
"Coreline" to Google) is **provisioned once by the maintainer**, never selected by
the operator. It resolves in this order (first hit wins):

1. `$CORELINE_GOOGLE_CLIENT_JSON` — path to a `client_secrets.json`.
2. `~/.config/coreline/google_client.json` — admin-placed file.
3. `EMBEDDED_CLIENT_CONFIG` in `auth.py` — for a packaged build.

> Per Google's documentation, the secret on a **desktop/installed-app** OAuth
> client is not treated as confidential — it identifies the app, not the user.
> The user's actual credential is the refresh token, which is operator-specific
> and Keychain-resident.

### 6.2 Scopes

```
https://www.googleapis.com/auth/drive              # read corporate folders + create docs
https://www.googleapis.com/auth/documents          # write the incident template
https://www.googleapis.com/auth/devstorage.read_write  # WORM bucket writes
```

Full `auth/drive` (not `drive.file`) is required because the incident folder
**pre-exists** and Coreline must read it by ID; `drive.file` only sees files the app
itself created and returns `404` on pre-existing folders.

### 6.3 Secret storage

| Secret | Store | Key |
|---|---|---|
| Google refresh token | macOS Keychain | `Coreline / google_refresh_token` |
| Slack bot token | macOS Keychain | `Coreline / slack_bot_token` |

The Slack bot token is the **only** secret the operator pastes. No secret is
ever written to `config.json`. The config file holds only: `operator_name`,
`operator_email`, `drive_folder_id`, `worm_bucket`, `slack_team_id`,
`setup_complete`.

### 6.4 Explicit non-goals (hard rules)

- **No** Chrome-cookie scraping.
- **No** reading of browser session/login databases.
- **No** OAuth tokens stored in project files or config.
- **No** service-account, dry-run, local, or team modes.

### 6.5 Threat-model notes

- *Token theft from Keychain* — mitigated by macOS Keychain ACLs; Coreline adds no
  weaker copy on disk. A revoked/rotated token surfaces as a friendly error with
  a **Reconnect Google** path.
- *Over-broad Drive scope* — accepted trade-off: Coreline acts as the operator, who
  already has access to the folder; the alternative scopes cannot both read a
  pre-existing folder and create docs in it.
- *Evidence tampering* — the manifest is written to a **bucket-locked (WORM)**
  bucket; `validate_bucket` confirms `storage.objects.create` up front and warns
  if absent, so evidence capture never silently no-ops.

---

## 7. Error handling

There is exactly one user-facing error path: **`friendly_error(exc)`**. It
inspects the exception type and returns a calm, actionable string for:

- Google `HttpError` — by status (`401` reconnect, `403` scope/permission,
  `404` not found, `429` rate limit), extracting the API's own reason text.
- `google.auth.exceptions.RefreshError` — session expired → reconnect.
- `slack_sdk` `SlackApiError` — mapped per Slack error code (`name_taken`,
  `missing_scope`, `invalid_auth`, `restricted_action`, …).
- `google.api_core` `Forbidden` / `NotFound` / generic call errors.
- `RuntimeError` (raised by `auth.py` with already-friendly text, e.g. "not
  provisioned").
- Network errors (`ConnectionError`, `TimeoutError`, DNS) → check connection.

Every network call in the UI is invoked through `App.run_async`, whose worker
catches **all** exceptions and routes them to the screen's `on_err` callback,
which renders `friendly_error(exc)`. A raw traceback cannot reach the operator.

---

## 8. Concurrency model

Tkinter is single-threaded and not thread-safe. Coreline enforces a strict rule:

- **All network/blocking work runs on a daemon worker thread** spawned by
  `App.run_async` (or, for multi-step declaration, a single dedicated worker).
- **All UI mutation happens back on the main thread**, marshalled via
  `App.ui_call(fn)` → `root.after(0, fn)`.

The result: the window never freezes during OAuth, validation, or a multi-step
declaration, and there are no cross-thread Tk calls.

---

## 9. Data & state

### 9.1 On-disk config — `~/.config/coreline/config.json` (non-secret)

```json
{
  "operator_name": "Jane Operator",
  "operator_email": "jane@example.com",
  "drive_folder_id": "1AbC…",
  "worm_bucket": "pantheon-incident-evidence",
  "slack_team_id": "T0123ABCD",
  "setup_complete": true
}
```

### 9.2 Keychain (service `Coreline`)

```
google_refresh_token   →  <opaque Google refresh token>
slack_bot_token        →  xoxb-…
```

### 9.3 Per-incident artifacts (created on Declare)

```
Google Doc   :  <Drive folder>/INC-YYYYMMDD-HHMMSS — <title>
Slack channel:  #inc-<date>-<slug>   (sanitized, ≤ 80 chars)
WORM object  :  gs://<bucket>/incidents/INC-…/manifest.json
```

Manifest schema:

```json
{
  "incident_id": "INC-20260625-143012",
  "title": "Suspicious Auth0 token reuse",
  "severity": "SEV2 — High",
  "summary": "…",
  "commander": "Jane Operator",
  "created_at": "2026-06-25T14:30:12+00:00",
  "google_doc": "https://docs.google.com/document/d/…",
  "slack_channel": "C0123ABCD"
}
```

---

## 10. Dependencies

```
google-auth-oauthlib      browser OAuth (InstalledAppFlow)
google-api-python-client  Drive + Docs APIs
google-cloud-storage      WORM bucket writes
slack-sdk                 Slack channel creation
keyring                   macOS Keychain access
customtkinter             modern UI (optional; native tkinter fallback)
```

Runtime: macOS, Python 3.x **with Tk** (CustomTkinter requires it; the native
fallback requires it too). The repository's virtualenv is built on a
Tk-enabled Python.

---

## 11. Extension points

The architecture isolates change behind narrow seams:

- **New incident artifact** (e.g. a Jira ticket, a PagerDuty incident) — add a
  method to `IncidentServices`, a toggle in the Declare form, and a step in the
  declaration worker. No other layer changes.
- **New auth provider scopes** — extend `SCOPES` in `auth.py` and re-run
  `reset_google_auth.py` so operators re-consent.
- **New secret** — add it through `CorelineStorage.set_secret/get_secret` and to the
  `clear_all` list; it will never leak to config by construction.
- **Packaging** — fill `EMBEDDED_CLIENT_CONFIG` and bundle with PyInstaller; the
  toolkit probe and Keychain access work unchanged in a frozen app.

---

## 12. Known limitations

- macOS-only secret storage (Keychain). Porting requires a `keyring`-supported
  backend on the target OS.
- The GCS client uses a placeholder project; **requester-pays** buckets (which
  need an explicit billing project) are not currently supported.
- Operator email from OAuth is best-effort (the configured scopes don't include
  `openid`/`email`); the email field in setup is the source of truth.
- Coreline creates artifacts; it does not yet track or update incident state after
  declaration.
