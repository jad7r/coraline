#!/usr/bin/env python3
"""
Coreline — Incident Response Console
================================

A lightweight, single-operator macOS desktop client for declaring security
incidents. Coreline is a *companion* to the operator's own company identity: it
holds no service account. The operator signs in once through their normal
Google/Okta browser SSO; the refresh token lives only in the macOS Keychain.
A single "Declare Incident" action then:

    1. Creates a Google Doc incident record inside the designated Drive folder.
    2. Creates a dedicated Slack incident channel, seeded with the brief.
    3. Writes an immutable manifest to a GCP WORM (bucket-locked) bucket.

Security model
--------------
  * Browser SSO only — no Chrome-cookie scraping, no browser-session DBs.
  * Secrets (Google refresh token, Slack bot token) live in the macOS Keychain
    via ``keyring``; the local config file holds non-secret values only.
  * The OAuth *client* is provisioned once by the maintainer (see auth.py);
    operators never pick a client-secrets JSON.

Rendering
---------
CustomTkinter is preferred. If it (or a compatible Tk) is unavailable, Coreline
falls back to native ``tkinter`` with the same layout and behaviour.
"""

import json
import os
import re
import threading
import webbrowser
from datetime import datetime, timezone

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

# --------------------------------------------------------------------------- #
# Toolkit selection: CustomTkinter preferred, native tkinter as the fallback.
# We *probe* CustomTkinter (construct + render a throwaway root) because an
# import success does not guarantee runtime compatibility with the host's Tk.
# --------------------------------------------------------------------------- #
USING_CTK = False
ctk = None
try:
    import customtkinter as _ctk

    _probe = _ctk.CTk()
    _probe.update_idletasks()
    # CustomTkinter schedules a recurring DPI-scaling callback on the root.
    # Cancel any pending 'after' jobs before destroying the probe so no
    # orphaned callback fires into a torn-down interpreter (Tk stderr noise).
    try:
        for _aid in _probe.tk.eval("after info").split():
            try:
                _probe.after_cancel(_aid)
            except Exception:
                pass
    except Exception:
        pass
    _probe.destroy()
    ctk = _ctk
    USING_CTK = True
except Exception:
    USING_CTK = False
    ctk = None


# --------------------------------------------------------------------------- #
# Storage is required for the app to function at all. Fail loudly but cleanly.
# --------------------------------------------------------------------------- #
try:
    from storage import CorelineStorage
except Exception as _storage_exc:  # pragma: no cover - environment guard
    _root = tk.Tk()
    _root.withdraw()
    messagebox.showerror(
        "Coreline cannot start",
        "The local storage layer failed to load:\n\n"
        f"{_storage_exc}\n\n"
        "Confirm 'keyring' is installed (pip install -r requirements.txt) "
        "and that storage.py sits next to gui.py.",
    )
    raise SystemExit(1)


# --------------------------------------------------------------------------- #
# Palette & typography — a single dark enterprise theme used by both toolkits.
# --------------------------------------------------------------------------- #
P = {
    "bg": "#0E1116",
    "surface": "#171C24",
    "surface2": "#1F2630",
    "border": "#2A323D",
    "text": "#E6EAF0",
    "muted": "#8A94A6",
    "primary": "#3B82F6",
    "primary_hover": "#2F6FE0",
    "success": "#22C55E",
    "warn": "#F59E0B",
    "danger": "#EF4444",
    "danger_hover": "#C0392B",
    "link": "#60A5FA",
    "accent": "#E5484D",
}

_UI = "Helvetica Neue"
_MONO = "Menlo"
FONT = {
    "h1": (_UI, 26, "bold"),
    "h2": (_UI, 19, "bold"),
    "title": (_UI, 15, "bold"),
    "body": (_UI, 13),
    "small": (_UI, 11),
    "muted": (_UI, 12),
    "button": (_UI, 13, "bold"),
    "mono": (_MONO, 12),
}

SEVERITIES = [
    "SEV1 — Critical",
    "SEV2 — High",
    "SEV3 — Moderate",
    "SEV4 — Low",
]

DOC_MIME = "application/vnd.google-apps.document"
FOLDER_MIME = "application/vnd.google-apps.folder"

# A non-billing placeholder project for the GCS client. Coreline only performs
# bucket-scoped object operations (test_iam_permissions, object create) against
# an explicitly named bucket — none of which require a real project — so the
# operator is never asked for one.
GCS_CLIENT_PROJECT = "coreline-incident-companion"


# --------------------------------------------------------------------------- #
# Errors
# --------------------------------------------------------------------------- #
class CorelineError(Exception):
    """A user-facing error whose message is already operator-friendly."""


# --------------------------------------------------------------------------- #
# Input filtering & sanitisation (QA layer)
# --------------------------------------------------------------------------- #
def extract_drive_folder_id(raw: str) -> str:
    """Isolate a Drive folder ID from a pasted URL or a bare ID."""
    raw = (raw or "").strip()
    if not raw:
        raise CorelineError("Paste a Google Drive folder link or its ID first.")
    m = re.search(r"/folders/([A-Za-z0-9_-]+)", raw)
    if m:
        return m.group(1)
    m = re.search(r"[?&]id=([A-Za-z0-9_-]+)", raw)
    if m:
        return m.group(1)
    if re.fullmatch(r"[A-Za-z0-9_-]{12,}", raw):
        return raw
    raise CorelineError(
        "That doesn't look like a Drive folder. Paste the folder URL "
        "(it contains '/folders/...') or the raw folder ID."
    )


def extract_bucket_name(raw: str) -> str:
    """Isolate a GCS bucket name from gs://, a console URL, or a bare name."""
    raw = (raw or "").strip()
    if not raw:
        raise CorelineError("Enter a GCP bucket name or gs:// path first.")
    m = re.match(r"gs://([^/]+)", raw)
    if m:
        return m.group(1)
    m = re.search(r"storage/browser/([^/?#]+)", raw)
    if m:
        return m.group(1)
    # Otherwise treat the input as a bucket name and let the API validate it.
    return raw


def sanitize_channel(raw: str) -> str:
    """Coerce arbitrary text into a valid Slack channel name."""
    s = (raw or "").lower()
    s = re.sub(r"[^a-z0-9-]+", "-", s)
    s = re.sub(r"-{2,}", "-", s).strip("-")
    if not s:
        s = "incident"
    return s[:80]


# --------------------------------------------------------------------------- #
# Exception translation — the single funnel that keeps tracebacks off-screen.
# --------------------------------------------------------------------------- #
def friendly_error(exc: Exception) -> str:
    """Map any backend exception to a calm, actionable operator instruction."""
    # Google API (Drive / Docs)
    try:
        from googleapiclient.errors import HttpError

        if isinstance(exc, HttpError):
            status = getattr(getattr(exc, "resp", None), "status", None)
            reason = ""
            try:
                payload = json.loads(exc.content.decode("utf-8"))
                reason = payload.get("error", {}).get("message", "")
            except Exception:
                pass
            if status == 401:
                return ("Your Google sign-in has expired. Use 'Reconnect Google' "
                        "in Settings.")
            if status == 403:
                low = reason.lower()
                if "scope" in low or "insufficient" in low or "permission" in low:
                    return ("Google denied access: your account is missing the "
                            "required scope/permission for this folder or Doc. "
                            + (reason or ""))
                return f"Google refused the request (403). {reason}".strip()
            if status == 404:
                return ("Google couldn't find that resource (404). Re-check the "
                        "Drive folder link or ID.")
            if status == 429:
                return "Google rate-limited the request. Wait a few seconds and retry."
            return f"Google API error {status}. {reason}".strip()
    except Exception:
        pass

    # Google credential refresh
    try:
        from google.auth.exceptions import RefreshError

        if isinstance(exc, RefreshError):
            return ("Google could not refresh your session (token revoked or "
                    "expired). Use 'Reconnect Google' in Settings.")
    except Exception:
        pass

    # Slack
    try:
        from slack_sdk.errors import SlackApiError

        if isinstance(exc, SlackApiError):
            err = ""
            try:
                err = exc.response.get("error", "")
            except Exception:
                pass
            mapping = {
                "name_taken": "That Slack channel name is already taken. Pick another.",
                "invalid_name": "Invalid Slack channel name. Use lowercase letters, "
                                "numbers and hyphens.",
                "invalid_name_specials": "Slack channel name contains invalid characters.",
                "invalid_name_maxlength": "Slack channel name is too long (max 80).",
                "missing_scope": "The Slack token is missing scopes. It needs "
                                 "'channels:manage' and 'chat:write'.",
                "not_authed": "No Slack token was supplied.",
                "invalid_auth": "The Slack token is invalid or was revoked. Update it "
                                "in Settings.",
                "account_inactive": "The Slack bot account is deactivated.",
                "token_revoked": "The Slack token was revoked. Issue a new one and "
                                 "update it in Settings.",
                "restricted_action": "Workspace policy blocks the bot from creating "
                                     "channels. Ask a Slack admin to allow it.",
                "ratelimited": "Slack rate-limited the request. Wait a moment and retry.",
            }
            return mapping.get(err, f"Slack error: {err or exc}.")
    except Exception:
        pass

    # Google Cloud Storage (google-api-core)
    try:
        from google.api_core import exceptions as gexc

        if isinstance(exc, gexc.Forbidden):
            return ("GCP denied the write. The signed-in account lacks "
                    "'storage.objects.create' on this WORM bucket.")
        if isinstance(exc, gexc.NotFound):
            return ("GCP bucket not found. Re-check the bucket name in Settings.")
        if isinstance(exc, gexc.GoogleAPICallError):
            return f"GCP error: {getattr(exc, 'message', str(exc))}"
    except Exception:
        pass

    if isinstance(exc, FileNotFoundError):
        return ("A required file is missing or was moved. If this persists, ask "
                "your administrator to re-provision Coreline.")
    if isinstance(exc, CorelineError):
        return str(exc)
    if isinstance(exc, RuntimeError):
        # auth.py raises RuntimeError with already-friendly text.
        return str(exc)

    name = type(exc).__name__
    if name in ("ConnectionError", "TimeoutError", "OSError", "URLError",
                "gaierror", "ConnectionResetError"):
        return ("Network problem reaching the service. Check your connection (or "
                "VPN) and retry.")

    return f"Unexpected error: {exc}"


# --------------------------------------------------------------------------- #
# Backend orchestration — Drive, Docs, GCS WORM, Slack.
# Imported lazily so the window opens even on a partial dependency install.
# --------------------------------------------------------------------------- #
class IncidentServices:
    def __init__(self):
        self.config = CorelineStorage.load_config()
        self._creds = None

    # -- credential plumbing ------------------------------------------------ #
    def creds(self):
        if self._creds is not None:
            return self._creds
        from auth import CorelineAuthManager

        c = CorelineAuthManager.get_google_credentials()
        if not c:
            raise CorelineError(
                "Your Google account isn't connected. Use 'Sign in with Google'."
            )
        self._creds = c
        return c

    def _drive(self):
        from googleapiclient.discovery import build

        return build("drive", "v3", credentials=self.creds(), cache_discovery=False)

    def _docs(self):
        from googleapiclient.discovery import build

        return build("docs", "v1", credentials=self.creds(), cache_discovery=False)

    def _gcs(self):
        from google.cloud import storage as gcs

        return gcs.Client(project=GCS_CLIENT_PROJECT, credentials=self.creds())

    def _slack(self):
        from slack_sdk import WebClient

        token = CorelineStorage.get_secret("slack_bot_token")
        if not token:
            raise CorelineError("Slack bot token isn't set. Add it in Settings.")
        return WebClient(token=token)

    # -- validators --------------------------------------------------------- #
    def validate_drive_folder(self, folder_id: str) -> str:
        meta = (
            self._drive()
            .files()
            .get(fileId=folder_id, fields="id,name,mimeType", supportsAllDrives=True)
            .execute()
        )
        if meta.get("mimeType") != FOLDER_MIME:
            raise CorelineError(
                "That ID points to a file, not a folder. Paste the Drive *folder* link."
            )
        return meta.get("name", "(unnamed folder)")

    def validate_bucket(self, bucket_name: str) -> dict:
        client = self._gcs()
        bucket = client.bucket(bucket_name)
        granted = bucket.test_iam_permissions(
            ["storage.objects.create", "storage.objects.get"]
        )
        return {
            "create": "storage.objects.create" in granted,
            "read": "storage.objects.get" in granted,
        }

    def validate_slack(self, token: str) -> dict:
        from slack_sdk import WebClient

        r = WebClient(token=token).auth_test()
        return {
            "team": r.get("team"),
            "team_id": r.get("team_id"),
            "user": r.get("user"),
        }

    # -- incident operations ------------------------------------------------ #
    def create_doc(self, title: str, body_text: str) -> dict:
        folder = self.config.get("drive_folder_id")
        if not folder:
            raise CorelineError("No Drive incident folder is configured.")
        drive = self._drive()
        created = (
            drive.files()
            .create(
                body={"name": title, "mimeType": DOC_MIME, "parents": [folder]},
                fields="id,webViewLink",
                supportsAllDrives=True,
            )
            .execute()
        )
        doc_id = created["id"]
        self._docs().documents().batchUpdate(
            documentId=doc_id,
            body={"requests": [{"insertText": {"location": {"index": 1},
                                               "text": body_text}}]},
        ).execute()
        url = created.get("webViewLink") or f"https://docs.google.com/document/d/{doc_id}/edit"
        return {"id": doc_id, "url": url}

    def create_channel(self, name: str, topic: str, intro: str) -> dict:
        slack = self._slack()
        resp = slack.conversations_create(name=name, is_private=False)
        channel = resp["channel"]
        cid = channel["id"]
        if topic:
            try:
                slack.conversations_setTopic(channel=cid, topic=topic[:250])
            except Exception:
                pass  # topic is a nicety; never fail the channel on it
        if intro:
            try:
                slack.chat_postMessage(channel=cid, text=intro)
            except Exception:
                pass
        team_id = self.config.get("slack_team_id")
        url = f"https://app.slack.com/client/{team_id}/{cid}" if team_id else None
        return {"id": cid, "name": channel.get("name", name), "url": url}

    def write_manifest(self, incident_id: str, manifest: dict) -> dict:
        bucket_name = self.config.get("worm_bucket")
        if not bucket_name:
            raise CorelineError("No WORM bucket is configured.")
        bucket = self._gcs().bucket(bucket_name)
        path = f"incidents/{incident_id}/manifest.json"
        bucket.blob(path).upload_from_string(
            json.dumps(manifest, indent=2), content_type="application/json"
        )
        return {
            "uri": f"gs://{bucket_name}/{path}",
            "url": f"https://console.cloud.google.com/storage/browser/_details/{bucket_name}/{path}",
        }


def build_doc_template(incident_id, severity, title, summary, commander) -> str:
    created = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return (
        f"{incident_id} — {title}\n"
        f"{'=' * (len(incident_id) + len(title) + 3)}\n\n"
        f"Severity:   {severity}\n"
        f"Commander:  {commander or '(unassigned)'}\n"
        f"Declared:   {created}\n\n"
        "Summary\n-------\n"
        f"{summary or '(add the initial summary here)'}\n\n"
        "Timeline\n--------\n"
        f"- {created}  Incident declared via Coreline.\n\n"
        "Impact\n------\n(assess scope and affected systems)\n\n"
        "Actions Taken\n-------------\n(record containment / eradication / recovery)\n\n"
        "Indicators of Compromise\n------------------------\n(list IOCs as discovered)\n\n"
        "Follow-ups\n----------\n(owners + due dates)\n"
    )


# --------------------------------------------------------------------------- #
# Widget factories — one call site, two toolkits.
# --------------------------------------------------------------------------- #
def frame(parent, bg=None, radius=12, border=0):
    if USING_CTK:
        return ctk.CTkFrame(
            parent,
            fg_color=(bg or "transparent"),
            corner_radius=radius,
            border_width=border,
            border_color=P["border"],
        )
    return tk.Frame(
        parent,
        bg=(bg or P["bg"]),
        highlightthickness=border,
        highlightbackground=P["border"],
        bd=0,
    )


def card(parent):
    return frame(parent, bg=P["surface"], radius=14, border=1)


def label(parent, text, kind="body", color=None, bg=None,
          anchor="w", justify="left", wraplength=0):
    if USING_CTK:
        return ctk.CTkLabel(
            parent, text=text, font=FONT[kind], text_color=(color or P["text"]),
            anchor=anchor, justify=justify, wraplength=wraplength,
            fg_color="transparent",
        )
    return tk.Label(
        parent, text=text, font=FONT[kind], fg=(color or P["text"]),
        bg=(bg or P["surface"]), anchor=anchor, justify=justify,
        wraplength=wraplength,
    )


def button(parent, text, command, variant="primary", width=150, state="normal"):
    spec = {
        "primary": (P["primary"], P["primary_hover"], "#FFFFFF"),
        "secondary": (P["surface2"], P["border"], P["text"]),
        "ghost": (P["surface"], P["surface2"], P["muted"]),
        "danger": (P["danger"], P["danger_hover"], "#FFFFFF"),
    }[variant]
    if USING_CTK:
        b = ctk.CTkButton(
            parent, text=text, command=command, width=width, height=38,
            corner_radius=9, font=FONT["button"],
            fg_color=spec[0], hover_color=spec[1], text_color=spec[2],
        )
        b.configure(state=state)
        return b
    b = tk.Button(
        parent, text=text, command=command, font=FONT["button"],
        bg=spec[0], fg=spec[2], activebackground=spec[1], activeforeground=spec[2],
        relief="flat", bd=0, highlightthickness=0, padx=14, pady=8, cursor="hand2",
    )
    b.configure(state=state)
    return b


def entry(parent, textvariable, placeholder="", show="", width=280):
    if USING_CTK:
        return ctk.CTkEntry(
            parent, textvariable=textvariable, placeholder_text=placeholder,
            show=show, width=width, height=36, corner_radius=8, font=FONT["body"],
            fg_color=P["surface2"], border_color=P["border"], text_color=P["text"],
        )
    return tk.Entry(
        parent, textvariable=textvariable, show=show, font=FONT["body"],
        bg=P["surface2"], fg=P["text"], insertbackground=P["text"], relief="flat",
        highlightthickness=1, highlightbackground=P["border"],
        highlightcolor=P["primary"], width=max(12, int(width / 8)),
    )


def textbox(parent, height=6, readonly=False):
    t = tk.Text(
        parent, height=height, font=FONT["body"], bg=P["surface2"], fg=P["text"],
        insertbackground=P["text"], relief="flat", bd=0, highlightthickness=1,
        highlightbackground=P["border"], highlightcolor=P["primary"], wrap="word",
        padx=10, pady=8, selectbackground=P["primary"],
    )
    if readonly:
        t.configure(state="disabled")
    return t


def option_menu(parent, variable, values, width=220):
    if USING_CTK:
        return ctk.CTkOptionMenu(
            parent, variable=variable, values=values, width=width, height=36,
            corner_radius=8, font=FONT["body"], fg_color=P["surface2"],
            button_color=P["surface2"], button_hover_color=P["border"],
            text_color=P["text"], dropdown_fg_color=P["surface2"],
            dropdown_text_color=P["text"], dropdown_hover_color=P["border"],
        )
    m = tk.OptionMenu(parent, variable, *values)
    m.configure(
        font=FONT["body"], bg=P["surface2"], fg=P["text"],
        activebackground=P["border"], activeforeground=P["text"], relief="flat",
        highlightthickness=0, bd=0, width=max(14, int(width / 9)),
    )
    m["menu"].configure(bg=P["surface2"], fg=P["text"], activebackground=P["primary"])
    return m


def checkbox(parent, text, variable, bg=None):
    if USING_CTK:
        return ctk.CTkCheckBox(
            parent, text=text, variable=variable, onvalue=True, offvalue=False,
            font=FONT["body"], text_color=P["text"], fg_color=P["primary"],
            hover_color=P["primary_hover"], border_color=P["border"],
        )
    return tk.Checkbutton(
        parent, text=text, variable=variable, onvalue=True, offvalue=False,
        font=FONT["body"], fg=P["text"], bg=(bg or P["surface"]),
        selectcolor=P["surface2"], activebackground=(bg or P["surface"]),
        activeforeground=P["text"], anchor="w", highlightthickness=0, bd=0,
    )


class ScrollFrame:
    """A scrollable container; populate ``.body``."""

    def __init__(self, parent, bg=None):
        bg = bg or P["bg"]
        if USING_CTK:
            self.outer = ctk.CTkScrollableFrame(parent, fg_color=bg)
            self.body = self.outer
        else:
            self.outer = tk.Frame(parent, bg=bg)
            canvas = tk.Canvas(self.outer, bg=bg, highlightthickness=0, bd=0)
            vsb = tk.Scrollbar(self.outer, orient="vertical", command=canvas.yview)
            canvas.configure(yscrollcommand=vsb.set)
            vsb.pack(side="right", fill="y")
            canvas.pack(side="left", fill="both", expand=True)
            self.body = tk.Frame(canvas, bg=bg)
            win = canvas.create_window((0, 0), window=self.body, anchor="nw")
            self.body.bind(
                "<Configure>",
                lambda e: canvas.configure(scrollregion=canvas.bbox("all")),
            )
            canvas.bind("<Configure>", lambda e: canvas.itemconfig(win, width=e.width))

    def pack(self, **kw):
        self.outer.pack(**kw)
        return self

    def grid(self, **kw):
        self.outer.grid(**kw)
        return self


class TabView:
    def __init__(self, parent, names):
        self.frames = {}
        if USING_CTK:
            self.tv = ctk.CTkTabview(
                parent, fg_color=P["surface"], corner_radius=14,
                segmented_button_fg_color=P["surface2"],
                segmented_button_selected_color=P["primary"],
                segmented_button_selected_hover_color=P["primary_hover"],
                segmented_button_unselected_color=P["surface2"],
                segmented_button_unselected_hover_color=P["border"],
                text_color=P["text"],
            )
            for n in names:
                self.tv.add(n)
                self.frames[n] = self.tv.tab(n)
        else:
            style = ttk.Style()
            try:
                style.theme_use("clam")
            except tk.TclError:
                pass
            style.configure("TNotebook", background=P["bg"], borderwidth=0)
            style.configure(
                "TNotebook.Tab", background=P["surface2"], foreground=P["text"],
                padding=(16, 8), font=FONT["button"],
            )
            style.map("TNotebook.Tab", background=[("selected", P["primary"])],
                      foreground=[("selected", "#FFFFFF")])
            self.tv = ttk.Notebook(parent)
            for n in names:
                f = tk.Frame(self.tv, bg=P["bg"])
                self.frames[n] = f
                self.tv.add(f, text=f"  {n}  ")

    def widget(self):
        return self.tv

    def frame(self, name):
        return self.frames[name]


class ActivityLog:
    """Read-only, append-only log with clickable links."""

    def __init__(self, parent):
        self.text = textbox(parent, height=16, readonly=True)
        self.text.tag_config("muted", foreground=P["muted"])
        self.text.tag_config("ok", foreground=P["success"])
        self.text.tag_config("warn", foreground=P["warn"])
        self.text.tag_config("err", foreground=P["danger"])
        self.text.tag_config("head", foreground=P["text"], font=FONT["title"])
        self._n = 0

    def widget(self):
        return self.text

    def _emit(self, s, tag=None):
        self.text.configure(state="normal")
        self.text.insert("end", s, tag or ())
        self.text.configure(state="disabled")
        self.text.see("end")

    def line(self, s="", tag=None):
        self._emit(s + "\n", tag)

    def link(self, label_text, url):
        self.text.configure(state="normal")
        tag = f"link{self._n}"
        self._n += 1
        self.text.tag_config(tag, foreground=P["link"], underline=True)
        self.text.tag_bind(tag, "<Button-1>", lambda e, u=url: webbrowser.open(u))
        self.text.tag_bind(tag, "<Enter>", lambda e: self.text.configure(cursor="hand2"))
        self.text.tag_bind(tag, "<Leave>", lambda e: self.text.configure(cursor=""))
        self.text.insert("end", label_text + "\n", tag)
        self.text.configure(state="disabled")
        self.text.see("end")

    def clear(self):
        self.text.configure(state="normal")
        self.text.delete("1.0", "end")
        self.text.configure(state="disabled")


# --------------------------------------------------------------------------- #
# Application controller
# --------------------------------------------------------------------------- #
class App:
    def __init__(self, root):
        self.root = root
        self.container = frame(root, bg=P["bg"])
        self.container.pack(fill="both", expand=True)
        self.show_start()

    def ui_call(self, fn):
        """Marshal a callback back onto the Tk main thread."""
        self.root.after(0, fn)

    def run_async(self, work, on_ok, on_err):
        """Run blocking work off the UI thread; deliver results on it."""
        def worker():
            try:
                result = work()
            except Exception as exc:  # noqa: BLE001 - funnelled to friendly_error
                self.ui_call(lambda e=exc: on_err(e))
                return
            self.ui_call(lambda r=result: on_ok(r))

        threading.Thread(target=worker, daemon=True).start()

    def _clear(self):
        for w in self.container.winfo_children():
            w.destroy()

    def show_start(self):
        self._clear()
        cfg = CorelineStorage.load_config()
        if cfg.get("setup_complete"):
            MainView(self.container, self)
        else:
            SetupScreen(self.container, self)


# --------------------------------------------------------------------------- #
# Setup screen — one screen, five fields, locks the app until complete.
# --------------------------------------------------------------------------- #
class SetupScreen:
    def __init__(self, parent, app: App):
        self.app = app
        self.parent = parent
        cfg = CorelineStorage.load_config()
        self.state = {
            "google_connected": bool(CorelineStorage.get_secret("google_refresh_token")),
            "slack_connected": bool(CorelineStorage.get_secret("slack_bot_token")),
            "drive_ok": False,
            "bucket_ok": False,
        }
        self.var_name = tk.StringVar(value=cfg.get("operator_name", ""))
        self.var_email = tk.StringVar(value=cfg.get("operator_email", ""))
        self.var_drive = tk.StringVar(value=cfg.get("drive_folder_id", ""))
        self.var_bucket = tk.StringVar(value=cfg.get("worm_bucket", ""))
        self.var_slack = tk.StringVar(value="")
        self._build()

    def _build(self):
        outer = frame(self.parent, bg=P["bg"])
        outer.pack(fill="both", expand=True, padx=28, pady=22)

        header = frame(outer, bg=P["bg"])
        header.pack(fill="x")
        label(header, "Coreline", kind="h1", color=P["accent"], bg=P["bg"]).pack(side="left")
        label(header, "  Setup", kind="h2", color=P["muted"], bg=P["bg"]).pack(
            side="left", pady=(6, 0))
        label(outer,
              "Configure Coreline once. Secrets are stored in the macOS Keychain — "
              "never in config files.",
              kind="body", color=P["muted"], bg=P["bg"]).pack(anchor="w", pady=(4, 12))

        cardf = card(outer)
        cardf.pack(fill="both", expand=True)
        scroll = ScrollFrame(cardf, bg=P["surface"])
        scroll.pack(fill="both", expand=True, padx=4, pady=4)
        b = scroll.body

        # Operator
        self._heading(b, "Operator")
        self.var_name.trace_add("write", lambda *_: self._refresh_finish())
        self._row_field(b, "Operator name", self.var_name, placeholder="Jane Operator")
        self._row_field(b, "Operator email", self.var_email,
                        placeholder="jane@example.com")

        # Google
        self._heading(b, "Google identity")
        label(b, "Sign in through your browser (Google/Okta SSO). No password is "
                 "stored — only a Keychain refresh token.",
              kind="body", color=P["muted"], bg=P["surface"], wraplength=620).pack(
            anchor="w", padx=22, pady=(0, 8))
        grow = frame(b, bg=P["surface"])
        grow.pack(anchor="w", fill="x", padx=22)
        self.btn_google = button(grow, "Sign in with Google", self._sign_in_google,
                                 variant="primary", width=210)
        self.btn_google.pack(side="left")
        self.lbl_google = label(b, "", kind="title", bg=P["surface"], wraplength=620)
        self.lbl_google.pack(anchor="w", padx=22, pady=(8, 4))
        self._set_conn(self.lbl_google, self.state["google_connected"],
                       "Signed in ✓", "Not signed in")

        # Drive
        self._heading(b, "Drive incident folder")
        self.lbl_drive = self._row_field_action(
            b, "Google Drive folder URL or ID", self.var_drive,
            "Validate Drive Folder", self._validate_drive,
            placeholder="https://drive.google.com/drive/folders/…")

        # WORM bucket
        self._heading(b, "WORM evidence bucket")
        self.lbl_bucket = self._row_field_action(
            b, "GCP WORM bucket name", self.var_bucket,
            "Validate WORM Bucket", self._validate_bucket,
            placeholder="gs://pantheon-incident-evidence")

        # Slack
        self._heading(b, "Slack workspace")
        self.lbl_slack = self._row_field_action(
            b, "Slack bot token (xoxb-…)", self.var_slack,
            "Save Slack Token and Test", self._save_slack, show="•",
            preset=self.state["slack_connected"])

        # Footer
        nav = frame(outer, bg=P["bg"])
        nav.pack(fill="x", pady=(14, 0))
        self.status = label(nav, "", kind="small", color=P["muted"], bg=P["bg"])
        self.status.pack(side="left")
        self.btn_finish = button(nav, "Finish Setup", self._finish,
                                 variant="primary", width=180)
        self.btn_finish.pack(side="right")
        self._refresh_finish()

    # -- layout helpers ----------------------------------------------------- #
    def _heading(self, parent, text):
        label(parent, text, kind="h2", bg=P["surface"]).pack(
            anchor="w", padx=22, pady=(18, 6))

    def _row_field(self, parent, caption, var, placeholder="", show=""):
        label(parent, caption, kind="title", bg=P["surface"]).pack(
            anchor="w", padx=22, pady=(6, 4))
        entry(parent, var, width=560, placeholder=placeholder, show=show).pack(
            anchor="w", padx=22, fill="x")

    def _row_field_action(self, parent, caption, var, btn_text, command,
                          placeholder="", show="", preset=False):
        label(parent, caption, kind="title", bg=P["surface"]).pack(
            anchor="w", padx=22, pady=(6, 4))
        row = frame(parent, bg=P["surface"])
        row.pack(anchor="w", fill="x", padx=22)
        entry(row, var, width=380, placeholder=placeholder, show=show).pack(
            side="left", fill="x", expand=True)
        button(row, btn_text, command, variant="secondary", width=220).pack(
            side="left", padx=(10, 0))
        status = label(parent, "", kind="body", color=P["muted"], bg=P["surface"],
                       wraplength=620)
        status.pack(anchor="w", padx=22, pady=(6, 2))
        if preset:
            status.configure(text="Saved ✓")
            self._tint(status, P["success"])
        return status

    # -- actions ------------------------------------------------------------ #
    def _sign_in_google(self):
        self.btn_google.configure(state="disabled")
        self._set_status("Opening browser for Google/Okta sign-in…")

        def work():
            from auth import CorelineAuthManager
            return CorelineAuthManager.run_oauth_flow()

        def ok(email):
            self.state["google_connected"] = True
            if email and "@" in email and not self.var_email.get().strip():
                self.var_email.set(email)
            self.lbl_google.configure(text="Signed in ✓")
            self._tint(self.lbl_google, P["success"])
            self._set_status("Google connected.", P["success"])
            self.btn_google.configure(state="normal")
            self._refresh_finish()

        def err(exc):
            self.btn_google.configure(state="normal")
            self._set_status(friendly_error(exc), P["danger"])

        self.app.run_async(work, ok, err)

    def _validate_drive(self):
        try:
            folder_id = extract_drive_folder_id(self.var_drive.get())
        except CorelineError as e:
            self._tint(self.lbl_drive, P["danger"], str(e))
            return
        self._tint(self.lbl_drive, P["muted"], "Checking folder access…")
        svc = IncidentServices()

        def ok(name):
            self.state["drive_ok"] = True
            CorelineStorage.save_config({"drive_folder_id": folder_id})
            self._tint(self.lbl_drive, P["success"], f"✓ {name}")
            self._refresh_finish()

        def err(exc):
            self.state["drive_ok"] = False
            self._tint(self.lbl_drive, P["danger"], friendly_error(exc))
            self._refresh_finish()

        self.app.run_async(lambda: svc.validate_drive_folder(folder_id), ok, err)

    def _validate_bucket(self):
        try:
            bucket = extract_bucket_name(self.var_bucket.get())
        except CorelineError as e:
            self._tint(self.lbl_bucket, P["danger"], str(e))
            return
        CorelineStorage.save_config({"worm_bucket": bucket})
        self._tint(self.lbl_bucket, P["muted"], "Testing bucket permissions…")
        svc = IncidentServices()

        def ok(perms):
            if perms["create"]:
                self.state["bucket_ok"] = True
                self._tint(self.lbl_bucket, P["success"],
                           f"✓ {bucket}: write confirmed (storage.objects.create).")
            else:
                self.state["bucket_ok"] = False
                self._tint(self.lbl_bucket, P["warn"],
                           f"⚠ {bucket}: your account lacks 'storage.objects.create'. "
                           "Ask GCP IAM to grant Storage Object Creator.")
            self._refresh_finish()

        def err(exc):
            self.state["bucket_ok"] = False
            self._tint(self.lbl_bucket, P["danger"], friendly_error(exc))
            self._refresh_finish()

        self.app.run_async(lambda: svc.validate_bucket(bucket), ok, err)

    def _save_slack(self):
        token = self.var_slack.get().strip()
        if not token:
            self._tint(self.lbl_slack, P["warn"], "Enter a Slack bot token first.")
            return
        self._tint(self.lbl_slack, P["muted"], "Verifying Slack token…")
        svc = IncidentServices()

        def ok(info):
            CorelineStorage.set_secret("slack_bot_token", token)
            CorelineStorage.save_config({"slack_team_id": info.get("team_id", "")})
            self.state["slack_connected"] = True
            self._tint(self.lbl_slack, P["success"],
                       f"✓ {info.get('team', '')} (as {info.get('user', 'bot')})")
            self._refresh_finish()

        def err(exc):
            self._tint(self.lbl_slack, P["danger"], friendly_error(exc))

        self.app.run_async(lambda: svc.validate_slack(token), ok, err)

    def _can_finish(self):
        return (bool(self.var_name.get().strip())
                and self.state["google_connected"]
                and self.state["drive_ok"]
                and self.state["bucket_ok"]
                and self.state["slack_connected"])

    def _refresh_finish(self):
        self.btn_finish.configure(state=("normal" if self._can_finish() else "disabled"))

    def _finish(self):
        CorelineStorage.save_config({
            "operator_name": self.var_name.get().strip(),
            "operator_email": self.var_email.get().strip(),
            "setup_complete": True,
        })
        self.app.show_start()

    # -- helpers ------------------------------------------------------------ #
    def _set_status(self, text, color=None):
        try:
            if USING_CTK:
                self.status.configure(text=text, text_color=color or P["muted"])
            else:
                self.status.configure(text=text, fg=color or P["muted"])
        except Exception:
            self.status.configure(text=text)

    def _set_conn(self, lbl, connected, yes, no):
        lbl.configure(text=(yes if connected else no))
        self._tint(lbl, P["success"] if connected else P["muted"])

    def _tint(self, widget, color, text=None):
        try:
            if text is not None:
                widget.configure(text=text)
            if USING_CTK:
                widget.configure(text_color=color)
            else:
                widget.configure(fg=color)
        except Exception:
            pass


# --------------------------------------------------------------------------- #
# Main view — Declare Incident + Settings
# --------------------------------------------------------------------------- #
class MainView:
    def __init__(self, parent, app: App):
        self.app = app
        self.parent = parent
        self.cfg = CorelineStorage.load_config()
        self._build()

    def _build(self):
        outer = frame(self.parent, bg=P["bg"])
        outer.pack(fill="both", expand=True, padx=22, pady=18)

        header = frame(outer, bg=P["bg"])
        header.pack(fill="x", pady=(0, 14))
        label(header, "Coreline", kind="h1", color=P["accent"], bg=P["bg"]).pack(side="left")
        label(header, "  Incident Response Console", kind="h2", color=P["muted"],
              bg=P["bg"]).pack(side="left", pady=(6, 0))
        who = self.cfg.get("operator_name", "operator")
        label(header, f"● {who}", kind="title", color=P["success"],
              bg=P["bg"]).pack(side="right", pady=(8, 0))

        self.tabs = TabView(outer, ["Declare Incident", "Settings"])
        self.tabs.widget().pack(fill="both", expand=True)
        self._build_declare(self.tabs.frame("Declare Incident"))
        self._build_settings(self.tabs.frame("Settings"))

    # -- declare ------------------------------------------------------------ #
    def _build_declare(self, parent):
        grid = frame(parent, bg=P["surface"])
        grid.pack(fill="both", expand=True, padx=14, pady=14)
        grid.columnconfigure(0, weight=1, uniform="col")
        grid.columnconfigure(1, weight=1, uniform="col")
        grid.rowconfigure(0, weight=1)

        # Left: form
        form = card(grid)
        form.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        label(form, "Declare a new incident", kind="h2", bg=P["surface"]).pack(
            anchor="w", padx=18, pady=(16, 10))

        self.var_title = tk.StringVar()
        self.var_sev = tk.StringVar(value=SEVERITIES[1])
        stamp = datetime.now().strftime("%Y%m%d-%H%M")
        self.var_chan = tk.StringVar(value=f"inc-{stamp}")
        self.var_doc = tk.BooleanVar(value=True)
        self.var_chan_en = tk.BooleanVar(value=bool(CorelineStorage.get_secret("slack_bot_token")))
        self.var_worm = tk.BooleanVar(value=True)

        label(form, "Incident title", kind="title", bg=P["surface"]).pack(
            anchor="w", padx=18, pady=(6, 4))
        entry(form, self.var_title, placeholder="Suspicious Auth0 token reuse",
              width=420).pack(anchor="w", padx=18, fill="x")

        label(form, "Severity", kind="title", bg=P["surface"]).pack(
            anchor="w", padx=18, pady=(12, 4))
        option_menu(form, self.var_sev, SEVERITIES).pack(anchor="w", padx=18)

        label(form, "Initial summary", kind="title", bg=P["surface"]).pack(
            anchor="w", padx=18, pady=(12, 4))
        self.txt_summary = textbox(form, height=5)
        self.txt_summary.pack(anchor="w", padx=18, fill="x")

        label(form, "Slack channel name", kind="title", bg=P["surface"]).pack(
            anchor="w", padx=18, pady=(12, 4))
        entry(form, self.var_chan, width=420).pack(anchor="w", padx=18, fill="x")

        opts = frame(form, bg=P["surface"])
        opts.pack(anchor="w", padx=18, pady=(14, 6), fill="x")
        checkbox(opts, "Create Google Doc", self.var_doc).pack(anchor="w", pady=2)
        checkbox(opts, "Create Slack channel", self.var_chan_en).pack(anchor="w", pady=2)
        checkbox(opts, "Write WORM evidence manifest", self.var_worm).pack(
            anchor="w", pady=2)

        self.btn_declare = button(form, "Declare Incident", self._declare,
                                  variant="primary", width=200)
        self.btn_declare.pack(anchor="w", padx=18, pady=(16, 18))

        # Right: activity log
        right = card(grid)
        right.grid(row=0, column=1, sticky="nsew", padx=(8, 0))
        label(right, "Activity", kind="h2", bg=P["surface"]).pack(
            anchor="w", padx=18, pady=(16, 10))
        self.log = ActivityLog(right)
        self.log.widget().pack(fill="both", expand=True, padx=18, pady=(0, 18))
        self.log.line("Ready. Fill the form and declare an incident.", "muted")

    def _declare(self):
        title = self.var_title.get().strip()
        if not title:
            self.log.line("Incident title is required.", "err")
            return
        sev = self.var_sev.get()
        summary = self.txt_summary.get("1.0", "end-1c").strip()
        channel = sanitize_channel(self.var_chan.get() or f"inc-{title}")
        do_doc = bool(self.var_doc.get())
        do_chan = bool(self.var_chan_en.get())
        do_worm = bool(self.var_worm.get())
        incident_id = "INC-" + datetime.now().strftime("%Y%m%d-%H%M%S")
        commander = self.cfg.get("operator_name", "")

        self.btn_declare.configure(state="disabled")
        self.log.clear()
        self.log.line(incident_id, "head")
        self.log.line(f"{sev} · {title}", "muted")
        self.log.line("")

        svc = IncidentServices()
        results = {"doc": None, "chan": None, "worm": None}

        def info(msg):
            self.app.ui_call(lambda: self.log.line(msg, "muted"))

        def good(msg, url=None):
            def f():
                self.log.line("  ✓ " + msg, "ok")
                if url:
                    self.log.link("    " + url, url)
            self.app.ui_call(f)

        def bad(msg):
            self.app.ui_call(lambda: self.log.line("  ✗ " + msg, "err"))

        def worker():
            if do_doc:
                info("Creating incident Google Doc…")
                try:
                    body = build_doc_template(incident_id, sev, title, summary, commander)
                    r = svc.create_doc(f"{incident_id} — {title}", body)
                    results["doc"] = r
                    good("Google Doc created in incident folder", r["url"])
                except Exception as e:  # noqa: BLE001
                    bad(friendly_error(e))

            if do_chan:
                info(f"Creating Slack channel #{channel}…")
                try:
                    intro = (f":rotating_light: *{incident_id}* — {title}\n"
                             f"Severity: {sev}\nCommander: {commander or '(unassigned)'}")
                    if results["doc"]:
                        intro += f"\nIncident doc: {results['doc']['url']}"
                    if summary:
                        intro += f"\n\n{summary}"
                    r = svc.create_channel(channel, f"{incident_id} {title}", intro)
                    results["chan"] = r
                    good(f"Slack channel #{r['name']} created", r.get("url"))
                except Exception as e:  # noqa: BLE001
                    bad(friendly_error(e))

            if do_worm:
                info("Writing immutable manifest to WORM bucket…")
                try:
                    manifest = {
                        "incident_id": incident_id,
                        "title": title,
                        "severity": sev,
                        "summary": summary,
                        "commander": commander,
                        "created_at": datetime.now(timezone.utc).isoformat(),
                        "google_doc": results["doc"]["url"] if results["doc"] else None,
                        "slack_channel": results["chan"]["id"] if results["chan"] else None,
                    }
                    r = svc.write_manifest(incident_id, manifest)
                    results["worm"] = r
                    good("WORM manifest written", r["url"])
                except Exception as e:  # noqa: BLE001
                    bad(friendly_error(e))

            def done():
                self.log.line("")
                any_ok = any(results.values())
                self.log.line(
                    "Declaration complete." if any_ok else "Nothing was created.",
                    "head" if any_ok else "warn",
                )
                self.btn_declare.configure(state="normal")

            self.app.ui_call(done)

        threading.Thread(target=worker, daemon=True).start()

    # -- settings ----------------------------------------------------------- #
    def _build_settings(self, parent):
        scroll = ScrollFrame(parent, bg=P["bg"])
        scroll.pack(fill="both", expand=True, padx=8, pady=8)
        body = scroll.body

        # Operator profile
        c1 = card(body)
        c1.pack(fill="x", pady=(4, 10))
        label(c1, "Operator profile", kind="h2", bg=P["surface"]).pack(
            anchor="w", padx=18, pady=(14, 8))
        self.s_name = tk.StringVar(value=self.cfg.get("operator_name", ""))
        self.s_email = tk.StringVar(value=self.cfg.get("operator_email", ""))
        self._settings_field(c1, "Name", self.s_name)
        self._settings_field(c1, "Email", self.s_email)
        button(c1, "Save profile", self._save_profile, variant="secondary",
               width=160).pack(anchor="w", padx=18, pady=(10, 16))

        # Google + Drive
        c2 = card(body)
        c2.pack(fill="x", pady=10)
        label(c2, "Google & Drive", kind="h2", bg=P["surface"]).pack(
            anchor="w", padx=18, pady=(14, 8))
        connected = bool(CorelineStorage.get_secret("google_refresh_token"))
        label(c2, "Signed in ✓" if connected else "Not signed in", kind="title",
              color=P["success"] if connected else P["muted"], bg=P["surface"]).pack(
            anchor="w", padx=18)
        button(c2, "Reconnect Google", self._reconnect_google, variant="secondary",
               width=190).pack(anchor="w", padx=18, pady=(10, 10))
        self.s_drive = tk.StringVar(value=self.cfg.get("drive_folder_id", ""))
        self._settings_field(c2, "Drive folder URL or ID", self.s_drive)
        self.s_drive_status = label(c2, "", kind="body", color=P["muted"],
                                    bg=P["surface"], wraplength=620)
        self.s_drive_status.pack(anchor="w", padx=18, pady=(4, 0))
        button(c2, "Validate & save folder", self._save_drive, variant="secondary",
               width=200).pack(anchor="w", padx=18, pady=(10, 16))

        # GCP
        c3 = card(body)
        c3.pack(fill="x", pady=10)
        label(c3, "GCP WORM evidence", kind="h2", bg=P["surface"]).pack(
            anchor="w", padx=18, pady=(14, 8))
        self.s_bucket = tk.StringVar(value=self.cfg.get("worm_bucket", ""))
        self._settings_field(c3, "WORM bucket name", self.s_bucket)
        self.s_bucket_status = label(c3, "", kind="body", color=P["muted"],
                                     bg=P["surface"], wraplength=620)
        self.s_bucket_status.pack(anchor="w", padx=18, pady=(4, 0))
        button(c3, "Check & save bucket", self._save_bucket, variant="secondary",
               width=190).pack(anchor="w", padx=18, pady=(10, 16))

        # Slack
        c4 = card(body)
        c4.pack(fill="x", pady=10)
        label(c4, "Slack", kind="h2", bg=P["surface"]).pack(
            anchor="w", padx=18, pady=(14, 8))
        slack_ok = bool(CorelineStorage.get_secret("slack_bot_token"))
        label(c4, "Connected ✓" if slack_ok else "Not connected", kind="title",
              color=P["success"] if slack_ok else P["muted"], bg=P["surface"]).pack(
            anchor="w", padx=18)
        self.s_slack = tk.StringVar(value="")
        self._settings_field(c4, "New bot token (xoxb-…)", self.s_slack, show="•")
        self.s_slack_status = label(c4, "", kind="body", color=P["muted"],
                                    bg=P["surface"], wraplength=620)
        self.s_slack_status.pack(anchor="w", padx=18, pady=(4, 0))
        button(c4, "Save Slack Token and Test", self._save_slack, variant="secondary",
               width=220).pack(anchor="w", padx=18, pady=(10, 16))

        # Danger zone
        c5 = card(body)
        c5.pack(fill="x", pady=(10, 6))
        label(c5, "Danger zone", kind="h2", color=P["danger"], bg=P["surface"]).pack(
            anchor="w", padx=18, pady=(14, 6))
        label(c5, "Purge local config and all Keychain secrets, then return to setup.",
              kind="body", color=P["muted"], bg=P["surface"], wraplength=620).pack(
            anchor="w", padx=18, pady=(0, 10))
        button(c5, "Reset Coreline", self._reset, variant="danger", width=160).pack(
            anchor="w", padx=18, pady=(0, 16))

    def _settings_field(self, parent, caption, var, show=""):
        label(parent, caption, kind="title", bg=P["surface"]).pack(
            anchor="w", padx=18, pady=(8, 4))
        entry(parent, var, width=520, show=show).pack(anchor="w", padx=18, fill="x")

    def _save_profile(self):
        CorelineStorage.save_config({
            "operator_name": self.s_name.get().strip(),
            "operator_email": self.s_email.get().strip(),
        })
        self.cfg = CorelineStorage.load_config()
        messagebox.showinfo("Coreline", "Profile saved.")

    def _reconnect_google(self):
        def work():
            from auth import CorelineAuthManager
            return CorelineAuthManager.run_oauth_flow()

        self.app.run_async(
            work,
            lambda email: messagebox.showinfo("Coreline", "Google reconnected."),
            lambda exc: messagebox.showerror("Coreline", friendly_error(exc)),
        )

    def _save_drive(self):
        try:
            folder_id = extract_drive_folder_id(self.s_drive.get())
        except CorelineError as e:
            self._tint(self.s_drive_status, P["danger"], str(e))
            return
        self._tint(self.s_drive_status, P["muted"], "Checking…")
        svc = IncidentServices()

        def ok(name):
            CorelineStorage.save_config({"drive_folder_id": folder_id})
            self.cfg = CorelineStorage.load_config()
            self._tint(self.s_drive_status, P["success"], f"✓ {name}")

        self.app.run_async(
            lambda: svc.validate_drive_folder(folder_id), ok,
            lambda exc: self._tint(self.s_drive_status, P["danger"], friendly_error(exc)),
        )

    def _save_bucket(self):
        try:
            bucket = extract_bucket_name(self.s_bucket.get())
        except CorelineError as e:
            self._tint(self.s_bucket_status, P["danger"], str(e))
            return
        CorelineStorage.save_config({"worm_bucket": bucket})
        self.cfg = CorelineStorage.load_config()
        self._tint(self.s_bucket_status, P["muted"], "Checking permissions…")
        svc = IncidentServices()

        def ok(perms):
            if perms["create"]:
                self._tint(self.s_bucket_status, P["success"],
                           f"✓ {bucket}: write confirmed.")
            else:
                self._tint(self.s_bucket_status, P["warn"],
                           f"⚠ {bucket}: missing storage.objects.create.")

        self.app.run_async(
            lambda: svc.validate_bucket(bucket), ok,
            lambda exc: self._tint(self.s_bucket_status, P["danger"], friendly_error(exc)),
        )

    def _save_slack(self):
        token = self.s_slack.get().strip()
        if not token:
            self._tint(self.s_slack_status, P["warn"], "Enter a token first.")
            return
        self._tint(self.s_slack_status, P["muted"], "Verifying…")
        svc = IncidentServices()

        def ok(info):
            CorelineStorage.set_secret("slack_bot_token", token)
            CorelineStorage.save_config({"slack_team_id": info.get("team_id", "")})
            self.cfg = CorelineStorage.load_config()
            self._tint(self.s_slack_status, P["success"],
                       f"✓ {info.get('team', '')} (as {info.get('user', 'bot')})")

        self.app.run_async(
            lambda: svc.validate_slack(token), ok,
            lambda exc: self._tint(self.s_slack_status, P["danger"], friendly_error(exc)),
        )

    def _reset(self):
        if not messagebox.askyesno(
            "Reset Coreline",
            "This purges local config and all Coreline Keychain secrets. Continue?",
        ):
            return
        CorelineStorage.clear_all()
        self.app.show_start()

    def _tint(self, widget, color, text=None):
        try:
            if text is not None:
                widget.configure(text=text)
            if USING_CTK:
                widget.configure(text_color=color)
            else:
                widget.configure(fg=color)
        except Exception:
            pass


# --------------------------------------------------------------------------- #
# Bootstrap
# --------------------------------------------------------------------------- #
def make_root():
    if USING_CTK:
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        root = ctk.CTk()
        root.configure(fg_color=P["bg"])
    else:
        root = tk.Tk()
        root.configure(bg=P["bg"])
    root.title("Coreline — Incident Response Console")
    root.geometry("1080x820")
    root.minsize(980, 720)
    return root


def main():
    CorelineStorage.initialize_storage()
    root = make_root()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
