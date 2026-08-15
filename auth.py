"""
Coreline — Google authentication
============================

Single operator mode. Coreline is a companion client that signs the *operator* in
through their own Google/Okta identity in the system browser. There is no
service account and no per-operator client-JSON picker.

The application's OAuth *client* (a desktop client_id/secret — per Google's
docs the secret on an installed-app client is NOT confidential) is provisioned
ONCE by whoever packages Coreline, and resolved in this order (first hit wins):

    1. $CORELINE_GOOGLE_CLIENT_JSON   -> path to a client_secrets.json
    2. ~/.config/coreline/google_client.json
    3. EMBEDDED_CLIENT_CONFIG below (filled in for a packaged build)

The resulting refresh token is stored only in the macOS Keychain. On later
launches credentials are hydrated from the Keychain and refreshed silently.
"""

import json
import os
from typing import Optional

from google_auth_oauthlib.flow import InstalledAppFlow
from google.oauth2.credentials import Credentials

from storage import CorelineStorage

# Scopes: full Drive (read pre-existing corporate folders + create incident
# docs), Docs (write the incident template), and GCS read/write (WORM bucket).
SCOPES = [
    'https://www.googleapis.com/auth/drive',
    'https://www.googleapis.com/auth/documents',
    'https://www.googleapis.com/auth/devstorage.read_write',
]

# Provisioned once by the Coreline maintainer for a packaged build. Operators never
# see or select this. Leave client_id empty to force resolution from the env
# var or the admin-provisioned file instead.
EMBEDDED_CLIENT_CONFIG = {
    "installed": {
        "client_id": "",
        "client_secret": "",
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "redirect_uris": ["http://localhost"],
    }
}

ADMIN_CLIENT_PATH = os.path.expanduser("~/.config/coreline/google_client.json")

_NOT_PROVISIONED = (
    "Coreline isn't provisioned with a Google OAuth client yet. Ask your "
    "administrator to place the desktop client at "
    "~/.config/coreline/google_client.json (or set CORELINE_GOOGLE_CLIENT_JSON)."
)


class CorelineAuthManager:
    @staticmethod
    def _load_client_config() -> dict:
        """Resolve the bundled OAuth client config (never operator-supplied)."""
        env_path = os.environ.get("CORELINE_GOOGLE_CLIENT_JSON")
        if env_path and os.path.exists(env_path):
            with open(env_path, "r") as f:
                return json.load(f)
        if os.path.exists(ADMIN_CLIENT_PATH):
            with open(ADMIN_CLIENT_PATH, "r") as f:
                return json.load(f)
        if EMBEDDED_CLIENT_CONFIG.get("installed", {}).get("client_id"):
            return EMBEDDED_CLIENT_CONFIG
        raise RuntimeError(_NOT_PROVISIONED)

    @staticmethod
    def _client_installed() -> dict:
        cfg = CorelineAuthManager._load_client_config()
        return cfg.get("installed") or cfg.get("web") or {}

    @staticmethod
    def is_provisioned() -> bool:
        """True if an OAuth client is available without operator interaction."""
        try:
            return bool(CorelineAuthManager._client_installed().get("client_id"))
        except Exception:
            return False

    @staticmethod
    def run_oauth_flow() -> str:
        """
        Launch the desktop OAuth flow in the system browser. Okta/Google SSO is
        handled by the browser. Returns the operator's email (best-effort).
        """
        try:
            client_config = CorelineAuthManager._load_client_config()
            flow = InstalledAppFlow.from_client_config(client_config, scopes=SCOPES)
            # Local server on a random port intercepts the redirect.
            # access_type=offline + prompt=consent guarantee a refresh token,
            # even when re-authenticating after a scope change.
            credentials = flow.run_local_server(
                port=0,
                access_type="offline",
                prompt="consent",
                authorization_prompt_message=(
                    "Coreline: please complete sign-in in your browser."
                ),
            )

            if not (credentials and credentials.refresh_token):
                raise ValueError(
                    "No refresh token returned. Reset Coreline permissions in your "
                    "Google account and try again."
                )

            CorelineStorage.set_secret("google_refresh_token", credentials.refresh_token)

            # id_token may be a decoded dict, a raw JWT string, or absent --
            # email is best-effort and must never sink a successful auth.
            email = "Authenticated Operator"
            try:
                id_token = getattr(credentials, "id_token", None)
                if isinstance(id_token, dict):
                    email = id_token.get("email", email)
            except Exception:
                pass
            return email
        except RuntimeError:
            raise  # already an operator-friendly message (e.g. not provisioned)
        except Exception as e:
            raise RuntimeError(f"Google sign-in failed: {e}")

    @staticmethod
    def get_google_credentials() -> Optional[Credentials]:
        """Hydrate Google credentials from the Keychain token (silent refresh)."""
        refresh_token = CorelineStorage.get_secret("google_refresh_token")
        if not refresh_token:
            return None
        try:
            inst = CorelineAuthManager._client_installed()
            if not inst.get("client_id"):
                return None
            return Credentials(
                token=None,
                refresh_token=refresh_token,
                token_uri=inst.get("token_uri", "https://oauth2.googleapis.com/token"),
                client_id=inst.get("client_id"),
                client_secret=inst.get("client_secret"),
                scopes=SCOPES,
            )
        except Exception:
            return None
