#!/usr/bin/env python3
"""
Coreline — Google auth cache reset
==============================

Wipes the cached Google refresh token from the macOS Keychain so the next
launch forces a fresh browser sign-in. Use this after changing OAuth SCOPES
in auth.py: a token minted with the old (narrower) scope will never gain the
new scope on its own — it must be re-consented.

Usage
-----
    python reset_google_auth.py          # clear ONLY the Google token
                                          # (keeps client-secrets path + profile)
    python reset_google_auth.py --all     # nuke everything: config + all secrets
"""

import sys

import keyring
from storage import CorelineStorage, SERVICE_NAME


def clear_google_token() -> None:
    try:
        keyring.delete_password(SERVICE_NAME, "google_refresh_token")
        print("✓ Cleared 'google_refresh_token' from the Keychain.")
    except keyring.errors.PasswordDeleteError:
        print("• No cached Google token found — nothing to clear.")
    print("Next launch will open the browser for a fresh, full-scope sign-in.")
    print("Your operator profile, Drive folder and WORM bucket config are preserved.")


def clear_everything() -> None:
    CorelineStorage.clear_all()
    print("✓ Purged local config and ALL Coreline Keychain secrets.")
    print("Next launch starts the setup wizard from scratch.")


if __name__ == "__main__":
    if "--all" in sys.argv:
        clear_everything()
    else:
        clear_google_token()
