import os
import json
import keyring
from typing import Dict, Any, Optional

SERVICE_NAME = "Coreline"
CONFIG_PATH = os.path.expanduser("~/.config/coreline/config.json")

class CorelineStorage:
    @staticmethod
    def initialize_storage():
        """Ensures the local configuration directory exists."""
        os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
        if not os.path.exists(CONFIG_PATH):
            with open(CONFIG_PATH, 'w') as f:
                json.dump({}, f)

    @staticmethod
    def load_config() -> Dict[str, Any]:
        """Loads non-secret configuration variables."""
        CorelineStorage.initialize_storage()
        try:
            with open(CONFIG_PATH, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return {}

    @staticmethod
    def save_config(config_data: Dict[str, Any]) -> None:
        """Saves non-secret configuration variables."""
        CorelineStorage.initialize_storage()
        current_config = CorelineStorage.load_config()
        current_config.update(config_data)
        with open(CONFIG_PATH, 'w') as f:
            json.dump(current_config, f, indent=4)

    @staticmethod
    def set_secret(key: str, value: str) -> None:
        """Securely stores a secret token in the macOS Keychain."""
        if not value:
            return
        try:
            keyring.set_password(SERVICE_NAME, key, value)
        except keyring.errors.KeyringError as e:
            raise RuntimeError(f"macOS Keychain access failed: {str(e)}")

    @staticmethod
    def get_secret(key: str) -> Optional[str]:
        """Retrieves a secret token from the macOS Keychain."""
        try:
            return keyring.get_password(SERVICE_NAME, key)
        except keyring.errors.KeyringError:
            return None

    @staticmethod
    def clear_all() -> None:
        """Purges local config and Keychain secrets for testing/resetting."""
        if os.path.exists(CONFIG_PATH):
            os.remove(CONFIG_PATH)
        for secret_key in ["slack_bot_token", "google_refresh_token"]:
            try:
                keyring.delete_password(SERVICE_NAME, secret_key)
            except keyring.errors.PasswordDeleteError:
                pass
