"""Compatibility imports for the shared service credential resolver.

Legacy Jira keychain entries remain supported by services.shared.secrets.
"""
from services.shared.secrets import SecretLoadError, Secrets, initialize_secrets

KEYRING_SERVICE = "coreline-jira-webhook-listener"
WEBHOOK_SECRET_ENV = "JIRA_WEBHOOK_SECRET"
WEBHOOK_SECRET_KEYRING_KEY = "jira-webhook-secret"
SecretsProvider = Secrets
