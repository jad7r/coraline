terraform {
  required_version = ">= 1.5"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
  # Recommended: configure a remote backend (GCS) so state (which records the locked
  # retention policy) is durable and shared. Left unconfigured here — set per environment.
  # backend "gcs" { bucket = "coreline-audit-tfstate" prefix = "coreline/gcs-evidence" }
}

provider "google" {
  project = var.project_id
  # Credentials come from ambient ADC / Workload Identity — no key file.
}
