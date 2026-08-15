variable "project_id" {
  description = "GCP project (where Google SecOps+ runs). This is the PROJECT, not a bucket."
  type        = string
  default     = "coreline-audit"
}

variable "location" {
  description = "Bucket location/region (pick per data-residency + SecOps region)."
  type        = string
  default     = "US-EAST1"
}

variable "evidence_bucket" {
  description = "Production WORM evidence bucket (globally-unique, lowercase)."
  type        = string
  default     = "coreline-audit-ir-evidence"
}

variable "staging_bucket" {
  description = "UN-locked, disposable bucket for CI/staging smoke tests. NEVER locked."
  type        = string
  default     = "coreline-audit-ir-evidence-staging"
}

variable "retention_seconds" {
  description = "Retention period in seconds (7 years = 7*365*24*3600)."
  type        = number
  default     = 220752000
}

variable "lock_retention" {
  description = <<-EOT
    Lock the retention policy on the PROD bucket. IRREVERSIBLE once applied — the policy can
    never be removed or shortened, and objects cannot be deleted for the full retention
    period, by anyone (incl. project owner). Two-step workflow: apply with `false`, verify
    with `terraform plan` / `gcloud storage buckets describe`, THEN set `true` and re-apply.
  EOT
  type        = bool
  default     = false
}

variable "writer_member" {
  description = <<-EOT
    The Coreline write identity — WRITE-ONLY. Prefer a Workload Identity Federation principal
    (keyless), e.g. "principal://iam.googleapis.com/projects/<NUM>/locations/global/
    workloadIdentityPools/<POOL>/subject/<SUBJECT>", or "serviceAccount:coreline-writer@<project>.iam.gserviceaccount.com".
  EOT
  type        = string
}

variable "auditor_member" {
  description = "Read-only auditor principal (a human/tool, NOT the app) for out-of-band verification."
  type        = string
}
