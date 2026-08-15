# Coreline evidence storage — WORM bucket + disposable staging + least-privilege IAM.
#
# Custody guarantee = these platform settings (retention lock + versioning) + the
# objectCreator-only write binding. The application makes no WORM claim; it only deposits.
#
# ⚠️ `lock_retention = true` is IRREVERSIBLE. See variables.tf for the two-step workflow.

# --------------------------------------------------------------------------- #
# Production evidence bucket — WORM
# --------------------------------------------------------------------------- #
resource "google_storage_bucket" "evidence" {
  name                        = var.evidence_bucket
  project                     = var.project_id
  location                    = var.location
  storage_class               = "STANDARD"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = false # never mass-delete evidence

  # NO object versioning — deliberately. The WORM property is the LOCKED RETENTION POLICY
  # plus unique object names (evidence uses UUIDs; registry revisions use sequence-suffixed
  # names). Under a locked, NON-versioned bucket, any overwrite of a not-yet-expired object
  # hard-fails (403 retentionPolicyNotMet) — the strong "a name can never point to different
  # content" guarantee. Enabling versioning would WEAKEN that (it lets the live object at a
  # key be replaced, keeping old bytes only as a noncurrent version) AND accrue billable
  # noncurrent versions that a lifecycle rule cannot delete inside the 7-year retention window.

  # Retention + (optionally) lock. When is_locked flips to true and is applied, the policy
  # becomes permanent — objects cannot be deleted/overwritten for retention_seconds, ever.
  retention_policy {
    retention_period = var.retention_seconds
    is_locked        = var.lock_retention
  }

  labels = {
    pan-owner       = "security-ops"
    pan-environment = "prod"
    system          = "coreline-evidence"
  }

  # Terraform must never destroy the locked evidence bucket.
  lifecycle {
    prevent_destroy = true
  }
}

# --------------------------------------------------------------------------- #
# Staging/CI bucket — UN-locked, disposable (never accrue undeletable test junk)
# --------------------------------------------------------------------------- #
resource "google_storage_bucket" "evidence_staging" {
  name                        = var.staging_bucket
  project                     = var.project_id
  location                    = var.location
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = true # disposable

  # No versioning here either — mirror prod so the smoke test exercises the real config.

  # Auto-clean smoke-test artifacts (no retention lock here, by design).
  lifecycle_rule {
    condition {
      age = 7
    }
    action {
      type = "Delete"
    }
  }

  labels = {
    pan-environment = "staging"
    system          = "coreline-evidence"
  }
}

# --------------------------------------------------------------------------- #
# IAM — least privilege. Additive (iam_member), never authoritative.
# --------------------------------------------------------------------------- #

# App on PROD: WRITE-ONLY. No read, no list, no delete — the one-way valve.
resource "google_storage_bucket_iam_member" "writer_prod" {
  bucket = google_storage_bucket.evidence.name
  role   = "roles/storage.objectCreator"
  member = var.writer_member
}

# Auditor on PROD: READ-ONLY, out-of-band verification. Separate principal from the app.
resource "google_storage_bucket_iam_member" "auditor_prod" {
  bucket = google_storage_bucket.evidence.name
  role   = "roles/storage.objectViewer"
  member = var.auditor_member
}

# App on STAGING: objectAdmin so CI can create AND clean up test objects (bucket is un-locked).
resource "google_storage_bucket_iam_member" "writer_staging" {
  bucket = google_storage_bucket.evidence_staging.name
  role   = "roles/storage.objectAdmin"
  member = var.writer_member
}
