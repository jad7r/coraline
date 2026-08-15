output "evidence_bucket" {
  description = "Production WORM evidence bucket name (set CORELINE_EVIDENCE_BUCKET to this in prod)."
  value       = google_storage_bucket.evidence.name
}

output "evidence_bucket_url" {
  value = google_storage_bucket.evidence.url
}

output "staging_bucket" {
  description = "Staging bucket name (set CORELINE_EVIDENCE_BUCKET to this for the CI smoke test)."
  value       = google_storage_bucket.evidence_staging.name
}

output "retention_locked" {
  description = "Whether the prod retention policy is locked (irreversible once true)."
  value       = google_storage_bucket.evidence.retention_policy[0].is_locked
}
