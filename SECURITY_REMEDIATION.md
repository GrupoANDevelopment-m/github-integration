# Goodware security remediation register

**Status date:** 2026-10-22  
**Scope:** remediation required before merging the audit branch or deploying the image.

This register deliberately distinguishes repository changes from actions that require credential-owner access. Deleting a secret file from the current tree does not revoke its value and does not erase earlier Git blobs.

## Required before production

- [ ] Revoke and rotate every credential, API token, signing key, database secret, and vault key that appeared in any tracked file or Git history.
- [ ] Re-provision the Goodware vault with a newly generated key. Do not reuse an exposed key to decrypt or re-encrypt production material without a controlled migration plan.
- [ ] Review GitHub Actions secrets, repository/environment secrets, deployment credentials, and container-registry credentials. Replace any value that may have been committed.
- [ ] Scan the full Git history and all branches/tags for secrets with an approved secret scanner. Review findings manually to avoid treating false positives as proof of exposure or safety.
- [ ] Coordinate a history rewrite with all repository collaborators. Use a reviewed git-filter-repo procedure to remove sensitive blobs, force-push only after approval, and require fresh clones where necessary.
- [ ] Re-run the full-history secret scan after rewriting and confirm that exposed values are revoked even if copies remain in forks, caches, artifacts, or clones.

## Runtime validation gates

- [ ] CI proves that real trained model artifacts load inside the built runtime image using the same pinned NumPy, pandas, scikit-learn, and joblib versions as training.
- [ ] CI exercises a real NSL-KDD feature row through the trained model; missing fields and unknown categorical values must fail closed.
- [ ] Federated HTTP integration verifies valid HMAC acceptance, invalid-signature rejection, no-secret refusal, and state changes only after accepted updates.
- [ ] Rollback integrity tests reject traversal, symlinks/special archive members, content-hash mismatches, and attempts to disable verification.
- [ ] Real-model benchmark artifact is retained from CI, including measured sample count, elapsed time, throughput and p50/p95/p99 latency. Results are runner-specific and must not be represented as a production SLA.
- [ ] Production deployment is tested with real secrets supplied through the deployment secret manager; CI placeholder values are never reused.

## Evidence and limitations

The audit branch contains automated code and CI changes for the runtime model dependency mismatch, real network-flow inference, federated HTTP validation, rollback integrity tests, and benchmark reporting. The latest CI run must pass on the final branch head before these gates can be marked complete.

**Not performed by repository edits:** revoking external credentials, rotating externally held keys, rewriting Git history, validating a real production secret manager, or testing under production traffic. These require authorized operator action and must remain unchecked until evidence is recorded.
