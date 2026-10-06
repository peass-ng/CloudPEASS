# Shared permission categorizations

The source of truth is [HackTricks Cloud](https://github.com/HackTricks-wiki/hacktricks-cloud/tree/master/src/permission-categorizations), with one YAML file for AWS, GCP, Azure, and Kubernetes. Edit those files to change classifications. Their README documents the schema and severity policy.

`python scripts/sync_hacktricks_permissions.py --book-root /path/to/hacktricks-cloud` validates and refreshes the bundled copies and legacy lists. Use `--check` to detect drift. The four SHA-256 hashes and source revision are recorded in `hacktricks-source.json` alongside the bundled files. Classification continues to work offline.

`.github/workflows/sync-permission-categorizations.yml` runs weekly on Monday and on manual dispatch. It validates and tests changes before committing them to the default branch using the standard GitHub Actions token. No extra secret is needed. If branch protection forbids that token from pushing, the workflow fails visibly; maintainers must permit the automation or adopt a PR-based update policy. File hashes prevent commits when only unrelated book content changed.

CloudPEASS's Python combination lists and Blue-CloudPEASS's categorized permission lists are generated compatibility outputs. Avoid editing them directly. `sync_cloudpeass_risks.py` in Blue-CloudPEASS remains available to update classifier code separately; it does not replace synchronization from HackTricks Cloud.

Source fetching retries up to five times, with a 150-second deadline per whole checkout attempt and backoff of 15, 30, 60, and 120 seconds. Git aborts stalled transfers, and the workflow has a 25-minute overall limit. Each attempt uses a temporary directory; only a complete checkout containing all four files becomes the synchronization source. Exhausted retries fail the job and preserve the bundled data.
