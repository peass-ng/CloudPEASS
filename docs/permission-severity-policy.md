# Permission severity policy

Both CloudPEASS and Blue-CloudPEASS use these levels for AWS, GCP, Azure and Kubernetes:

- **Critical:** direct or nearly self-sufficient privilege grants, identity takeover, credential minting or privileged execution. Examples include `iam:PassRole`, service-account token minting, administrator assignment and Kubernetes `bind`/`escalate`. A trivial lookup or target-dependent prerequisite can still exist; Critical does not promise that a call succeeds on every target.
- **High:** protected data, stored secrets or private-key disclosure; code/configuration poisoning, traffic interception and escalation paths that depend on additional grants or target configuration.
- **Medium:** availability/integrity disruption (DoS/Break), telemetry tampering and ordinary operational changes. A prerequisite without the complete permission chain stays at its standalone level.
- **Low:** discovery and ordinary metadata reads without protected content.

The audit uses HackTricks Cloud master **45bcf7a7381a496d6dfd5b5d533681fff85c608d**. `permission-severity-audit.csv` records exact provider decisions and source links. It is a documentation-based classification review; existing live validation records retain their original provenance.

Exact `severity_overrides` precede generic naming rules. `severity_caps` prevent legacy combination lists from raising pure disruption or discovery above its audited level. Other prerequisites can be raised when their complete documented combination is present. Both runtime reports and stored catalogs use the same engine. Bundled rules are authoritative; a stale network/cache copy cannot silently change a shipped audit.

Kubernetes classification includes the API group, resource, subresource, verb and available name/selector constraints. Reading Secrets is High; minting a ServiceAccount token is Critical. Legacy status mutations whose only demonstrated effect is deletion or failed rollout availability are Medium. Ordinary RBAC writes respect Kubernetes escalation checks.
