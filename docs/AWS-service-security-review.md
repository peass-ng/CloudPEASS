# AWS service security review

This tracker covers all 455 unique IAM service prefixes from the AWS Policy Generator catalog. Services that share an IAM prefix are combined because IAM cannot distinguish them by service name.

The machine-readable inventory is [AWS-service-security-review.csv](AWS-service-security-review.csv). It retains only each service's priority and final review status; lab dates, identities, fixtures, controls, proof artifacts, and teardown narratives are intentionally omitted.

The companion [AWS cross-service security review](AWS-cross-service-security-review.md) lists X001–X119 and the complete known-positive permission inventory, including each permission's standalone severity, combination status, and cleaned HackTricks documentation link.

## Completion summary

| Status | Services |
| --- | ---: |
| `validated` | 140 |
| `no_new_positive` | 158 |
| `blocked` | 157 |
| `queued` | 0 |
| `in_progress` | 0 |

`validated` means the service has at least one documented technique. `no_new_positive` means the review added no new technique. `blocked` means a required safe and reversible prerequisite was unavailable; it is not a claim that the service has no attack surface.

Priorities are retained for future review passes:

- `P0`: identity, credential, organization, compute, execution, deployment, backup, or broadly sensitive data control planes.
- `P1`: services likely to contain secrets, customer data, invocation paths, resource-policy pivots, or service-role abuse.
- `P2`: all remaining services.

AWS adds APIs and changes behavior, so a completed row remains eligible for future review.
