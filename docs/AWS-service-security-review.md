# AWS service security review tracker

This tracker keeps the AWS post-exploitation and privilege-escalation review
systematic. The companion CSV contains all 455 unique IAM service prefixes from
the 475 entries currently published by AWS's Policy Generator catalog. Entries
that share a prefix are combined because IAM cannot distinguish them by service
name. It is a work queue, not a claim that a queued service has no attack surface.

## Status meanings

- `queued`: not yet reviewed in this campaign.
- `in_progress`: documentation and API review or isolated live testing is in progress.
- `no_new_positive`: reviewed on the recorded date; no new reproducible technique was found.
- `validated`: at least one new technique passed the full evidence gate. A service remains
  eligible for later review because AWS adds APIs and changes behavior.
- `blocked`: a precise prerequisite prevented a conclusive test; the Notes field records it.

## Priority meanings

- `P0`: identity, credential, organization, compute, execution, deployment, backup, or broadly
  sensitive data control planes. Review these first.
- `P1`: services likely to contain secrets, customer data, invocation paths, resource-policy
  pivots, or service-role abuse.
- `P2`: all remaining services. P2 means later, not safe or uninteresting.

## Evidence gate

A technique can be added to HackTricks and CloudPEASS only when all of these are true:

1. The attack uses synthetic resources in an authorized account and a unique test prefix.
2. A least-privilege test identity succeeds with the candidate permission set.
3. A negative control with the candidate permission removed (or explicitly denied) fails.
4. The resulting security impact is observed, not inferred from an accepted API response.
5. Required companion permissions, resource policies, trust relationships, and ownership
   assumptions are recorded exactly.
6. Every test resource is deleted and the exact prefix is re-enumerated until empty.
7. The documentation includes reproduction and cleanup commands without overstating scope.

## Workflow

Review one service at a time. Start with API actions that can return credentials or sensitive
data, invoke code, pass or change identities, attach resources, alter policies, restore or clone
data, create signed URLs, or cause a more privileged service to act. Record failed hypotheses as
`no_new_positive` or `blocked` so they are not repeatedly rediscovered. Update the CSV in the same
commit as the evidence-backed implementation, then open a new HackTricks PR for documented true
positives.

The 2026-09-10 campaign completed the service-by-service pass over all 455 prefixes: 135 are
`validated`, 159 are `no_new_positive`, 161 are precisely `blocked`, and none remain `queued` or
`in_progress`. Blocked rows remain explicit future test plans when their missing prerequisite can
be supplied without violating the cleanup gate.

On 2026-09-08 the tracker was reconciled with
`live_validated_disclosure_documentation` and its regression suite. Fifty-six previously queued
service prefixes already had an evidence-backed action, a dedicated automated assertion, and a
service-specific HackTricks document; those rows now record the exact actions and documents as
`validated`. This reconciliation created no infrastructure and made no new severity decision. A
tracker regression test prevents a prefix with registered live evidence from silently remaining
queued.

The same evidence gate was subsequently applied to B2BI and additional Amazon Connect data
surfaces. Exact-action sessions recovered randomized B2BI sample/mapping and partner-contact
canaries, Connect contact attributes, and two forms of Connect Data Table values. Neighboring-action
controls were denied, and every transformer, profile, contact, table, flow, instance, and test role
was removed before those actions were marked `validated`.

## Ranked P0 hypothesis queue

These are test plans, not findings. The order favors paths that might reuse an existing service
role, weaken a trust boundary, expose a credential, or clone protected data. Each row must still
pass the evidence gate before it can change a permission severity or appear in HackTricks.

| Rank | Service | Next isolated hypothesis |
| ---: | --- | --- |
| Q03 | AWS Config | Point remediation at a preauthorized SSM Automation path and call `StartRemediationExecution`; distinguish Config permissions from SSM and pass-role checks. |
| Q04 | CodeConnections | Use an installed connection through an existing or synthetic consumer to determine whether `UseConnection` exposes or executes otherwise inaccessible private repository content. |
| Q05 | IAM Roles Anywhere | Mutate a trust anchor used by an existing profile and role, then attempt a certificate-backed session; retain the exact role trust and profile prerequisites. |
| Q07 | AWS Batch | Register and submit attacker code against existing job and execution roles; remove each `iam:PassRole` and Batch dependency independently. |
| Q10 | EKS | Create an access entry and attach an EKS access policy, then prove Kubernetes authorization rather than treating accepted IAM APIs as impact. |
| Q11 | OpenSearch | Change a domain access policy or another authorization surface and prove new data-plane access with a denied-before control. |
| Q12 | RDS | Share, copy, or restore an unencrypted snapshot and read a canary without source-instance access; record customer-managed KMS blockers separately. |
| Q13 | FSx | Copy, share, or restore a backup and mount/read a canary without source-filesystem permission. |
| Q14 | EventBridge | Attach a target to an existing rule and attempt execution through an existing service role or target resource policy, with and without `iam:PassRole`. |
| Q16 | S3 Object Lambda | Test access-point policy self-grant and a known transformed-object path while the caller remains denied direct source-object access. |

Source catalog: <https://awspolicygen.s3.amazonaws.com/js/policies.js>

## Review log

### AWS Backup (`backup`) — 2026-09-08

Validated with synthetic resources and least-privilege STS sessions:

- `backup:StartRestoreJob` plus `iam:PassRole` restored both a native DynamoDB backup and a fully
  AWS Backup-managed recovery point. The actor was denied source-table reads but could read the
  restored table because only the target ARN was allowed.
- Removing `backup:StartRestoreJob` denied the restore. Granting it without `iam:PassRole` failed
  specifically on the pass-role authorization check.
- `backup:PutBackupVaultAccessPolicy` let a same-account role self-grant
  `backup:DeleteRecoveryPoint`. Deletion failed before the vault-policy change and succeeded after
  it; the temporary policy was then removed.
- `backup:DeleteRecoveryPoint` deleted the scoped synthetic recovery point and is therefore a
  direct recovery/destructive impact permission when vault lock or an applicable deny does not
  block it.
- A least-privilege role denied direct source-bucket reads and was also denied through a Backup
  Access Point created without a policy. With the full `backup:CreateBackupAccessPoint`,
  `backup:DescribeBackupAccessPoint`, `s3:CreateAccessPoint`, `s3:GetAccessPoint`, and
  `s3:PutAccessPointPolicy` chain, it embedded a policy granting itself `s3:GetObject` and read the
  exact canary directly from the S3 recovery point without an identity-based data permission.

Not promoted from this pass:

- `backup:GetRecoveryPointRestoreMetadata` returned infrastructure restore metadata for the
  synthetic DynamoDB point, not table data or a credential.
- Cross-account copy remains a separate, configuration-dependent path requiring organization,
  destination-vault, role, and encryption prerequisites; no cross-account impact is claimed.
- Compliance-mode vault lock was not activated because its minimum cooling-off period conflicts
  with the mandatory same-session cleanup requirement.

The S3 Backup Access Point API was introduced after the locally installed AWS CLI model. The live
check therefore used a disposable current AWS SDK environment; the HackTricks procedure records
upgrading the CLI or using a current SDK as the compatibility fallback.

Cleanup completed in dependency order. Exact-prefix inventories for Backup vaults/access points,
recovery points, DynamoDB tables/backups, S3 buckets/access points, IAM roles, EventBridge rules,
and tagged resources all returned empty. The account's AWS Backup service-linked role dates from
2022 and was deliberately left untouched.

### Account access manager (`account-access`) — 2026-09-08

The management-account lab is an all-features AWS Organization but has no IAM Identity Center
instance. Account access manager requires that identity source before an application or role
entitlement can be created. Enabling a new organization-wide identity system solely to exercise
`account-access:CreateEntitlement` would expand the test beyond a safely isolated fixture, so the
service is recorded as `blocked`, with no security claim and no infrastructure created.

### AWS Service Catalog (`servicecatalog`) — 2026-09-08

Live validation confirmed that `servicecatalog:CreateProvisioningArtifact` plus
`servicecatalog:ProvisionProduct` can turn an existing privileged launch constraint into a
privilege-escalation path. A synthetic end-user role controlled one private template object and
the exact product, but had no `iam:PassRole`, no CloudFormation create permission, and no direct
`organizations:DescribeOrganization`. It added an artifact whose template created a role trusting
the end user, provisioned it, assumed the created role, and successfully called
`organizations:DescribeOrganization`. The Service Catalog record identified the configured launch
role as the executor.

Independent controls removed each Service Catalog action in turn. Creating the artifact without
`CreateProvisioningArtifact` and provisioning it without `ProvisionProduct` both returned
`AccessDenied`, and neither control created a resource. A second end-to-end run used
`DisableTemplateValidation=true` and succeeded without caller `cloudformation:ValidateTemplate`,
so that permission is not part of the minimum chain. The caller still needs control of a template
source, access to a non-shared product associated with its portfolio, and a launch constraint whose
role can perform the template's actions. The pair is therefore recorded as a conditional critical
combination while each permission remains medium in isolation.

### Amazon EC2 Image Builder (`imagebuilder`) — 2026-09-08

Live validation confirmed a version-reference escalation. A benign recipe stored
`component/cloudpeass-ib-.../x.x.x` and an enabled pipeline used an infrastructure configuration
with a synthetic instance profile. A restricted role with only `imagebuilder:CreateComponent` on
that component name, `imagebuilder:StartImagePipelineExecution` on the existing pipeline, and read
access to a proof bucket published version `2.0.0` and started the unchanged pipeline. The resulting
image record resolved the wildcard to the new `2.0.0/1` component and launched a build instance
with the existing instance profile.

The caller had no `iam:PassRole`, no `imagebuilder:UpdateImagePipeline`, and was denied
`organizations:DescribeOrganization`. Its component used the build profile to write the caller
identity and organization response to the proof bucket. Reading those objects showed the exact
build-instance role ARN and organization metadata. Removing `StartImagePipelineExecution` denied a
second start and created no image; removing `CreateComponent` denied creation of version `3.0.0`.
The pair is conditional critical: the recipe must track a wildcard version beneath a component name
the caller can update, and the existing pipeline profile must expose a useful permission or data
path. Pinned component build ARNs prevent this particular technique.

The image was cancelled as soon as both proof objects arrived. Image Builder reported `CANCELLED`,
the EC2 instance reached `terminated`, and no AMI, snapshot, or active volume was produced. The
pipeline, image record, recipe, both component versions, infrastructure configuration, two log
groups, proof objects and bucket, test roles, and instance profile were deleted. Exact-prefix checks
returned no active Image Builder, IAM, S3, CloudWatch Logs, EC2, EBS, AMI, or snapshot resources.
The account's Image Builder service-linked role dates from 2020 and was deliberately left untouched.

### AWS CodeDeploy (`codedeploy`) — 2026-09-08

Live validation confirmed that a controlled S3 revision plus `codedeploy:CreateDeployment` can
execute lifecycle hooks as root on an existing EC2 deployment-group target and inherit its instance
profile. AWS enforced `codedeploy:GetDeploymentConfig` on the group's deployment configuration and
`codedeploy:RegisterApplicationRevision` on the application as dependent permissions of the create
request. The caller did not need to make a separate register call.

The synthetic caller could write one revision object and read three proof objects, but had no
`iam:PassRole`, EC2, SSM, or direct `organizations:DescribeOrganization`. The revision's
`AfterInstall` hook returned `uid=0(root)`, the exact assumed instance-role ARN, and organization
metadata. A policy containing only `CreateDeployment` failed on `GetDeploymentConfig`; adding that
failed on `RegisterApplicationRevision`; adding all three succeeded. A final control removed
`CreateDeployment` while retaining both dependencies and was denied without creating a second
deployment.

The chain is conditional critical: the application and EC2/on-premises deployment group must
already exist, the caller must control an accessible revision source, and at least one reachable
agent target must expose useful host or instance-profile privilege. The successful deployment was
deleted with its group/application; the only EC2 target was terminated, its volume and no-ingress
security group deleted, and all test IAM, instance-profile, S3, and local bundle resources removed.
Authoritative inventories returned no active prefix-matching resource; the Resource Groups Tagging
API temporarily retained tombstones for the terminated instance and deleted volume.

### AWS Systems Manager (`ssm`) — 2026-09-08

Live validation confirmed that `ssm:StartAutomationExecution` alone can invoke an
administrator-authored Automation runbook with a constant privileged `assumeRole`. The test role
had no `iam:PassRole` and was denied `organizations:DescribeOrganization`, but started the exact
document successfully. Its `aws:executeAwsApi` step assumed the stored role and returned the
organization ID.

`ssm:GetAutomationExecution` is not required for the action's impact. A second session containing
only `StartAutomationExecution` was denied the get call, while an independent administrator
observed that its execution reached `Success` with the same privileged output. Removing Start and
retaining only Get denied a third execution. This finding is scoped to a role ARN stored directly in
the runbook and preauthorized when the document was authored; passing an attacker-selected
`AutomationAssumeRole` parameter at runtime can invoke separate `iam:PassRole` checks.

The permission is classified critical because preauthorized runbooks are delegated-administration
entry points and may change infrastructure or expose role-only output. A useful document and any
required parameter values remain prerequisites. Both completed executions became immutable history;
the document and two test roles were deleted, and exact checks returned no active Automation, IAM,
or tagged fixture.

### AWS Signer (`signer`) — 2026-09-08

Live validation confirmed a code-signing trust bypass when `signer:StartSigningJob` covers the exact
profile version trusted by an enforcing Lambda Code Signing Config. The restricted caller staged an
attacker-controlled ZIP, signed it with that trusted profile, and used
`lambda:UpdateFunctionCode` to deploy it to an existing function. The caller had no
`iam:PassRole` and was denied `organizations:DescribeOrganization`, but an independent invocation
returned the function execution-role ARN and organization ID.

The unsigned deployment was rejected with `CodeVerificationFailedException`. A role lacking
`StartSigningJob` could not sign, while a signing-only role produced a valid signed ZIP but was
denied `UpdateFunctionCode`. Lambda also enforced `lambda:GetCodeSigningConfig` during the update.
Minimization runs reduced the S3 prerequisites to `ListBucket`, `GetObjectVersion`, and `PutObject`
for signing, plus `GetObject` so Lambda could fetch the signed result. `GetBucketLocation` and
`GetBucketVersioning` were removed and the complete path still succeeded.

`StartSigningJob` is high because it is authority to produce artifacts accepted as a trusted
publisher; the end-to-end Lambda execution path is conditional critical and additionally requires
an enforcing configuration that trusts the profile, code-update access, controlled staging objects,
and a function role with useful access. List and describe permissions were absent from the attack
sessions. Known names and versions can instead come from SAM/CloudFormation templates, CI files,
artifact manifests, cached command output, errors, or shell history.

All functions, code-signing configurations, buckets and every object version, IAM roles, and inline
policies were deleted. Signer jobs remain immutable history, and each test signing profile was
canceled and revoked because Signer does not permit reusing or physically deleting its name after
cancellation. Exact checks returned no active compute, S3, Lambda, or IAM fixture.

### Amazon EventBridge (`events`) — 2026-09-08

Live validation confirmed that `events:PutTargets` plus `events:PutEvents` can invoke an existing
privileged Lambda without `lambda:InvokeFunction` or `iam:PassRole` when the Lambda resource policy
already trusts the targeted rule ARN. Three administrator-created rules on a synthetic custom bus
isolated the controls. A PutEvents-only role emitted before any target existed and no proof object
appeared; it was denied PutTargets. A PutTargets-only role attached the function but was denied
PutEvents. The full role attached the same function to a third rule, emitted an attacker-controlled
event, and read a proof containing the function execution-role ARN and organization ID.

The caller was independently denied direct Lambda invocation and
`organizations:DescribeOrganization`. No execution role was supplied to `PutTargets`; Lambda
authorized `events.amazonaws.com` through its own resource policy. This pair is conditional
critical because a controllable bus/rule, a useful target, and a matching target resource policy
are prerequisites. Each EventBridge action remains medium alone.

All three rules and targets, the custom bus, function, bucket and object versions, four IAM roles,
inline policies, and Lambda resource-policy statements were deleted. Exact prefix checks returned
no active EventBridge, Lambda, S3, or IAM fixture.

### IAM Roles Anywhere (`rolesanywhere`) — 2026-09-08

Live validation confirmed that `rolesanywhere:UpdateTrustAnchor` alone can replace the CA
certificate bundle behind an existing trust anchor. A client certificate issued by the synthetic
attacker CA was rejected before the update. A no-permission IAM user was denied the update, while a
restricted user with only `UpdateTrustAnchor` replaced the anchor. The unchanged certificate then
obtained temporary credentials for the existing profile's target role and returned organization
metadata unavailable to the restricted user directly. No `iam:PassRole` was used.

The permission is critical when the anchor is enabled, an enabled profile names a useful role, the
role trusts `rolesanywhere.amazonaws.com`, and its trust-policy conditions accept the certificate's
subject/issuer/SAN attributes and source anchor. Strong `aws:SourceArn`, `aws:SourceAccount`, and
principal-tag conditions can prevent a swapped CA from satisfying the role trust.

The trust anchor, profile, target role, two disposable IAM users and access keys, inline policies,
local CA/client keys, and the service-linked role created by the first anchor were deleted. Exact
Roles Anywhere and IAM inventories returned empty.

### Amazon EventBridge Pipes (`pipes`) — 2026-09-08

The tested same-role target-redirection hypothesis produced no new positive. An administrator
created a running SQS-to-SQS pipe whose existing execution role could receive from the source and
send to both the benign and synthetic attacker queues. A restricted IAM user had only
`pipes:UpdatePipe` on that exact pipe and receive access to the attacker queue; it was denied direct
reads from the source queue.

Changing the target still required the caller to submit the pipe's `RoleArn`. AWS denied the update
specifically because the caller lacked `iam:PassRole`, even though the ARN was unchanged and the
pipe was already running. A no-permission user was also denied. This rules out treating
`pipes:UpdatePipe` alone as a validated stored-role bypass for this configuration; attack paths
that genuinely include `iam:PassRole`, or a different independently tested authorization surface,
remain separate cases.

The pipe, all three queues, execution role and policy, both disposable IAM users, and both access
keys were deleted. Exact prefix queries returned no remaining Pipes, SQS, or IAM resources.

### Amazon SageMaker (`sagemaker`) — 2026-09-08

Live validation confirmed that `sagemaker:UpdateNotebookInstanceLifecycleConfig` alone can persist
attacker-controlled shell code into a lifecycle configuration already attached to a notebook. The
restricted user could not start or stop the notebook, lacked `iam:PassRole`, and was denied direct
`organizations:DescribeOrganization`. A no-permission user was denied the lifecycle update.

The notebook's original benign `OnStart` hook reached `InService` without creating a proof object.
After an administrator stopped it, the restricted user replaced only the lifecycle configuration's
`OnStart` content. The restricted user's own start request was denied. On the next administrator
start, the new script ran as root, wrote the unique canary, reported the notebook's exact assumed
execution-role ARN, and returned organization metadata that the updater could not access directly.

This single permission is critical when a target lifecycle configuration is attached to at least
one notebook that will later start and the notebook role or host exposes useful privilege or data.
The action does not attach the configuration to a different notebook; known configuration names
can still be recovered from IaC, CI files, cached output, errors, or shell history when list and
describe permissions are unavailable. Disabling notebook-user root access does not restrict the
lifecycle hook itself.

The notebook was stopped and deleted, followed by its lifecycle configuration, private proof
bucket and object, execution role and policy, two disposable IAM users, and both access keys.
Exact prefix inventories returned no remaining SageMaker notebook, lifecycle configuration, S3
bucket, IAM user, or IAM role.

### Amazon API Gateway Management (`apigateway`) — 2026-09-08

Live validation confirmed that `apigateway:PATCH` alone can redirect an existing HTTP API
integration and intercept requests when its stage has automatic deployment enabled. The synthetic
`$default` stage initially routed `POST /submit` to a benign Lambda and returned `benign`; no proof
object existed. A restricted user knew the API and integration IDs but had no API Gateway list/get
permissions, deployment permission, Lambda invocation, or `iam:PassRole`.

A no-permission user was denied `UpdateIntegration`, and the restricted user was denied direct
invocation of the collector Lambda. The restricted user then changed only the existing
integration's URI with `apigateway:PATCH`. The next request was received by the collector, whose
private proof object contained the exact JSON body, bearer `Authorization` header, and custom
sensitive header. No `apigateway:POST` deployment action was needed because auto-deploy published
the integration update.

The action is High based on the independently observed request and token disclosure. Whether it
becomes privilege escalation or Critical depends on the affected route, its authorization model,
the secrets carried by clients, and whether the replacement endpoint is accepted. Without list or
get permissions, IDs may still be recovered from invoke URLs, OpenAPI/IaC files, CI configuration,
SDK settings, logs, cached CLI output, errors, or shell history. Stages without auto-deploy require
a separate deployment path.

The HTTP API, stage, route and integration, both Lambda functions and their policies, private proof
bucket and object, execution role, two disposable IAM users, both access keys, and local deployment
ZIP were deleted. Exact prefix inventories returned no API Gateway, Lambda, S3, or IAM resource.

### Amazon EventBridge Scheduler (`scheduler`) — 2026-09-08

The tested stored-role target-redirection hypothesis produced no new positive. An administrator
created an enabled schedule whose execution role could send to both a benign queue and a synthetic
attacker queue. A restricted user had only `scheduler:UpdateSchedule` on that exact schedule and
receive access to the attacker queue; it was denied reads from the original target queue.

`UpdateSchedule` requires a complete target object including `RoleArn`. AWS denied the restricted
update specifically on `iam:PassRole` even though the request resubmitted the unchanged role already
stored on the schedule. A no-permission user was independently denied the update. Therefore
`scheduler:UpdateSchedule` alone is not classified as a stored-role bypass for this configuration;
attack chains that also include `iam:PassRole` remain separately relevant.

The schedule, both queues, execution role and policy, two disposable IAM users, and both access keys
were deleted. Exact prefix queries returned no remaining Scheduler, SQS, or IAM resources.

### AWS Secrets Manager (`secretsmanager`) — 2026-09-08

Live validation confirmed that `secretsmanager:PutResourcePolicy` alone can grant a same-account IAM
user access to a secret value. A synthetic user had an identity policy allowing only
`PutResourcePolicy` on one exact secret and was denied `GetSecretValue` before the change. A
no-permission user was independently denied the policy update.

The restricted user installed a policy naming its exact IAM-user ARN and allowing
`secretsmanager:GetSecretValue` on that secret. The same user then recovered the exact canary even
though its identity policy still contained no read action. This is classified Critical because it
directly turns resource-policy control into secret disclosure.

The proof is deliberately limited to a same-account IAM user and a secret encrypted with the
AWS-managed Secrets Manager key. Cross-account principals require both resource- and identity-based
allows, and customer-managed KMS keys introduce `kms:Decrypt` plus key-policy authorization.
`BlockPublicPolicy` protects against policies that Zelkova considers broad/public; fixed-principal
self-grants must still be prevented by restricting `PutResourcePolicy` itself. Known secret names or
ARNs may come from application configuration, IaC, CI files, environment variables, logs, errors,
or shell history when list/get metadata calls are denied.

The resource policy was removed, the secret was force-deleted and polled until absent, and both
disposable IAM users, access keys, and inline policy were deleted. Exact Secrets Manager and IAM
prefix inventories returned empty.

### Amazon DynamoDB (`dynamodb`) — 2026-09-08

Live validation confirmed that `dynamodb:PutResourcePolicy` alone can grant a same-account IAM user
data access to a table. The restricted user's identity policy allowed only `PutResourcePolicy` on
one exact table, and its `GetItem` request was denied before the change. A no-permission user was
independently denied the policy update.

The restricted user installed a table policy naming its exact IAM-user ARN and allowing only
`dynamodb:GetItem`. After DynamoDB's short policy-propagation interval, the same user read the exact
canary without an identity-based data action. The permission is classified Critical because it
directly converts authorization-boundary control into table data access and can grant broader
write, stream, or backup actions when the table policy accepts them.

The result is scoped to the tested same-account user/table path. Cross-account principals and
secondary resources such as indexes, streams, global-table replicas, exports, and backups have
their own supported-action, ARN, KMS, and identity-policy requirements. When table enumeration is
denied, names and ARNs may remain in application configuration, IaC, CI files, environment
variables, logs, error messages, or shell history.

The resource policy was removed before the table was deleted and polled until absent. Both
disposable IAM users, access keys, and the inline policy were deleted; exact DynamoDB and IAM
prefix inventories returned empty.

### Amazon SQS (`sqs`) — 2026-09-08

Live validation confirmed that `sqs:SetQueueAttributes` alone can replace a queue's resource policy
and grant the same-account caller access to message data. A synthetic IAM user had only that action
on one exact queue and was denied `ReceiveMessage` before the change. A no-permission user was
independently denied the attribute update.

The restricted user installed a `Policy` attribute naming its exact IAM-user ARN and allowing only
`sqs:ReceiveMessage`. After propagation, the same user recovered the seeded canary without an
identity-based receive allow. This permission is Critical: besides arbitrary queue-policy control,
the same setter can change redrive, retention, visibility, delay, encryption, and other attributes
that influence confidentiality, integrity, or availability.

The proof requires an owner-account caller because SQS does not permit cross-account callers to use
`SetQueueAttributes`. A known queue URL is sufficient; when `ListQueues` or `GetQueueUrl` is denied,
URLs commonly remain in application configuration, Lambda event-source mappings, environment
variables, IaC, CI files, logs, errors, or shell history.

The policy attribute was cleared before deleting the queue. Both disposable IAM users, access keys,
and the inline policy were deleted; exact SQS and IAM prefix inventories returned empty.

### Amazon SNS (`sns`) — 2026-09-08

Live validation confirmed that `sns:SetTopicAttributes` alone can replace a topic policy and grant
the same-account caller subscription access. A restricted IAM user's identity policy allowed only
`SetTopicAttributes` on one topic plus receive access to a synthetic destination queue. Its
`Subscribe` request was denied before the policy change, and a no-permission user was independently
denied the attribute update.

The restricted user set the topic's `Policy` attribute to name its exact IAM-user ARN and allow
only `sns:Subscribe`. It then subscribed the queue without an identity-based SNS subscribe allow.
An administrator published a later canary, and the restricted user received it from the queue. The
permission is Critical because it can convert policy control into persistent access to future topic
messages and can also authorize publication or other policy-supported topic actions.

The delivery endpoint must separately accept SNS messages. The lab kept all data inside the test
account and used a queue policy restricted to `sns.amazonaws.com` with the exact topic ARN as
`aws:SourceArn`. When SNS listing is denied, topic ARNs can still appear in application settings,
subscriptions, IaC, CI files, logs, errors, or shell history.

The subscription was removed before deleting the topic and queue. Both disposable IAM users,
access keys, inline policy, and queue policy were deleted; exact SNS, SQS, and IAM inventories
returned empty.

### AWS Identity and Access Management (`iam`) — 2026-09-08

Validated `iam:CreateAccessKey` as a direct cross-user credential takeover primitive. A synthetic
target user had only `organizations:DescribeOrganization`; the attacking user had only
`iam:CreateAccessKey` on that exact target ARN. The attacker was denied the Organizations call,
and a separate no-permission user was denied access-key creation. The attacking user then created
an access key for the target, and the returned credentials successfully retrieved the lab
organization's exact ID and ARN. This observes inherited target authorization rather than merely
an accepted IAM control-plane response.

`iam:ListUsers` is not required. Target names and ARNs can instead be recovered from CloudTrail,
resource policies, trust policies, infrastructure-as-code, CI/CD configuration, application
settings, environment variables, logs, and access-denied messages. A target that already has two
access keys cannot receive another until one is deleted, so `iam:DeleteAccessKey` is only an
optional capacity-making companion permission and not part of the validated singleton.

The proof used a unique prefix and never persisted target credentials in the repository. Cleanup
enumerated and deleted every access key before deleting all three synthetic users and their inline
policies; the exact-prefix IAM user inventory returned empty. A prior propagation-sensitive run
was also cleaned by enumerating every key rather than relying on a cached identifier.

### Amazon Route 53 (`route53`) — 2026-09-08

Validated `route53:ChangeResourceRecordSets` as an existing-zone DNS takeover primitive. A
synthetic public hosted zone began with an A record resolving to `192.0.2.10`. The attacking user
had only the candidate action on the exact hosted-zone ARN, was denied `ListHostedZones`, and knew
the zone ID and record name. A separate no-permission user was denied the same UPSERT. The attacker
changed the existing record to `192.0.2.99`; after Route 53 reported the change synchronized, a
direct query to the zone's public authoritative name server returned `192.0.2.99`.

The permission is High in isolation because control of an existing record can redirect application
or email traffic and can satisfy some DNS-based ownership checks; the final impact depends on what
the name serves and on transport authentication. The already-recorded multi-permission private-DNS
and Private CA chain remains Critical separately. `route53:ListHostedZones` is not required: zone
IDs and record names commonly appear in IaC state, deployment output, CloudTrail, application and
resolver configuration, CI/CD variables, logs, errors, console URLs, and NS/SOA lookups.

Cleanup first deleted the exact altered record and then the synthetic hosted zone. Both IAM users,
their access keys, and the inline policy were deleted. Exact Route 53 and IAM prefix inventories
returned empty; no existing account-owned zone was modified.

### AWS Elastic Load Balancing V2 (`elasticloadbalancing`) — 2026-09-08

Validated `elasticloadbalancing:ModifyListener` as an Application Load Balancer traffic-redirection
primitive. A synthetic internet-facing ALB listener initially returned the literal body `benign`.
The attacking user had only the candidate permission on the exact listener ARN, could not call
`DescribeListeners`, and knew the listener ARN. A separate no-permission user was denied the same
modification. The attacker replaced the default action with an HTTPS redirect to
`attacker.invalid`; a real request to the ALB then returned the exact attacker-selected `Location`.

No target group, backend, service role, `iam:PassRole`, or ELB list/read permission was required for
the tested redirect. The permission is High because it can divert requests away from an existing
listener, although TLS behavior, client redirect handling, and the listener's traffic determine
whether secrets are exposed. Listener ARNs and ALB names can be recovered without ELB listing from
IaC state, CloudTrail, deployment output, CI/CD configuration, application inventories, logs,
errors, metrics dimensions, and console URLs.

Cleanup deleted the listener and ALB, waited for load-balancer deletion, and retried the security
group deletion until delayed ENI detachment completed. Both IAM users, every access key, and the
inline policy were deleted. Exact-prefix ALB, security-group, and IAM inventories returned empty.
Two earlier harness-only failures—the CLI shorthand parser and a non-portable case-insensitive
`awk` expression—also ran full cleanup and did not count as security results.

### Amazon Cognito Identity (`cognito-identity`) — 2026-09-08

Validated `cognito-identity:UpdateIdentityPool` as a public credential-enablement primitive. A
synthetic identity pool had unauthenticated access disabled but already had an unauthenticated IAM
role assigned. That role could read one exact private S3 canary. An unsigned `GetId` request failed
before the change. The attacking user had only `UpdateIdentityPool` on the exact pool ARN, could
not list identity pools, and a separate no-permission user was denied the update. The attacker
enabled unauthenticated identities; an unsigned client then obtained an identity ID and temporary
role credentials and used them to read the exact canary.

This path requires the latent unauthenticated role assignment and its effective permissions. The
attacker did not need `SetIdentityPoolRoles`, `iam:PassRole`, IAM read access, or any signed
permission for the public `GetId`/`GetCredentialsForIdentity` calls. Cognito enhanced-flow
scope-down policies still limit the resulting session. Identity-pool IDs and names are commonly
public client configuration and can also be recovered from mobile/web bundles, environment
variables, IaC, CI/CD output, logs, errors, and deep links when list access is denied.

Cleanup deleted the identity pool, role and inline policy, S3 object and bucket, both users, every
access key, and the candidate policy. Exact Cognito pool, IAM user/role, and S3 bucket inventories
returned empty.

### Amazon EC2 (`ec2`) — `ModifyInstanceAttribute` network exposure — 2026-09-08

Validated that `ec2:ModifyInstanceAttribute` alone can replace the security groups on a known
running instance's primary network interface. A synthetic instance ran an HTTP service containing
an exact canary while its initial security group had no ingress. The request timed out before the
change. The attacking user had only the candidate action, could not describe the instance, and a
separate no-permission user was denied modification. After the attacker supplied the ID of a
synthetic security group allowing TCP/8080, the same public-IP request returned the exact canary.

The `groups` path did not require stopping or starting the instance, modifying the network
interface directly, reading EC2 inventory, passing a role, or changing user data. It requires a
known instance ID and replacement security-group ID. Those identifiers commonly appear in IMDS,
hostnames, DNS, IaC state, deployment and CI/CD output, CloudTrail, Systems Manager, monitoring,
logs, errors, and console URLs. The action is Critical because it can expose otherwise unreachable
administrative or data services; actual reachability still depends on routing, NACLs, the service
bind address, and other network controls.

Cleanup terminated the instance and waited for the terminal state; its delete-on-termination root
volume disappeared. Both security groups, both IAM users, all access keys, and the inline policy
were deleted. Exact instance, volume, security-group, and IAM prefix inventories returned empty.

### Amazon Route 53 Domains (`route53domains`) — 2026-09-08

Validated `route53domains:GetDomainDetail` as a registration-data disclosure. A disposable user
with only that action could not call `ListDomains`, while a separate no-permission user was denied
the detail request. For one known domain, the candidate call returned 33 nonempty fields across the
registrant, administrative, and technical contacts plus a status entry. The harness counted fields
in memory and did not print or persist any names, addresses, email addresses, telephone numbers,
nameservers, or other response values.

The API authorizes the action against `Resource: "*"`; a first per-domain-ARN attempt was denied
against resource `*`, then fully cleaned. The domain name itself needs no AWS permission to
discover because DNS, certificate-transparency records, application URLs, emails, public source,
and client configuration commonly expose it. Neither run changed the registered domain. Both
sets of disposable users, every access key, and inline policies were deleted; exact IAM prefix
inventory returned empty.

### Amazon Resource Groups Tagging API (`tag`) — 2026-09-08

No new independent escalation primitive was found for `tag:TagResources`. The first hypothesis
gave a user a latent `secretsmanager:GetSecretValue` allow conditioned on
`aws:ResourceTag/Access=allowed` plus only the generic tagging action. Its pre-tag secret read and
resource enumeration were denied, and a no-tagging control could not call the API. Although the
candidate `TagResources` request returned HTTP success, the secret remained untagged and the
conditional read stayed denied; the harness correctly rejected the result.

A second isolated run captured the response's per-resource result. `FailedResourcesMap` reported
`AccessDeniedException`, and an administrator read confirmed the original synthetic tag was
unchanged. This matches the CLI/API requirement: the caller needs `tag:TagResources` **and** the
resource-owning service's tagging permission—for example `secretsmanager:TagResource`. That
service-specific permission can already make the same tag change directly, so adding the generic
action does not unlock a separate ABAC path. Consumers must inspect `FailedResourcesMap`; a zero
exit status or HTTP 200 alone is a false positive.

Both synthetic secrets were force-deleted and polled until absent. All three disposable users,
every access key, and inline policy were deleted; exact Secrets Manager and IAM inventories
returned empty. No HackTricks attack entry or permission-severity promotion was made.

### AWS Certificate Manager (`acm`) — 2026-09-08

Validated `acm:ExportCertificate` as direct private-key disclosure for an exportable certificate.
The lab requested one unique public certificate with export enabled and certificate-transparency
logging disabled, then validated it using one unique CNAME beneath an authorized hosted zone. The
attacking user had only `ExportCertificate` on the exact certificate ARN and was denied
`ListCertificates`; a separate no-permission user was denied export. The successful response
contained an encrypted private-key PEM. Because the caller chooses the export passphrase, the
harness decrypted it and confirmed that its derived public-key fingerprint exactly matched the
issued certificate. No key material or fingerprint was printed or persisted.

The path requires a known certificate ARN and a certificate that was issued as exportable. This
action does not turn existing non-exportable or imported certificates into exportable ones. ARN
fallbacks include ALB/NLB listeners, CloudFront and API Gateway configuration, CloudFormation/IaC
state, deployment output, CloudTrail, certificate deployment configuration, logs, and console
URLs. The permission is Critical because the returned private key can enable service impersonation
where the certificate remains trusted.

The validation CNAME was deleted from the existing zone before the synthetic certificate was
deleted. The certificate, both IAM users, every access key, and the inline policy were removed;
exact ACM, Route 53 record, and IAM inventories returned empty. A first harness run translated no
ACM `Value` field into Route 53's `ResourceRecords` shape, failed before DNS mutation, and was also
fully cleaned; it did not count as a security result.

### P0 prerequisite audit — 2026-09-08

Read-only inventories resolved nine currently untestable P0 rows as `blocked`, not safe or
negative. The organization has `ALL` features but contains only its management account, so AWS RAM
cross-account sharing and Organizations delegation/SCP/account-movement hypotheses have no
independent authorized consumer. No share or organization policy was changed. IAM Identity Center
returned no instances, which also leaves Identity Store and SSO Directory without a target;
Control Tower returned no landing zones. Enabling either organization-wide control plane solely
for a test would exceed an isolated disposable fixture.

Directory Service and registered WorkSpaces directory inventories were empty, as were WorkSpaces,
Secure Browser portals, and Storage Gateways. WorkSpaces therefore lacks its directory prerequisite;
Secure Browser lacks a configured portal and identity provider; Storage Gateway lacks an activated
appliance and backing store. None of those services was created or mutated. Their tracker notes
retain the exact missing prerequisite so a future authorized lab with the service already present
can resume the security-impact test rather than infer a result from API documentation.

### AWS Resource Groups (`resource-groups`) — 2026-09-08

No new high-impact standalone technique was found. The `GroupResources` API is not a generic path
for arbitrary groups: the installed current CLI documents support only EC2 HostManagement,
CapacityReservationPool, and ResourceGroups ApplicationGroup types. Creating an empty group or a
generic group for arbitrary manual membership was rejected. Even supported group membership is
organizational metadata and does not grant access to the member resource.

Two data-boundary tests used private S3 canaries. A tag-query group did not surface its newly tagged
bucket to an identity with only `ListGroupResources`, because resolving that query also requires
`tag:GetResources`. A deterministic CloudFormation-stack group produced the same explicit
`Forbidden` result: that query type additionally requires `cloudformation:DescribeStacks`,
`cloudformation:ListStackResources`, and `tag:GetResources`. The identities remained denied direct
S3 reads, list operations, and the no-permission controls. The dependent read permissions can
enumerate resource ARNs and types, but group membership itself does not authorize access, so no
High/Critical finding or HackTricks attack entry was created.

Both groups, both private buckets and objects, the CloudFormation stack, all four disposable users,
every access key, and inline policies were deleted. Exact Resource Groups, CloudFormation, S3, and
IAM prefix inventories returned empty.

### AWS Security Token Service (`sts`) — evidence reconciliation — 2026-09-08

The earlier live-tested `sts:GetFederationToken` result from commit `46c3d77` is now registered in
the stricter disclosure-evidence map and tracker. It mints a separate temporary access key, secret,
and session token for the current IAM user; requested session policies intersect with the user's
authority, so it cannot escalate beyond that user. It remains High as credential hand-off and a
session-lifetime extension primitive, not Critical privilege escalation. HackTricks already records
the exact IAM-user prerequisite, 36-hour maximum, role/session restriction, permissionless
`GetCallerIdentity` fallback, and a 15-minute restrictive demonstration.

This reconciliation created no infrastructure and intentionally did not mint another STS session,
because issued STS credentials cannot be explicitly destroyed. `AssumeRole`, SAML, web-identity,
service-bearer, delegated-token, and root-session paths remain governed by their separate trust,
provider/token, companion-permission, organization, and task-policy prerequisites; no unconditional
impact is inferred from the STS action name alone.

Concurrent live evidence for the `iotsitewise` asset-property read APIs and SimpleDB `GetAttributes`
and `Select` arrived while the EKS review was running. Their dedicated regression tests and
HackTricks document mappings were already committed, so the two P2 tracker rows were reconciled to
`validated`; this reconciliation created no infrastructure and made no new severity decision.

Concurrent live evidence for TwinMaker `GetWorkspace`, `GetComponentType`, and `GetPropertyValue`
arrived during the subsequent prerequisite review and was reconciled to its existing dedicated
HackTricks mapping under the same no-new-infrastructure rule.

### Amazon EKS (`eks`) — 2026-09-08

Validated the `eks:CreateAccessEntry` plus `eks:AssociateAccessPolicy` pair as direct Kubernetes
cluster-admin escalation. A synthetic EKS control plane used API-and-ConfigMap authentication and
no worker nodes. The attacking IAM user had only those two EKS actions, could not list clusters,
and its signed Kubernetes token initially received `Unauthorized`; a separate no-permission user
was denied access-entry creation. The attacker created a `STANDARD` entry for itself and associated
`AmazonEKSClusterAdminPolicy` with cluster scope. A fresh token then made
`kubectl auth can-i '*' '*' --all-namespaces` return `yes` against the real Kubernetes API.

The proof needed no `DescribeCluster`, `iam:PassRole`, node role, managed node group, or workload.
It does require a cluster authentication mode containing `API`, a known cluster name/endpoint/CA,
and permission for both control-plane actions. When EKS reads are denied, those values can appear
in kubeconfig files, IaC state, deployment output, CI/CD variables, CloudTrail, logs, errors,
application configuration, and console URLs.

An independent second cluster tested whether `CreateAccessEntry` alone could specify the built-in
Kubernetes `system:masters` group. EKS rejected it with `InvalidParameterException` because group
names cannot start with `system:`. The singleton was therefore not promoted; the two-action pair is
the validated Critical result. Both access entries and clusters were deleted and polled absent,
then their roles, users, every access key, policies, generated ENIs/security groups, and exact local
kubeconfig files were removed. All exact-prefix inventories returned empty.

### AWS CodeBuild (`codebuild`) — running-sandbox command injection, 2026-09-10

`codebuild:StartCommandExecution` alone was validated as a direct takeover of a running CodeBuild
sandbox's execution role. An administrator created the project and started a disposable sandbox
whose service role could read exactly one Secrets Manager canary. A new IAM user with only
`StartCommandExecution` and a known sandbox ID submitted arbitrary shell/Python, and the completed
command's `standardOutputContent` contained the exact randomized canary. A separate empty user was
denied the same request.

The caller did not have `StartSandbox`, `StartBuild`, `BatchGetProjects`, `BatchGetSandboxes`,
Secrets Manager access, `iam:PassRole`, or access to the project's service role. Reading command
output through the API is also optional because attacker code can use the sandbox role directly or
send results to a destination it controls. The prerequisite is a still-running sandbox and its ID;
without CodeBuild list/read access, IDs can still be recovered from console URLs, earlier API/CLI
output, local shell history, CI artifacts, logs, EventBridge events, CloudTrail/SIEM copies,
screenshots, and support bundles.

The test sandbox was stopped and its live state reached `STOPPED`; the project, secret, inline
role policy, role, both IAM users, and all access keys were deleted. Exact project, secret, role,
and user lookups returned absent. CodeBuild retains the terminal sandbox record in its historical
inventory and exposes no delete-sandbox operation; the retained record is stopped and cannot run
commands.

### CodeConnections and agent-channel prerequisite review — 2026-09-08

`codeconnections:UseConnection` is a permissions-only authorization gate used by integrated
consumers; the current caller-facing CodeConnections API exposes no operation that returns its
installation token or private repository contents. The account contains five AVAILABLE real
GitHub/Bitbucket connections, which were deliberately not consumed or altered. Exploitation also
needs a consumer operation such as CodeBuild/CodePipeline create or update plus its service-role and
often `iam:PassRole` prerequisites. No standalone CodeConnections technique was promoted; impact
must be attributed to and tested through the actual consumer.

The current AWS CLI contains no `ec2messages` or `ssmmessages` service model, and Systems Manager
reported no managed nodes. The former is an agent message-delivery plane; the latter's control/data
channel operations require managed-node/session material such as the stream token issued by
`StartSession`. With neither a node nor token, ordinary IAM-user calls cannot reach an independent
channel target. Both prefixes are `blocked`, not negative, until an authorized managed-node fixture
can test stolen-token and cross-node controls.

SageMaker geospatial was reachable only in `us-west-2` during the regional check and contained no
Earth Observation jobs; `eu-west-1` returned a service/authorization-resolution error. Testing job
reads or exports requires a synthetic source collection, job, and execution role, so that prefix is
also retained as blocked rather than inferred safe.

### Amazon S3 Object Lambda (`s3-object-lambda`) — 2026-09-08

The Q16 access-point-policy self-grant hypothesis is blocked by service eligibility. The synthetic
fixture successfully created a private source bucket/object, supporting S3 access point, published
Lambda transformer version, and an execution role limited to `WriteGetObjectResponse`. AWS then
rejected `CreateAccessPointForObjectLambda` with the explicit statement that S3 Object Lambda is
available only to existing customers already using the service and selected APN partners. The
authorized account has no pre-existing Object Lambda access point.

No policy was set and no transformed read was attempted, so there is no positive or negative claim
about `PutObjectLambdaAccessPointPolicy`. The supporting access point, Lambda function/version,
execution role and policy, object and bucket were deleted. The failure occurred before disposable
reader users were created. Exact Object Lambda access-point, S3 access-point/bucket, Lambda, IAM
user/role inventories returned empty, and the local source and ZIP were removed.

### Amazon OpenSearch Service (`es`) — 2026-09-08

`es:UpdateDomainConfig` alone was validated as a domain resource-policy takeover. A synthetic
public HTTPS domain initially allowed only the lab administrator, which inserted a randomized
canary. The least-privilege test user had only `UpdateDomainConfig` on the exact domain ARN: a
signed data-plane request returned HTTP 403 before the change, `ListDomainNames` was denied, and an
empty-permission control could not update the domain. The test user then replaced the access policy
with one granting its own ARN only `es:ESHttpGet` on that domain's subresources. After processing
completed, the same signed request returned HTTP 200 and the exact canary.

The result requires a known domain name and a reachable endpoint; VPC placement, fine-grained
access control, explicit denies, and customer-managed KMS authorization can impose additional
boundaries. One preliminary harness failed on an empty Bash-array expansion before creating users
or a canary; that domain was also deleted. Both domains reached deletion, every test user, access
key, and policy was removed, and exact-prefix domain and user inventories returned empty.

The catalog's separate `opensearch` IAM prefix is for OpenSearch Applications, direct query, and
auto-optimize operations; it is not an alias for `es`. `ListApplications` returned empty in both
`eu-west-1` and `us-east-1`, so application login/query hypotheses remain blocked without a
disposable application. The validated managed-domain result is attributed only to `es`.

### Amazon EKS Auth (`eks-auth`) — 2026-09-08

`eks-auth:AssumeRoleForPodIdentity` was validated as a credential-access primitive when the caller
has a live Pod-bound EKS service-account token. The least-privilege IAM user had only that action
on `Resource: *`; it was denied EKS cluster listing and direct access to a synthetic S3 canary. An
empty-permission user could not exchange the same token, and changing one token character caused
`InvalidTokenException`. With the valid token, the candidate received the role associated with
the `proof/reader` service account and those temporary credentials read the exact canary.

The token prerequisite is material. A service-account-only token with the correct
`pods.eks.amazonaws.com` audience was rejected because it lacked the required
`kubernetes.io/pod` claim. The successful proof used a TokenRequest bound to a real, unscheduled
Pod object and therefore included the live Pod UID; no worker node or workload execution was
needed. The action does not let a caller choose an arbitrary role: EKS resolves the existing Pod
Identity association for the token's cluster, namespace, service account, and Pod binding.

The association, Pod/namespace, no-node cluster, bucket/object, cluster and pod roles, IAM users,
access keys, policies, generated cluster security group, and local kubeconfig were deleted. The
returned temporary credentials were never printed or persisted, and the only resource they could
read was deleted during cleanup. Exact-prefix cluster, role, user, and bucket inventories returned
empty.

### AWS Config (`config`) — 2026-09-08

The Q03 remediation hypothesis did not produce an independent escalation. A complete disposable
recorder and delivery channel evaluated a synthetic IAM user as `NON_COMPLIANT`; a custom SSM
Automation document stored a constant execution-role ARN whose only privilege was writing a proof
object. The candidate had exactly `config:PutRemediationConfigurations` and
`config:StartRemediationExecution`, while an empty-permission control was denied.

The candidate could configure the document and request manual remediation without
`iam:PassRole`, but Config reported `FAILED` at `Initialization`: the initiating user lacked the
necessary Systems Manager and resource permissions. No SSM Automation execution existed and no
proof object was written. The account initially lacked `AWSServiceRoleForConfigRemediation`, so a
service-linked role was created before the final run; its presence did not remove the initiator
permission check. Adding direct SSM execution and resource authority would collapse the path into
the already documented `ssm:StartAutomationExecution` technique rather than make the Config pair a
separate primitive.

Two preliminary fixtures were also removed: one exposed that the managed rule keys IAM resources
by immutable `UserId`, and one hit access-key propagation before authorization. All Config rules,
recorders, delivery channels, documents, buckets, objects, prefixed roles/users, keys, and policies
were deleted. IAM service-linked-role deletion initially returned transient internal errors with an
empty usage list; a later deletion task reached `SUCCEEDED`, and `GetRole` returned `NoSuchEntity`.

### Amazon Redshift (`redshift`) and Data API (`redshift-data`) — 2026-09-09

Two provisioned-cluster credential actions were independently validated without discovery
permissions. One IAM user had exactly `redshift:GetClusterCredentials`; a second had exactly
`redshift:GetClusterCredentialsWithIAM`; both used `Resource: *` for the isolated authorization
test and both were denied `DescribeClusters`. Each API returned a temporary username/password,
and each credential set connected to the synthetic cluster over TLS and selected the randomized
canary. An empty-permission control was denied both credential calls. `DescribeClusters` is thus a
discovery convenience, not part of either minimum credential path; a known cluster ID, endpoint,
database, and applicable database-user privileges are the material prerequisites.

The same fixture rejected two Data API bypass hypotheses. A user with only
`redshift-data:GetStatementResult` supplied a valid completed statement UUID created by the lab
administrator, but the API returned `ResourceNotFoundException: Query does not exist`; the
empty-permission control was denied. Replacing that policy with exactly
`redshift-data:ExecuteStatement` plus `redshift-data:GetStatementResult` still could not submit the
query without underlying Redshift authentication authority. A provisioned-cluster Data API path
therefore also needs `redshift:GetClusterCredentials`/`GetClusterCredentialsWithIAM`, or a
secret-based path and its separate Secrets Manager authorization, so those impacts are not
attributed to the Data API actions alone.

The test used the region's smallest currently orderable single-node class, `ra3.large`; obsolete
`dc2.large`, zero-retention, and unencrypted create requests were rejected before provisioning and
their support resources were removed. Both completed clusters were deleted without final
snapshots. All automated/manual snapshots, subnet groups, ingress security groups, IAM users,
access keys, policies, and the temporary PostgreSQL driver directory were re-enumerated absent.

### Amazon RDS (`rds`) and IAM database authentication (`rds-db`) — 2026-09-09

`rds:ModifyDBInstance` alone was validated as a non-Aurora master-password takeover. The candidate
policy scoped the action to the exact synthetic DB ARN and did not grant any describe action; an
empty-permission control could not modify the instance. The mutation response itself returned the
endpoint, and after the immediate change completed the new caller-selected password connected to
PostgreSQL over TLS with AWS's published CA bundle and selected the exact canary. This path does
not apply when Secrets Manager manages the master password, and network reachability remains a
separate prerequisite.

`rds-db:connect` was independently validated against the exact
`arn:aws:rds-db:<region>:<account>:dbuser:<DbiResourceId>/iam_reader` resource. Both the candidate
and empty-permission control could locally generate syntactically valid signed authentication
tokens because token generation makes no service API call. The control's database authentication
failed, while the allowed principal connected over verified TLS as the IAM-enabled database user
and selected the canary. IAM database authentication, a live matching engine user with `rds_iam`,
its database grants, the exact endpoint/port/user, and network reachability are all required.

One preliminary instance was removed after the local operating-system trust store rejected the RDS
certificate chain before SQL or test-user creation. The successful rerun used AWS's official global
RDS CA bundle with hostname verification enabled. Both instances, subnet groups, ingress security
groups, IAM users, keys, policies, CA bundle, temporary PostgreSQL driver directories, automated
backups, and snapshots were deleted; exact inventories returned empty.

### Amazon FSx (`fsx`) — 2026-09-09

The authorized region contains no FSx filesystem and no FSx backup. Consequently the Q13
`CopyBackup`/`CreateFileSystemFromBackup` data-copy hypothesis cannot be given a source canary, and
the resource-policy and backup-principal-association paths have no existing object on which to
prove a boundary change. A conclusive data test would additionally require a protocol-compatible
client to mount the restored Windows, Lustre, OpenZFS, or ONTAP filesystem. No existing account
resource was touched, no synthetic FSx infrastructure was created, and no FSx impact is claimed.

### Initial P1 prerequisite batch — 2026-09-09

Ten P1 prefixes were reviewed without mutating existing resources. MWAA and MWAA Serverless
returned no environments or workflows in `eu-west-1` or `us-east-1`. OpenSearch Serverless had no
collections, data-access policies, or encryption policies. Compute Optimizer Automation returned
`OptInRequiredException` for both enrollment and rule inventory. AppIntegrations was unavailable in
`eu-west-1` and returned no applications, data integrations, or event integrations in
`us-east-1`. The current CLI has no App2Container or AgentAccess MCP model; the account also has no
WorkSpace/session or known App2Container job target.

Two existing Amplify applications were observed but deliberately not changed. Both returned empty
backend-environment inventories, leaving Amplify Admin token/backend operations and UI Builder
components, forms, themes, codegen jobs, and Studio-token operations without a test target. IAM
Access Analyzer returned no analyzers. A real management trail and existing policy-generation role
were not consumed; policy-generation behavior therefore remains blocked behind a separate
synthetic trail/role and pass-role validation rather than being inferred safe. These rows are
recorded as prerequisite blockers, not negative security conclusions.

### AWS Amplify Admin (`amplifybackend`) — 2026-09-10

A disposable Amplify app and Gen 1 backend enabled the previously blocked Studio-token tests.
An IAM principal restricted to exactly `amplify:GetApp` and `amplifybackend:CreateToken` received
a 36-character one-time challenge and 36-character session ID with an approximately two-minute
expiry. `CreateToken` alone and `CreateToken` plus `amplify:GetBackendEnvironment` both returned
the deliberately opaque `Invalid appId` response, while an empty-permission control was denied.
Inspection of the deployed Amplify Studio client confirmed that its login URL consumes `appId`,
`backendEnvironmentName`, `code`, and `sessionId`, then submits the challenge through Cognito's
custom-auth flow as the fixed `aws-amplify-admin` user. The pair is therefore a High application-
administration credential path, rather than a harmless token-metadata read.

A second exact-action principal holding `amplify:GetApp` and `amplifybackend:GetToken` recovered
the same challenge for an administrator-seeded token when supplied with its exact live session ID.
This path is conditional credential recovery rather than enumeration. CloudTrail records the app
ID but redacts both `sessionId` and `challengeCode` as `***`; permissionless session-ID fallbacks
include Studio URLs and browser history/devtools, copied commands, support captures, proxy telemetry,
and application logs. App IDs remain recoverable from public Amplify hostnames and frontend/build
configuration without `ListApps`. All disposable apps, backends, tokens, IAM users, access keys, and
policies used by the validation were removed and the exact app inventory returned empty.

### Amazon Athena (`athena`) — Spark-session takeovers, 2026-09-10

A disposable PySpark workgroup, notebook, running notebook session, S3 output bucket, execution
role, and Secrets Manager canary were used to test `CreatePresignedNotebookUrl`. An IAM user holding
exactly that action on `Resource: *` minted a URL containing the notebook `authToken`; an otherwise
identical empty-permission user was denied. The bearer URL returned HTTP 200 and opened the real
Jupyter notebook in a headless browser with no AWS credentials. The browser submitted arbitrary
Python calculations, and the service executed them under the existing notebook execution role.
The URL-minting user required neither `StartCalculationExecution` nor `iam:PassRole`.

A separate normal Spark session validated the direct API path. An exact-action user holding only
`athena:StartCalculationExecution` submitted inline Python to the administrator-created session.
The calculation completed and recovered a real `ASIA...` execution-role access-key ID, secret-key
length, session-token length, and one-way secret-key fingerprint. The empty control was denied.
The candidate did not have `StartSession`, `GetSession`, direct role access, or `iam:PassRole`, and
`GetCalculationExecution` was used only by the administrator to verify the already executed result.

This path requires a known, live notebook-session ID and is Critical when the session's execution
role can reach privileged APIs or sensitive data. A normal programmatic Spark session is not enough:
the API returned `Invalid Request` until a notebook-backed session was created. `ListSessions` is
only a discovery convenience; session IDs appear in notebook URLs, browser history/devtools,
screenshots and support artifacts, CLI output, shell history, application/orchestration logs, and
CloudTrail/SIEM copies. The generated URL is a roughly ten-minute credential. Every synthetic
session, calculation, notebook/workgroup resource, object, bucket, secret, role policy, IAM user,
and access key was removed after the test.

### AWS Glue (`glue`) — interactive-session role takeover, 2026-09-10

A disposable Glue 4.0 interactive session used an execution role restricted to reading one
Secrets Manager canary. An IAM user holding exactly `glue:RunStatement` on `Resource: *` submitted
inline Python to the ready session; the statement reached `AVAILABLE` and returned the exact
canary. An empty-permission control was denied. The candidate had no `CreateSession`, `GetSession`,
direct Secrets Manager permission, or `iam:PassRole`, so `RunStatement` is a standalone
Critical role-takeover primitive when it reaches a session backed by a privileged execution role.

`ListSessions` is only a discovery convenience. Session IDs can appear in notebook and console
URLs, local notebook metadata, browser artifacts, CLI output, shell history, CloudWatch and
application/orchestration logs, screenshots and support bundles, and CloudTrail/SIEM copies. The
session, statement, secret, execution role and inline policy, both IAM users, and both access keys
were deleted; exact Glue, Secrets Manager, and IAM lookups confirmed the test resources absent.

### Amazon Managed Service for Prometheus (`aps`) — 2026-09-09

`aps:PutResourcePolicy` alone was validated as a workspace-policy self-grant. A disposable AMP
workspace contained a recording rule whose constant vector exposed the exact value `42009`. The
candidate IAM user had only `PutResourcePolicy` on the exact workspace ARN, was denied
`ListWorkspaces`, and received HTTP 403 from a SigV4 Prometheus query before the change. An
empty-permission user was denied the same syntactically valid policy update. The candidate then
replaced the workspace policy with an exact-principal grant of only `aps:QueryMetrics`; its same
signed request returned HTTP 200 and the canary value.

This needs a known workspace ID/ARN and a reachable Prometheus endpoint. Other desired capabilities
must be explicitly included in the resource policy, and organization policies or explicit denies
can still block the path. The current AMP API has separate create and put operations for rule-group
namespaces; an initial harness using the now update-only put operation was deleted before users
were created. The successful rule namespace, resource policy, workspace, users, access keys,
identity policy, and local rule file were removed; exact workspace and user inventories returned
empty.

### P1 application, recovery, and governance prerequisites — 2026-09-09

Application Auto Scaling returned no targets across eleven common service namespaces. App Runner
returned no services, source connections, or VPC connectors; Application Insights returned no
applications; ARC Zonal Shift returned no managed resources or shifts. Audit Manager reported
`INACTIVE` and rejected assessment/report inventory until account setup. Backup Gateway returned no
gateway, hypervisor, or virtual machine; Backup Search returned no search or export jobs. These
execution, configuration, and data paths remain blocked on their respective service targets.

The current CLI exposes no Application Signals MCP, Application Transformation, Mainframe
Application Testing, Arsenal, or Backup storage model, and the account has no external session,
agent, assessment, deployment, test-run, job, or capsule identifier for their protocol actions.
Marketplace Management is portal-only and operates on real seller banking/verification state, so
it was not mutated without a disposable seller account. AWS Artifact's report catalog was
enumerated without downloading a report: it exposed AWS-managed compliance documents but no
credential, execution, delegation, or customer-workload path, so it is recorded
`no_new_positive`; report and agreement content can still be contract-sensitive.

Application Signals had real service observations, so two exact-action identities were tested on
a known service key. `GetService` alone and `ListServiceOperations` alone were accepted but returned
zero service keys, attribute maps, metric references, and operations, while the administrator saw
3, 2, 3, and 5 respectively for the same target and time window. Both identities were denied
`ListServices`, and empty-permission controls were denied the exact calls. This shows that the
service actions alone do not expose the telemetry; underlying CloudWatch/X-Ray/observability
authority remains material. No standalone read was promoted, and every test user, key, and policy
was removed.

`cloudwatch:GetDashboard` was independently validated on an exact synthetic dashboard ARN. The
candidate was denied `ListDashboards`, and an empty-permission control was denied the known-name
read. The allowed response returned the exact text-widget canary from the nested dashboard body.
Dashboard JSON can expose metric queries, alarm/resource identifiers, regions/accounts,
operational links, runbooks, and operator-pasted text; the name can be recovered from IaC,
deployment output, bookmarks, logs, errors, or console URLs without list permission. The
dashboard, users, access keys, and policy were deleted and exact inventories were empty.

### AWS Budgets (`budgets`) — 2026-09-09

The IAM action name does not mirror the API operation: `budgets:ViewBudget` alone authorized
`DescribeBudget` for an exact synthetic budget ARN. The response returned the randomized budget
name and its distinctive USD `42009` limit. The candidate was denied `DescribeBudgets`, while an
empty-permission control was denied the same known-name `DescribeBudget` request. This read can
expose configured limits, filters, actual and forecast spend, health, time periods, and action or
notification context; it does not by itself modify the budget or execute a budget action.

The budget had no notification, subscriber, or action. It was deleted together with both test
users, access keys, and the inline policy, and exact name lookups for the budget and users returned
not found. The account's pre-existing `Cost Budget` was deliberately not read or changed.

### AWS Billing and Billing Console (`billing`, `aws-portal`) — 2026-09-09

`aws-portal:ViewBilling` alone was validated as a sensitive credit-record disclosure through the
current Billing `GetCredits` API. The response contained a real record with credit identifiers,
type, monetary balances, applicable products, dates, sharing state, and status. The harness asserted
record presence and field names but did not print or persist any value. The candidate was denied
`billing:ListBillingViews`, and an empty-permission identity was denied the same credits request.

An independent identity with only the apparently narrower `billing:GetCredits` action was also
denied: the response named missing `aws-portal:ViewBilling`. Conversely, the legacy Billing Console
permission needed no `billing:GetCredits` grant to return the record. Therefore the observed impact
is attributed only to `aws-portal:ViewBilling`; the `billing` prefix is `no_new_positive` for this
hypothesis. Four disposable users, their access keys, and inline policies were deleted and exact
user lookups returned not found. Existing billing views, preferences, credits, and account data
were read-only and were not modified.

### AWS Marketplace agreements (`aws-marketplace`) — 2026-09-09

Three agreement reads were independently validated against the account's existing buyer
agreements. `SearchAgreements` alone returned non-empty agreement summaries;
`DescribeAgreement` alone returned metadata for a known agreement ID; and `GetAgreementTerms`
alone returned accepted term content. These surfaces can reveal vendor relationships, buyer and
seller account IDs, product/offer identifiers, contract dates and renewal state, negotiated
pricing dimensions, quantities, and legal terms. A caller does not need
`aws-marketplace:ViewSubscriptions` for these API calls despite current operation-mapping tables
showing it as an additional authorization action.

Each permission was placed in its own disposable assumed role. The roles carrying either a
different Marketplace action or no action were denied the target request, establishing that the
three permissions are independent rather than a bundle. The harness logged only booleans, error
codes, and content presence: it did not print or persist agreement IDs, parties, products, prices,
or terms. No Marketplace agreement, subscription, product, offer, payment, cancellation, or seller
state was changed. All eight matrix roles and inline policies were deleted; exact role lookups
returned not found. Seller catalog inventories for AMI, container, SaaS, data, and offer entities
were empty.

### Billing exports and service prerequisites — 2026-09-09

Billing and Cost Management Data Exports returned zero configured exports and seven AWS-provided
table schemas; legacy Cost and Usage Reports returned zero report definitions. Both create paths
need a destination bucket policy, and AWS documents that initial report delivery can take up to 24
hours. Because an accepted create call would not prove data access and waiting would leave an
asynchronous export beyond the bounded cleanup window, `bcm-data-exports` and `cur` remain blocked
without a pre-existing disposable export. No export, report, bucket, or policy was created.

Cloud Directory rejected directory inventory in `eu-west-1`, `us-east-1`, and `us-west-2` because
the account is not authorized for the service in those Regions. Compute Optimizer reported
`Inactive` with no member enrollment; enabling its account-wide analysis was not treated as an
isolated test fixture. CodeGuru Security returned `FeatureNoLongerAvailableException` and stated
that the service is no longer supported. CodeCatalyst workspace inventory required a distinct
authorization token that the AWS profile does not have, and there is no known disposable space,
connection, or Identity Center application to test its separate IAM integration actions.

CloudTrail returned one pre-existing integration channel in each of the two queried Regions, but
zero CloudTrail Lake event data stores. The real channels were not used to inject synthetic audit
events. Creating the event store needed to prove `cloudtrail-data:PutAuditEvents` would leave that
store in AWS's mandatory seven-day `PENDING_DELETION` state, so this integrity-impact hypothesis is
blocked by the same-session destruction requirement. None of these prerequisite checks created or
changed infrastructure.

### Amazon ECR Public (`ecr-public`) — 2026-09-09

`ecr-public:SetRepositoryPolicy` alone was validated as a public-repository supply-chain takeover.
A disposable role scoped to the exact synthetic repository ARN was denied
`InitiateLayerUpload` before the change. An empty-permission role was denied the same
`SetRepositoryPolicy` request. The candidate then installed a policy granting only its own role
the four upload operations (`InitiateLayerUpload`, `UploadLayerPart`, `CompleteLayerUpload`, and
`PutImage`), uploaded an in-memory OCI config and tar/gzip layer containing a randomized canary,
and published that manifest as the mutable `stable` tag.

An administrator independently observed that `stable` resolved to the candidate-created manifest
digest and that both uploaded digests were `AVAILABLE`. Thus the impact was a real tagged-image
change, not merely an accepted policy request. Downstream CI, ECS, Kubernetes, or other consumers
that repull mutable tags could execute the substituted content with their workload identity. Tag
immutability, digest pinning, explicit denies, or consumers that never refresh the tag prevent this
specific path.

Two earlier attempts also reached the successful policy self-grant and tagged upload, but their
verification incorrectly used private ECR's unavailable `BatchGetImage` API and then an incomplete
anonymous Registry V2 request; both cleanup traps still succeeded. The final run used the native
ECR Public describe and layer-availability APIs. Every synthetic repository/image/layer, role, and
inline policy from all runs was force-deleted, exact prefix inventories were empty, and the
account's unrelated pre-existing public repository was not read or changed.

### AWS DataSync (`datasync`) — 2026-09-09

`datasync:StartTaskExecution` was validated as a delegated sensitive-data copy when an existing
task's destination is accessible to the caller. A synthetic S3-to-S3 task used a DataSync role
that could read a protected source canary and write to an initially empty destination. The
candidate had only `StartTaskExecution` on the exact task ARN and `s3:GetObject` on the destination
prefix: it had no source-bucket action, no `iam:PassRole`, and could not list DataSync tasks. A
destination-only control was denied when starting the same task.

The candidate started the unchanged task. After DataSync reported `SUCCESS`, its destination read
returned the exact source canary. This is a conditional high-impact combination rather than a
universal source selector: the task fixes its source, destination, and service role, and the caller
still needs a way to access the destination. Non-S3 locations may instead be reachable through
their native NFS, SMB, EFS, FSx, HDFS, or object-storage protocol.

Two preliminary fixtures were also removed after exposing S3's nonexistent-key anti-oracle and
normal IAM policy propagation. The successful task execution, task, both S3 locations, source and
destination objects/buckets, DataSync service role, candidate/control roles, and every inline
policy were deleted. Exact task, location, bucket, and role inventories returned empty.

Three adjacent data/security services had no safe data target. Database Query Metadata Service is
not present in the installed SDK or CLI and no Query Editor favorite, history, tab, or authenticated
console protocol object is known, so `GetQueryString` remains blocked rather than inferred.
Detective returned zero graphs in both primary Regions; enabling the account-wide graph would not
produce an immediate synthetic investigation dataset. Application Discovery Service likewise
returned zero agents in both Regions and has no external host or imported dataset from which to
prove configuration or network disclosure. None of these checks changed service state.

### Amazon Managed Grafana (`grafana`) — 2026-09-09

Two plaintext bearer-token operations were independently validated on the exact workspace ARN.
`grafana:CreateWorkspaceApiKey` let its role choose `ADMIN`, returned the key once, and that key
read the exact canary from a private dashboard over the workspace HTTP API. For current Grafana
versions, `grafana:CreateWorkspaceServiceAccountToken` alone minted a token for a known existing
admin service-account ID, and that token independently read the same dashboard. The latter action
does not create or elevate the service account: its existing Grafana role is therefore a material
prerequisite.

The empty-permission role was denied both token creations. The API-key candidate could not list
workspaces, and the service-account-token candidate could not list service accounts. A known
workspace ID/ARN is therefore required for both, and a known service-account ID for the newer path.
The current API also warns that legacy workspace API keys will be removed in favor of service
accounts, so both forms are recorded rather than treating the deprecated operation as complete
coverage.

The first workspace proved the API-key path with wildcard resource scope. A later combined run
attached both policies to the exact returned workspace ARN before its several-minute provisioning
phase, eliminating IAM propagation ambiguity and validating both paths with resource scoping. An
intermediate same-parameter create was rejected by idempotency before creating a workspace; another
run exposed the too-late policy attachment and cleaned up normally. All three created workspaces,
private dashboards, API keys, service account/token, customer-managed workspace roles,
candidate/control roles, and inline policies were deleted. Exact workspace and role inventories
returned empty; no Identity Center instance or service-linked role was created.

### Amazon Data Lifecycle Manager (`dlm`) — 2026-09-09

The previously listed singleton `dlm:CreateLifecyclePolicy` high-risk entry was not supported by
live authorization behavior and has been removed. A syntactically valid untagged snapshot-policy
request named a disposable DLM service role and targeted an unused synthetic tag. A role with only
`CreateLifecyclePolicy` was denied specifically for missing `iam:PassRole`; an empty-permission
control was denied for missing the DLM action. An earlier tagged request correctly stopped first on
the separate `dlm:TagResource` permission and created nothing.

No lifecycle policy or snapshot was created in either run. The service role and both candidate
roles, including their inline policies, were deleted and exact policy/role inventories were empty.
`CreateLifecyclePolicy` may still participate in a path when the caller also has pass-role authority
over a useful DLM role, but that is not a high-impact singleton and the accepted API configuration
alone would not prove snapshot access.

### AWS Data Exchange and Data Pipeline — 2026-09-09

AWS Data Exchange had zero datasets and zero jobs in both tested Regions. The official API
authorization matrix requires `dataexchange:GetAsset` in addition to `StartJob` for both S3 and
signed-URL asset exports. Jobs can be created, started, cancelled, and inspected, but the API has
no delete operation. A synthetic job would therefore leave history without testing an access
bypass, so no job or dataset was created and the service remains blocked pending a disposable
existing asset/job.

AWS Data Pipeline likewise returned zero pipelines in both Regions. It is unavailable to new
customers, so this account cannot safely validate the established create/define/activate plus
PassRole execution chain. No pipeline was created or modified. The existing documented path
remains applicable to grandfathered accounts, but this review does not upgrade it from literature
to live evidence.

### Amazon Data Firehose (`firehose`) — 2026-09-09

`firehose:UpdateDestination` was validated as a conditional live-stream exfiltration primitive.
A direct-put stream initially delivered to a private source bucket through a dedicated delivery
role. The exact-stream candidate submitted an `ExtendedS3DestinationUpdate` containing only a new
`BucketARN`; it deliberately omitted `RoleARN` and had no `iam:PassRole`. Firehose merged the
partial update, retained the existing role, and moved to a new active version pointing at the
replacement bucket. A destination-read-only control was denied the update.

After the update settled, the administrator wrote a unique private record to simulate the next
producer event. Firehose delivered it to the replacement bucket and the candidate's exact-object
read returned the canary. The candidate could not describe the stream and had no list permission;
the known stream name, version, and destination ID were supplied to the test. Exploitation requires
the retained delivery role's S3 policy and, for cross-account delivery, the replacement bucket
policy to authorize writes. A narrowly scoped role therefore prevents arbitrary redirection.

The stream and delivered object, both buckets, delivery role, candidate/control roles, and every
inline policy were deleted. Exact stream, bucket, and role inventories returned empty.

### AWS Database Migration Service (`dms`) — 2026-09-09

`dms:ModifyEndpoint` was validated as a conditional S3-target redirection primitive. A synthetic
full-load task connected a protected S3 source to an initially private S3 target through a DMS
service-access role. The exact-endpoint candidate submitted only a replacement `BucketName` and
`BucketFolder`. DMS retained the stored `ServiceAccessRoleArn`, accepted the update without
`iam:PassRole`, and automatically re-tested the modified endpoint successfully. A destination-read-
only control was denied the same update.

The administrator then started the already-created task to model its next legitimate execution.
DMS copied the one-row source dataset to the replacement bucket, and the candidate's exact-prefix
`s3:GetObject` recovered the private canary. The candidate had no source S3 permission, DMS list or
describe action, `dms:TestConnection`, `dms:StartReplicationTask`, or PassRole. This is not an
arbitrary-bucket primitive: the retained role must already authorize writes to the replacement
bucket, a cross-account bucket must trust that role, and the task must be stopped/ready for the
endpoint change and later started. A configured expected bucket owner can further constrain S3
destinations.

The first isolated endpoint-only run proved the partial update and cleaned an asynchronously
deleting endpoint. Four guarded end-to-end iterations then resolved the minimum classic-DMS
requirements: `dms.t3.small` was the smallest available class; DMS 3.4.7+ required public S3 egress
or a VPC endpoint; original connections had to test successfully; `TestConnection` authorizes both
endpoint and replication-instance ARNs; and `ModifyEndpoint` itself initiates the replacement
connection test. Every iteration deleted its task, endpoints/connections, instance, subnet group,
three buckets and contents, service/candidate/control roles, inline policies, and temporary
`dms-vpc-role`. Independent exact inventories returned empty.

### Amazon DocumentDB Elastic Clusters (`docdb-elastic`) — 2026-09-09

`docdb-elastic:UpdateCluster` was validated as a standalone administrator-credential takeover.
A one-shard `PLAIN_TEXT` elastic cluster stored a unique document through its original administrator
password. An empty-permission control was denied the password update. The candidate role held only
`UpdateCluster` on the exact cluster ARN and supplied the required `PLAIN_TEXT` authentication type
with a replacement administrator password. After the cluster returned to active, that password
opened a new TLS connection and read the exact protected canary. The candidate was denied
`GetCluster` and held no list or data-read IAM action.

The path requires a known cluster ARN, endpoint, administrator user name, VPC network reachability,
and a cluster using plain-text password authentication. It provides database-administrator access
to protected data and is therefore Critical. The request does not need the existing password, and
neither `GetCluster` nor list permission is an authorization prerequisite.

Five isolated iterations established the exact boundary. The first exposed a classic-CA versus
Elastic public-certificate mismatch; the second established direct `mongos` topology; the third
proved baseline access but showed that `UpdateCluster` requires `authType` alongside the password;
the fourth accepted the update but was stopped before broad cleanup could overlap a concurrent
fixture; and the locked final run completed the read. Every cluster, snapshot, service endpoint,
service-linked role, candidate/control role, and inline policy from all attempts was removed, and
the final exact inventories were empty.

### AWS Directory Service (`ds` and `ds-data`) — 2026-09-09

A fresh inventory queried all 32 Regions exposed by the Directory Service SDK. Every reachable
Region returned zero directories; disabled opt-in Regions returned authorization errors, and one
disabled endpoint timed out. There is consequently no existing AWS Managed Microsoft AD, Simple
AD, or AD Connector target on which to exercise either control-plane or Directory Service Data
mutations. Creating a managed multi-AZ directory solely for this review is not a small disposable
prerequisite.

The existing documented `ds:ResetUserPassword` path remains High because resetting a known
resettable directory user's password can take over that AD identity and any applications or AWS
console roles already assigned to it. Directory Service Data's `ResetUserPassword`,
`AddGroupMember`, `CreateUser`, and `UpdateUser` are also concrete candidates for credential or
group-based escalation, but their effect depends on Directory Service Data being enabled, known
user/group identifiers, and the directory's effective AD authorization. Those candidates remain
blocked rather than being promoted from API shape alone. No directory, user, group, password,
role, subnet, or security group was created or changed.

### Amazon ElastiCache (`elasticache`) — 2026-09-09

`elasticache:ModifyUser` was validated as a standalone conditional Redis RBAC credential-takeover
primitive. A minimal serverless Redis cache used a user group containing a disabled replacement
default user and one password-authenticated user with access to all keys and commands. From the
private VPC runner, unauthenticated access was denied and the original password stored a unique
canary. An empty-permission control was denied `ModifyUser`.

The candidate role had only `elasticache:ModifyUser` on the exact user ARN. It replaced that
user's password, waited for asynchronous propagation, then opened a new TLS connection with the
replacement credential and read the exact protected canary. The role was denied `DescribeUsers`
and had no cache describe/list action. Exploitation still requires a known user ID, an endpoint,
network reachability, and a target user whose existing access string authorizes useful keys and
commands; the action is therefore High rather than Critical.

The serverless cache and service-managed endpoint, user group, password user, disabled default
user, candidate/control roles, inline policy, and any attributable snapshot were deleted. Exact
inventories and endpoint deltas were empty after teardown.

### AWS Elastic Beanstalk (`elasticbeanstalk`) — 2026-09-09

An all-region inventory queried the 32 Regions exposed by the SDK and found zero live
environments. The only remaining application is an unrelated, empty `flask-tutorial2` shell from
the EB CLI in 2023; it has no version, configuration template, or environment and was preserved.
Without a live environment there is no workload or instance profile on which to validate
`UpdateEnvironment` environment-hook injection, application-version deployment, or role-credential
impact, so those paths remain blocked rather than inferred.

The audit did find a separate 2022 `MyApp` security-lab artifact in us-east-1 with six unprocessed
versions named after the documented Beanstalk privilege-escalation examples. It had no environment
or template, and its referenced source bucket was already absent. The exact application and all
six version records were deleted and polled until absent.

The legacy singleton High entry for `elasticbeanstalk:RebuildEnvironment` was removed. Rebuilding
an unchanged environment is an availability action; the existing documented compromise requires
separate control of the source bundle plus the permissions needed for Beanstalk, S3, EC2,
CloudFormation, and Auto Scaling orchestration. A duplicated `autoscaling:SuspendProcesses` token
in the multi-action legacy chain was also removed. No new attack entry or severity promotion was
made.

### Amazon EMR (`elasticmapreduce`) — 2026-09-09

An all-region review queried 34 SDK Regions and found zero active classic EMR clusters, Studios,
or notebook executions in every reachable Region. The current Botocore EMR model exposes no
legacy operation containing `Editor`. There is therefore no safe existing target on which to test
whether `AddJobFlowSteps` can execute an inline `command-runner.jar` step under a useful EC2
instance profile, or whether any legacy notebook flow remains reachable.

Two unsupported singleton severities were removed. `RunJobFlow` documents `iam:PassRole` as a
dependent action when selecting the EMR service role and EC2 instance profile, so it is not a
standalone High escalation primitive. `OpenEditorInConsole` was marked Critical in the legacy list
even though the existing documentation requires a compatible editor and surrounding editor
operations, and the current SDK no longer exposes that API family. Both now remain Medium in
isolation; contextual multi-permission chains can still be security-critical. No cluster, step,
role, Studio, notebook, EC2 instance, or network resource was created or changed.

### Amazon EMR on EKS (`emr-containers`) — 2026-09-09

An all-region inventory found zero virtual clusters and zero managed endpoints across the 27
Regions exposed by the EMR Containers SDK. A separate all-region EKS inventory found zero EKS
clusters across 34 SDK Regions. Creating the prerequisite would require a complete EKS cluster,
compatible managed-node or Karpenter capacity, namespace integration, private networking, load
balancer controller, execution role, and managed endpoint rather than a small isolated fixture.

AWS's current authorization reference explicitly lists `iam:PassRole` as a dependent action for
`StartJobRun`. `GetManagedEndpointSessionCredentials` remains a high-value future test: it returns
a token used to authenticate to a private Jupyter gateway, accepts an `executionRoleArn`, and does
not list PassRole as a dependent action. End-to-end testing must establish whether an exact-endpoint
caller can select a role broader than its own and whether kernels actually use that role. Without
an endpoint and data-plane connection, the token shape alone is not evidence of privilege
escalation, so no severity or HackTricks attack entry was added. No resource or role was created or
changed.

### Amazon GuardDuty (`guardduty`) — 2026-09-09

eu-west-1 contains one preserved detector created in 2023, but it is `DISABLED`, has zero findings,
and has zero associated members; us-east-1 has no detector. `GetFindings` can disclose detailed
security context when a finding ID is known, but this account has no such target. Creating sample
findings would leave finding history retained by the service for 90 days and would not satisfy the
same-session cleanup requirement.

The existing documentation already covers suspending monitoring, suppression filters, trusted-IP
sets, and publishing-destination deletion. Those actions are defense evasion or availability
changes, not standalone privilege escalation or sensitive-data access, so they were not promoted
to High/Critical. Enabling, deleting, or otherwise mutating the preserved detector merely to test
authorization would change a pre-existing security control. No detector, finding, filter, member,
IP set, threat-intelligence set, or publishing destination was created or changed.

### AWS Health (`health`) — 2026-09-09

The global us-east-1 Health endpoint rejected `DescribeEvents` with
`SubscriptionRequiredException`. The account lacks the support-plan prerequisite, so there is no
event ARN or affected-entity target on which to test incident-detail or resource-identifier
disclosure. Health incidents cannot be safely manufactured for the lab. No event, subscription,
role, or resource was created or changed, and the service remains blocked rather than classified
from response schemas.

### AWS Identity Sync and Identity Store Auth — 2026-09-09

IAM Identity Center still reports zero instances, and current Botocore exposes neither an
`identity-sync` nor `identitystore-auth` client. Identity Sync's authorization reference defines
profile, filter, target, start, and stop operations, but there is no identity source or target in
this account; creating a profile also depends on Directory Service authorization. That service is
blocked pending an existing synchronized identity environment.

Identity Store Auth is a firmer negative boundary: its official authorization reference states
that it has no directly invocable API operation. `BatchDeleteSession`, `BatchGetSession`, and
`ListSessions` are permission-only IAM actions for AWS-managed flows. Without a caller-facing API,
they do not provide a direct post-exploitation primitive merely because they appear in a policy.
The prefix is therefore `no_new_positive`. No instance, profile, target, filter, session, role, or
permission was created or changed.

### Amazon Inspector2 (`inspector2`) — 2026-09-09

The account reports Inspector as `DISABLED` for EC2, ECR, Lambda, Lambda code, and code-repository
scanning. `ListFindings` and `ListFilters` returned empty inventories, and CIS configuration
enumeration was rejected because the invoking account is not enabled. There is consequently no
finding, report, SBOM, scan, or suppression-rule target for a scoped permission test.

`CreateFindingsReport` remains a concrete sensitive-context exfiltration candidate because the
caller chooses the destination S3 bucket and KMS key, including suitably configured resources in
another account. A valid test still needs enabled Inspector and at least one private finding.
Enabling a security service solely for this review would create charges and scan/finding history
that cannot be erased in the same session, so the candidate remains blocked rather than promoted
from API shape or documentation alone. Filter, disable, and organization-configuration mutations
are defense evasion, not standalone privilege escalation or access to protected workload data, and
therefore do not meet this campaign's High/Critical criterion. No Inspector setting or resource was
created or changed.

### Retired IoT Analytics, IoT Events, and Fleet Hub services — 2026-09-09

AWS's current General Reference lists all three services in full shutdown: AWS IoT Analytics since
15 December 2025, Fleet Hub for AWS IoT Device Management since 18 October 2025, and AWS IoT
Events since 20 May 2026. A full shutdown means the service is removed from the AWS portfolio and
is unavailable in any capacity.

Current calls corroborate that boundary. IoT Analytics `ListChannels` could not connect to either
the eu-west-1 or us-east-1 service endpoint, IoT Events `ListDetectorModels` could not connect to
its eu-west-1 endpoint, and the current AWS CLI/Botocore distribution no longer exposes an
`iotfleethub` client. Historical permissions such as IoT Analytics `GetDatasetContent` and
`SampleChannelData`, IoT Events detector/input mutations, and Fleet Hub application management
cannot now reach a service resource. The three prefixes are `no_new_positive`; no legacy
resource, setting, role, or endpoint was created or changed.

### AWS IoT FleetWise (`iotfleetwise`) — 2026-09-09

The current SDK advertises FleetWise only in ap-south-1, eu-central-1, and us-east-1.
`GetRegisterAccountStatus` was rejected by the service with `AccessDeniedException` in all three
Regions even for the lab administrator. The account is therefore not registered and provides no
signal catalog, model or decoder manifest, vehicle, fleet, campaign, or edge-agent data path.

Creating or approving a campaign that routes existing vehicle signals to an attacker-readable
destination remains a concrete future data-exfiltration hypothesis. A meaningful validation
requires a registered account, the complete model/decoder/signal hierarchy, a fleet with a real
vehicle or Edge agent, and generated private telemetry. Those prerequisites cannot be inferred
from campaign request fields or safely synthesized through an account rejected by the service.
No account setting, campaign, vehicle, fleet, IAM role, or destination was created or changed.

### AWS IoT Managed Integrations (`iotmanagedintegrations`) — 2026-09-09

The reachable eu-west-1 endpoint returned zero customer managed things, cloud-connector
destinations, credential lockers, custom destinations, endpoints, provisioning profiles, device
discoveries, account associations, OTA tasks/configurations, notifications, event-log
configurations, or hub configuration. The only listed cloud connector is AWS's catalog entry for
TP-Link, and default encryption is AWS managed.

`CreateProvisioningProfile` is superficially credential-like: it returns a claim certificate and
private key. AWS documents those materials as inputs for onboarding a new device, however; they do
not authenticate as an existing managed thing or expose its state. A custom endpoint and
subsequent device provisioning are still required. Existing-thing `GetManagedThingState`,
`GetManagedThingCertificate`, `SendManagedThingCommand`, and connector association/token-refresh
paths have no target in this account. Creating an unowned physical-device ecosystem would not
validate compromise of existing data or privilege, so the service remains blocked and nothing was
created or changed.

### Amazon MemoryDB (`memorydb`) — 2026-09-09

`memorydb:UpdateUser` was validated as a standalone conditional ACL-user credential-takeover
primitive. A one-node, zero-replica TLS cluster used a custom ACL containing only one
password-authenticated user with full key and command access. Unauthenticated access was rejected,
and the original password stored and read a unique canary. An empty-permission role was denied the
password update.

The candidate role held only `UpdateUser` on the exact user ARN. It replaced the user's complete
password set, was independently denied `DescribeUsers`, and waited for the user to return to
`active`. The replacement password then opened a fresh verified-TLS connection and read the exact
protected canary. No MemoryDB list/describe permission, existing password, cluster-control
permission, or IAM pass-role permission was used.

The impact is constrained by the target user's existing access string and still requires a known
user name, endpoint, network reachability, and a useful attached ACL. It is therefore High rather
than Critical. The first calibration cluster exposed only an SSH quoting error before the data
plane was contacted; it was completely deleted. The successful cluster, ACL, user, subnet group,
candidate/control roles and policy, service endpoint, snapshots, and newly created service-linked
role were also deleted. Final exact-prefix inventories returned zero.

### Amazon MSK control and data planes (`kafka`, `kafka-cluster`) — 2026-09-09

Two isolated Provisioned MSK clusters established both permission boundaries. On the IAM-authenticated
TLS data plane, a full-control fixture role created an exact private topic and produced a unique
canary. An empty role consumed nothing. A second role with only `kafka-cluster:Connect` on the exact
cluster, `DescribeTopic` and `ReadData` on the exact topic, plus `DescribeGroup` and `AlterGroup` on
the exact consumer group consumed that canary. It was independently denied
`kafka:DescribeClusterV2`. This standard consumer combination is High because it directly reads
protected stream data, conditional on known brokers/topic/group and network reachability.

The control-plane candidate held only `kafka:UpdateSecurity` on the exact cluster and was denied
`DescribeClusterV2`. Given the known ARN and current version, it enabled unauthenticated access
without any `kafka-cluster:*`, KMS, list, or describe permission. IAM auth remained enabled. After
the cluster returned to `ACTIVE`, AWS returned its unauthenticated TLS bootstrap brokers and a fresh
client with no AWS credentials consumed the exact protected canary. This is Critical because the
single control-plane action removed the IAM authentication/authorization boundary for any client
with a private network path to a topic whose Kafka ACL posture allows anonymous access. Explicit
Kafka ACLs may still deny that principal, and the update does not make a private cluster
Internet-reachable.

The first cluster was a calibration run: its security update was rejected before mutation because
the request unnecessarily resubmitted immutable inter-broker encryption. CloudTrail confirmed that
exact `BadRequestException`; the corrected request omitted the field and succeeded. Both clusters,
topics, brokers, roles, inline policies, and newly created Kafka service-linked roles were deleted.
Exact-prefix cluster and IAM inventories returned zero.

### Amazon Machine Learning (`machinelearning`) — 2026-09-09

The legacy Amazon ML endpoint in us-east-1 rejected `DescribeDataSources`, `DescribeMLModels`,
`DescribeEvaluations`, and `DescribeBatchPredictions` with its service-level “no longer
available to new customers” response, even for the lab administrator. This account cannot create
or access an Amazon ML target.

The remaining API model exposes data sources, models, prediction endpoints, evaluations, and batch
prediction jobs, but no standalone operation that returns a credential, assumes an existing
identity, changes a resource policy, or executes code under a selectable privileged role. A
prediction against attacker-provided input is not access to protected training data. The row is
blocked on service eligibility rather than promoted from legacy API names; nothing was created or
changed.

### Amazon Macie (`macie2`) — 2026-09-09

Macie is disabled in both eu-west-1 and us-east-1. `GetMacieSession`, `ListFindings`, and
`ListClassificationJobs` all returned the explicit not-enabled boundary. Detailed finding and
sensitive-data-occurrence operations require a real finding, and reveal configuration can add a
separate role dependency.

Enabling Macie merely to manufacture a target would start billable security discovery and leave
scan/finding history that cannot be erased in the same session. Configuration, suppression, and
disable actions are defense evasion rather than direct privilege or protected-data access. The
sensitive-occurrence hypothesis remains blocked; no session, job, finding, bucket classification,
IAM role, or setting was created or changed.

### AWS Marketplace Commerce Analytics (`marketplacecommerceanalytics`) — 2026-09-09

Commerce Analytics is a seller-only service whose `GenerateDataSet` operation can deliver
confidential usage, subscriber, billing, tax, and disbursement datasets to a requested S3 bucket
through a previously enrolled Marketplace role, then notify SNS. The authorization reference does
not expose a resource scope or service-specific condition key, making this a strong data
exfiltration candidate in a seller account.

This lab has no role trusted to Marketplace's documented account `452565589796`, no
marketplace/commerce destination bucket, no seller-report SNS topic, and no seller dataset.
Creating a role, bucket, and topic cannot manufacture the missing victim seller enrollment or
private commerce records. `StartSupportDataExport` has the same target prerequisite. Both remain
blocked rather than being called with fake destinations that could leave an undeletable
asynchronous request. No Marketplace, IAM, S3, or SNS state was changed.

### AWS Elemental MediaConvert (`mediaconvert`) — 2026-09-09

An all-region inventory covered the 17 enabled Regions supported by the current MediaConvert SDK
and found zero customer jobs, queues, job templates, presets, or account resource policies.
`CreateJob` is the execution and data-movement operation: its request chooses input/output
locations and a service role, and AWS's current authorization mapping explicitly requires
`iam:PassRole`. Job templates deliberately do not store the role.

Creating or updating a template, preset, queue, or resource policy therefore cannot by itself make
MediaConvert read protected S3 input, write an attacker destination, or act with an existing role.
Read operations expose configuration and paths rather than the media objects. No standalone
credential, privilege, or protected-data primitive remains, so the prefix is
`no_new_positive`; nothing was created or changed.

### AWS Elemental MediaStore (`mediastore`) — 2026-09-09

AWS lists MediaStore in full shutdown since 12 November 2025. Current `ListContainers` calls in
eu-west-1 and us-east-1 return empty inventories, and full-shutdown services are no longer
available in any capacity. Historical object/container-policy operations have no reachable
resource. The generic `PutMetricPolicy` match remains an operational Low action, not a privilege
boundary. The prefix is `no_new_positive`; nothing was created or changed.

### AWS Elemental MediaTailor (`mediatailor`) — 2026-09-09

An all-region inventory across 15 enabled supported Regions found zero playback configurations,
source locations, or channels. The current public API and service-authorization reference expose
no operation named `GetSecretsManagerAccessToken`, despite that permission-shaped name appearing
in some generated policy catalogs.

MediaTailor source locations can be configured to use a Secrets Manager access token, but the
service—not the API caller—retrieves that separately authorized secret and sends it as an origin
HTTP header. The workflow needs a secret resource policy, a customer KMS key/grant, and source
content; it does not return the secret to a caller holding only a MediaTailor permission. Channel
policies and schedule mutations affect media delivery but do not independently grant AWS
privilege or protected source access. The prefix is `no_new_positive`; nothing was created or
changed.

### AWS Application Migration Service (`mgn`) — 2026-09-09

Every one of the 18 enabled Regions supported by the current MGN SDK returned
`UninitializedAccountException` for source-server, application, wave, and import inventories.
There is no replication agent, source server, launch configuration/template, staging area,
application, or wave.

`StartTest`, `StartCutover`, launch-configuration mutation, and injected post-launch actions are
valuable future hypotheses because an initialized migration can cause EC2 and SSM to act through
existing MGN roles. A valid privilege result requires a replicated victim source, its derived
launch template, a useful target instance profile, and proof of resulting code execution or
credential access. Initializing the service alone creates account-wide roles and staging
infrastructure but cannot manufacture that victim boundary. The row remains blocked; nothing was
created or changed.

### Amazon Mobile Analytics (`mobileanalytics`) — 2026-09-09

AWS discontinued Amazon Mobile Analytics on 30 April 2018 and moved its functionality to Amazon
Pinpoint. The legacy `PutEvents` REST path was redirected to Pinpoint for existing clients, while
the querying API disappeared. Current Botocore no longer includes a `mobileanalytics` client.

The legacy IAM prefix therefore has no caller-facing read, credential-return, resource-policy, or
identity operation. Event ingestion is telemetry integrity, not privilege or protected-data
access, and is now owned by the replacement service. The prefix is `no_new_positive`; nothing was
created or changed.

### AWS networking observability and control services — 2026-09-09

An all-region inventory across all 18 enabled Regions found zero AWS Network Firewall firewalls,
policies, rule groups, TLS inspection configurations, analysis reports, or flow operations; zero
Network Flow Monitor scopes or monitors; zero CloudWatch Network Monitor monitors or probes; and
zero OAM sinks or links. The Network Flow Monitor endpoint advertised for eu-south-2 was the sole
unreachable endpoint. Global Network Manager in us-west-2 likewise has zero global/core networks,
attachments, connect peers, or peerings, and organization service access is disabled.

Several specific hypotheses remain blocked on real victim targets. Network Firewall
`StartFlowCapture` exposes flow tuples rather than packet contents, while analysis reports can
disclose observed HTTP host and TLS SNI domains. Network Flow Monitor contributor/insight queries
can disclose workload and traffic metadata. Network Manager peer, attachment, policy, and routing
operations could redirect connectivity only in an existing core network. Creating idle synthetic
resources would not prove access to protected traffic, and enabling organization-wide integration
would exceed isolated scope.

OAM `CreateLink` is the strongest untested cross-account candidate: a source-account caller may
export logs, metrics, or traces into a separately controlled monitoring-account sink whose policy
accepts the source. This lab has no second controlled account or pre-existing sink, and a
same-account link is not evidence for that boundary. The candidate therefore remains blocked
rather than promoted from its request schema. No network, firewall, monitor, sink, link, policy,
route, telemetry source, organization setting, or role was created or changed.

CloudWatch Network Monitor operations expose reachability measurements and endpoint metadata, not
packet payloads or identities, so no standalone High/Critical primitive was found. Network Manager
Chat has no current Botocore client and its official action set only manages AWS-console chat
conversations/messages. Shield network security director likewise has no current client and only
offers posture finding/resource/insight/remediation reads plus finding-status updates. The latter
may reveal security context or support defense evasion, but neither prefix returns workload data,
credentials, or privilege. These three rows are `no_new_positive`.

### Database, legacy, and application-platform batch — 2026-09-09

Oracle Database@AWS rejected onboarding and inventory calls in eu-west-1, eu-central-1, us-east-1,
and us-west-2 because this account is not enrolled. Database-node control and IAM-role association
remain target-dependent candidates, but require Marketplace/OCI onboarding, a network, and an
existing database. All 18 enabled Regions contained zero Aurora clusters, so RDS Data API direct
SQL cannot be tested against protected data. Redshift Serverless likewise has zero namespaces,
workgroups, snapshots, or recovery points across all enabled supported Regions. Credential/token,
SQL, restore, and policy hypotheses for those three prefixes remain blocked, and no empty database
was created merely to restate its intended access behavior.

The current SDK no longer exposes clients for OpsWorks Stacks, OpsWorks Configuration Management,
or Private Networks. Their legacy IAM prefixes have no current reachable target, so each is
`no_new_positive`. Polly has zero lexicons in all supported enabled Regions. One completed
synthetic task record remains in us-east-1, but its destination bucket is already absent, task
metadata only contains the dead output URI, and Polly exposes no API to erase completed task
history. Synthesis processes caller-provided text and depends on explicit S3 write access for
asynchronous output; no privilege, identity, secret, or protected-input primitive was found.

Private CA Connector for AD has zero connectors and directory registrations in the three checked
service Regions. Template and group-access-control mutation could become an AD certificate logon
escalation against an existing managed directory/CA/template/principal, but those targets are
absent and a disposable Private CA cannot be permanently deleted in-session. Proton has zero
environments, services, components, repositories, and provisioning-role settings in every enabled
supported Region. Its component/service update paths remain candidates only where an existing
deployment reuses a useful provisioning role. Both services remain blocked without manufacturing
the victim boundary.

Q Business has zero applications in every reachable service Region, so Q Apps has no backing
instance, app, library item, document, or session. Corpus search/document reads, Q Apps session
exports, plugin actions, and data-accessor token paths remain concrete protected-content candidates
but cannot be classified from schemas without a real application and identity context. QuickSight
is unsubscribed in every enabled supported Region: account/namespace/user calls report no tenant
and data source/dataset inventories are empty. Subscribing would create a billable persistent
tenant without victim content. These three services remain blocked and unchanged.

Resource Explorer has six preserved local indexes and default views. Its `Search` operation is a
valuable resource-discovery fallback, but the result is indexed resource identity/metadata rather
than workload payload, credential, or assumable role; mutation of indexes/views does not grant
access to a result. No new High/Critical post-exploitation primitive was found, and none of the
pre-existing indexes or views was changed.

### Security, messaging, and workflow batch — 2026-09-09

Security Incident Response is inactive and has no case or attachment; Shield Advanced is inactive
and has no protection or attack; Security Hub is unsubscribed in all 18 enabled Regions; and
Security Lake rejects inventory because this account is not enabled. The important future targets
remain case-attachment download, Shield attack/DRT context, Security Hub finding disclosure, and
especially Security Lake `CreateSubscriber` as a possible cross-account export of an existing
victim lake. None can be promoted without real protected content and, for Security Lake, a second
controlled subscriber account. Enabling paid security products would leave retained state and
cannot manufacture victim data, so no setting was changed.

The current SDK exposes neither SageMaker data science assistant nor Security Agent as a public
client, and the lab has no Studio assistant session, managed agent, repository, assessment, or
finding target. Both remain blocked rather than inferred from console/preview permission names.
Serverless Application Repository has zero account-owned applications in every enabled supported
Region. Private template retrieval or policy self-grant needs an existing private app, while an
actual deployment crosses separate CloudFormation/IAM authorization boundaries. No repository
application or stack was created.

Current SMS/Voice inventories contain zero phone numbers, pools, configuration sets, registrations,
or legacy voice configurations. Send/configuration operations support spend or messaging abuse but
do not return protected messages, credentials, or an identity; the prefix is `no_new_positive`.
End User Messaging Social has zero linked WhatsApp accounts, leaving message-media reads and
impersonating sends blocked on real account/content identifiers. Snowball has zero jobs; unlock-code
and manifest access remains a sensitive device-data candidate, but requires an actual job/device
and physical or network access. No messaging or Snowball resource was created.

IAM Identity Center still has zero instances, so OIDC token endpoints have no registered client,
grant, user authorization, or target account. AWS Support rejects case inventory because Premium
Support is absent, leaving real case attachments unavailable. SWF has zero registered domains in
all enabled supported Regions; activity/decision polling could reveal workflow input and task
tokens, but its domains can only be deprecated rather than deleted immediately, preventing a
clean disposable test. These rows remain blocked.

WorkSpaces Thin Client has zero environments/devices across all seven enabled supported Regions;
its appliance configuration does not expose a workspace credential or session and is
`no_new_positive`. Timestream for LiveAnalytics rejects this account because only existing
customers can access it, leaving direct `Select` and scheduled-query role-reuse hypotheses blocked.
Timestream for InfluxDB has zero instances/clusters and no caller-facing query or password-return
operation, so its control-plane mutations are `no_new_positive`. Telco Network Builder explicitly
returns that the deprecated service blocks every API operation. Trusted Advisor is unavailable at
this support level and its recommendations/lifecycle state expose context rather than privilege or
workload payload. No resource or setting in this batch was created or changed.

### Authorization, collaboration, and traffic-policy batch — 2026-09-09

Verified Permissions has zero policy stores in all 18 enabled Regions. Policy/schema mutation only
changes an application's authorization when a real application delegates decisions to that store;
the service returns decisions rather than AWS credentials. VPC Lattice has zero services, service
networks, target groups, resource configurations, or gateways in every enabled supported Region.
Its auth/resource-policy and association operations remain important boundary-changing candidates,
but need a protected, reachable backend and a successful data-plane proof. Both rows remain blocked
and no synthetic topology was created.

WAF has zero regional web ACLs, API keys, rule groups, or IP sets. Its mutations provide traffic
control/defense evasion rather than AWS privilege or backend-data access; decrypted mobile client
keys are integration material, not backend authorization credentials. WorkSpaces Application
Manager has no current SDK client, and WorkSpaces Managed Instances has zero instances/volumes;
its create path crosses explicit IAM/EC2 provisioning boundaries. These three prefixes are
`no_new_positive`.

Wickr has zero networks. OIDC/user/device mutations require an existing Wickr tenant and identity
flow before an impersonation claim can be tested. WorkDocs has no active site, organization,
document, or user target and is closed to new setup, leaving direct document-version download
blocked on an existing customer. WorkMail lists only a preserved organization tombstone already in
`Deleted` state; every user, impersonation-role, token, and export inventory rejects it as inactive.
`ResetPassword`, `AssumeImpersonationRole`, mailbox export, and Message Flow
`GetRawMessageContent` remain high-value takeover/data candidates against a live organization, but
creating a paid directory-backed tenant would persist state without victim mail. Nothing was
created or changed.

X-Ray contains zero trace summaries in the last six hours across every enabled supported Region.
Trace and insight retrieval can disclose URLs, annotations, errors, and service topology, but a
synthetic trace cannot be deleted before service retention expires. No retained trace was injected
solely to prove the intended read API, so the row remains blocked.

### CloudWatch Synthetics (`synthetics`) — 2026-09-09

The lab initially contained zero canaries. A disposable canary was created with an execution role
that could write to one exact S3 bucket and call `organizations:DescribeOrganization`. The
candidate role was denied `synthetics:GetCanary`, direct S3 writes, direct Organizations access,
and direct Lambda code updates; an empty role was denied the dry-run action.

`synthetics:StartCanaryDryRun` alone accepted the request but failed asynchronously. One-action-at-
a-time CloudTrail calibration found that replacement code is installed through the generated
Lambda in the caller's authorization context. The exact successful permission chain was
`synthetics:StartCanaryDryRun`, `lambda:GetFunctionConfiguration`,
`lambda:PublishLayerVersion`, `lambda:GetLayerVersion` on both the AWS runtime layer and generated
code layer, `lambda:UpdateFunctionConfiguration`, `lambda:PublishVersion`,
`lambda:AddPermission`, and `iam:PassRole` on the existing execution role. The constrained final
run passed and wrote proof containing that execution-role ARN and the protected organization
identifier. It did not require `lambda:InvokeFunction` in the caller policy because
`AddPermission` authorized the Synthetics service on the generated function version.

`UpdateCanary` was tested separately. It also accepted replacement code with the Synthetics action
alone, then rolled back after sequentially exposing the same hidden Lambda preparation checks and
an `iam:PassRole` check. Consequently, neither Synthetics action is High/Critical alone; the tested
dry-run combination is a conditional role-reuse escalation when the caller can pass a useful
existing canary role and modify the generated Lambda resources.

The canary, artifact/proof bucket and objects, generated Lambda function and layer versions, log
groups, three IAM roles and inline policies, lock, bytecode, and test harness were removed. Exact
post-cleanup inventories returned zero for every created resource type.

### Developer, collaboration, and legacy application batch — 2026-09-09

Clean Rooms and Clean Rooms ML have zero collaborations, memberships, configured tables, protected
queries/jobs, model channels, or exports. Their query/model paths remain protected partner-data
candidates but cannot be assessed without the missing multi-account boundary. App notification and
chat services likewise have no rules, targets, Slack/Teams/Chime channels, or identities; exporting
source events or using a configured chat role needs those real integrations. Nothing was connected
to an external service.

Cloud9 has one preserved root-owned legacy EC2 environment named `eksworkshop`, with managed AWS
credentials explicitly disabled by its owner. Testing membership/token hypotheses would mutate
user infrastructure and would not prove inherited AWS privilege under that setting, so it was left
untouched. CloudFront has zero key-value stores, CloudHSM has zero clusters/backups, and CloudSearch
rejects this non-existing customer account. Key/value disclosure, HSM backup sharing, and search
domain data/policy paths remain blocked on real targets.

CodeGuru Security explicitly reports that its feature is no longer available. Profiler and Reviewer
have zero groups, repository associations, or reviews, leaving application stack/profile and source
diff reads target-blocked. CodeStar is retired; CodeWhisperer is superseded by Amazon Q Developer;
and the secure CodeDeploy command prefix is an internal agent channel. The five preserved
CodeStar/CodeConnections installations were not consumed: `UseConnection` still needs a separately
authorized consumer service and role, as recorded in the earlier review. No connection changed.

Cognito Sync has no identity-pool dataset target. Comprehend has zero endpoints/flywheels/models and
Comprehend Medical has zero jobs; real-time APIs process caller-supplied text and asynchronous
objects stay behind S3/role boundaries. Connect Campaigns has no enabled tenant. Console Mobile,
Consolidated Billing, Control Catalog, Cost Optimization Hub, CloudShell, and similar preference or
catalog surfaces do not provide separate credentials or workload access. Customer Verification
remains blocked because there is no public client or enrolled document/PII target. No resource or
setting in this batch was created or changed.

### Emerging, orchestration, and billing-service batch — 2026-09-09

The retired Alexa for Business and BugBust services have no current SDK client or reachable target.
Action Recommendations exposes only recommendation listing, AWS Connector only registration/health,
and Bedrock Web Search only caller-selected public-web retrieval. ARC Region Switch and Auto Scaling
Plans have zero plans and provide failover/capacity control rather than data or identity. These are
`no_new_positive`.

Several new or externally provisioned services have no public client/target but retain worthwhile
future candidates: Agent Registry resource-policy self-grant plus MCP invocation; DevOps Agent
access-token, one-time-login, asset-content and resource-search operations; Claude Platform
AssumeConsole/file/webhook-secret operations; and Mantle file/inference content. Activate may expose
member contact/credit/cost data, while App Studio deployment and AIOps investigation policies need
an enabled tenant/group. They remain blocked rather than classified from action names alone.

AppFabric has zero bundles/authorizations/ingestions, AppFlow has zero connector profiles/flows in
all enabled supported Regions, and App Mesh has zero meshes. Existing SaaS authorization reuse,
flow redirection, and mesh route/backend redirection are concrete data-exfiltration hypotheses, but
need a real protected source or Envoy workload and an observable receiving endpoint. No empty
fixture can prove that victim boundary, and nothing was created. The separate App Mesh Preview
prefix has no current distinct client or target.

Billing dashboards contain only five AWS-managed defaults; GetDashboard returns widget/query
configuration rather than evaluated cost values. Pricing Calculator has no accessible workspace,
Recommended Actions is read-only optimization metadata, and Billing Conductor has zero billing
groups. Braket has zero jobs/tasks and retains S3 authorization for output objects. None provides a
standalone credential, workload payload, or AWS identity, so no new High/Critical path was added.
Connect Cases has zero domains; case/search/audit/related-item reads remain blocked candidates for
real customer-support PII rather than being inferred from schemas.

### Amazon Lightsail (`lightsail`) — 2026-09-09

The Region initially contained zero instances and buckets; the only key pair was the preserved
custom key `mykey` from 2022. A disposable Amazon Linux 2023 instance held one exact local canary.
Two mutually isolated roles had either `lightsail:GetInstanceAccessDetails` on the exact instance
or `lightsail:DownloadDefaultKeyPair` on `*`. Each action returned private key material that opened
a real SSH session and read the canary. Empty-role and cross-action controls were denied.

The temporary-access response requires its `certKey` to be stored beside the private key using the
OpenSSH `-cert.pub` companion name. The Python SDK used in the test returned the misleadingly named
`privateKeyBase64` field as already decoded PEM, so resilient clients must detect PEM before trying
Base64 decoding. Both credential paths are Critical because they provide operating-system access
to an existing instance, subject to the target using the regional default key for the download path.

A separate Lightsail object-storage bucket contained one private canary. A role with only
`lightsail:CreateBucketAccessKey` received a long-term access key and, after propagation, used it to
read the exact object while its direct IAM-role S3 request was denied. A role with only
`lightsail:UpdateBucket` changed `getObject` from private to public; an unsigned request then read
the canary. The private rule was restored and the same unsigned request returned `AccessDenied`.
Both actions are Critical credential/boundary-changing data-access primitives.

`OpenInstancePublicPorts`, `PutInstancePublicPorts`, `SetResourceAccessForBucket`, and
`UpdateContainerService` were removed from the Critical singleton list. Alone they expose network
reachability or activate service-to-service access; they do not authenticate the caller, return
data, or provide an AWS identity. They remain Medium unless combined with a separately demonstrated
access path. The instance, bucket/object/access keys, six IAM roles/policies, and local key material
were deleted. Exact inventories returned zero, and `mykey` was not modified.

### AWS Transfer Family (`transfer`) — 2026-09-09

The account initially contained zero Transfer servers. The isolated fixture created a public SFTP
server, one service-managed user, and an execution role able to read one exact private S3 canary.
The original SSH key read the canary, while an unrelated key could not authenticate.

An empty role was denied `transfer:ImportSshPublicKey`. A candidate with only that action on the
exact user ARN imported its public key and then opened a fresh SFTP session as the existing user.
The session read the exact protected canary through the user's Transfer role even though the
candidate was denied `transfer:DescribeUser`, direct S3 access, and had no `iam:PassRole`. This is
High because it impersonates the selected Transfer user and inherits that user's configured S3 or
EFS scope; it does not disclose reusable AWS role credentials.

The path requires a known server ID and user name, a service-managed user with SFTP enabled,
network reachability to the endpoint, and useful permissions on the user's configured role. The
server/user, SSH-key records, bucket/object, three roles and inline policies, local keys, harness,
lock, and bytecode were deleted. Exact post-cleanup checks returned zero for every fixture resource.

### Billing, retired, and externally provisioned service batch — 2026-09-09

The re:Invent billing prefix exposes only permission-only `info` and `approve` operations. There is
no public CLI/SDK client and the account has no pass-purchase request; manufacturing one or calling
`approve` would alter a real commercial billing decision. FinOps Agent likewise has no public
client or enumerable tenant. One-time-login, approval, document/artifact, connection, integration,
and automation operations remain concrete candidates, but need a real enabled agent space and
protected content. Both rows are blocked and no commercial or external workflow was touched.

CloudWatch Evidently's endpoints no longer resolve after the service retirement, including in four
formerly supported Regions. Its historic feature/launch mutation APIs only affected applications
that separately trusted Evidently decisions; they did not return an AWS identity. The row is
`no_new_positive` and no retained project was created.

Elastic VMware Service has no environment in the lab. A valid fixture requires exactly four
supported bare-metal hosts, ten non-overlapping VLANs and real single-use Broadcom VCF/vSAN
licenses covering at least 256 cores and 110 TiB. Existing-environment reads may expose license
keys, topology, hostnames, managed-secret ARNs, or depot URLs, while connector/entitlement changes
could affect access, but none can be promoted without that costly licensed target.

FinSpace legacy and kdb inventories are empty in all five account-accessible Regions. The sole
`finspace-api` action is particularly interesting: `GetProgrammaticAccessCredentials` models an
access-key ID, secret key, and session token. Its actual identity and data scope cannot be inferred
without a legacy environment. Creating the prerequisite provisions persistent paid users or kdb
infrastructure shortly before the announced 2026-10-07 service retirement, so both FinSpace rows
remain blocked and no credential claim is added.

### AWS Fault Injection Service (`fis`) — 2026-09-09

Live validation confirmed a template-role reuse escalation. A benign FIS template initially held
only `aws:fis:wait`. A restricted role with exactly `fis:UpdateExperimentTemplate` and
`fis:StartExperiment` replaced that action with `aws:ssm:start-automation-execution`, supplied
parameters for an existing Automation document, and deliberately omitted `roleArn`. FIS retained
the template's existing role without checking caller `iam:PassRole`.

The stored FIS role was preauthorized to start that exact document and pass its Automation role.
The document attached one exact proof policy to the restricted caller. Before the experiment, the
same STS session was denied `organizations:DescribeOrganization`; after it ran, the call returned
the protected organization ID and management account. The caller was still denied direct
`iam:AttachRolePolicy`. Empty-role, start-only, and update-only controls independently failed.

The tested combination is conditional Critical. It requires a known template, a useful action or
document reachable by the stored FIS role, and `StartExperiment`; neither FIS permission is an
unconditional escalation alone. Live IAM evaluation also exposed two important scope details:
updating required authorization on both the template and referenced FIS action ARN, while starting
required the template plus the prospective `experiment/*` ARN. First use additionally needs the
account's FIS service-linked role, but the restricted actor did not need permission to create it
once the controller provisioned it.

The experiment was stopped and the template, Automation document, attached proof policy, managed
policy, six IAM roles and inline policies, and first-use FIS service-linked role were deleted.
Exact active-resource inventories are empty. FIS exposes no `DeleteExperiment` API, so the terminal
experiment record remains as immutable service audit history rather than active infrastructure.

### Firewall, forecasting, embedded-software, and free-tier batch — 2026-09-09

Firewall Manager has no default or delegated administrator in the organization. `PutPolicy`,
administrator, resource-set, and third-party-firewall operations can have organization-wide impact,
but only after FMS governance and service integrations are configured. Creating that prerequisite
would change real organization security management, so the row is blocked and nothing was
associated.

Amazon Forecast has zero datasets, groups, predictors, or forecasts in all ten SDK-supported
Regions. `QueryForecast` remains a direct business-data candidate and export APIs can expose model
output through S3, but both require an existing trained forecast with protected values. Running a
new billable training job would manufacture only synthetic output, not the missing victim boundary,
so the row is blocked without a data-access claim.

Amazon FreeRTOS has no public SDK client. General software/configuration downloads are not workload
credentials; EMP patch URLs need a paid Extended Maintenance entitlement that is absent. AWS Free
Tier reads were reachable, but a role with only `freetier:GetFreeTierUsage` was denied specifically
on the separate `aws-portal:ViewBilling` check. That billing permission is already independently
classified and documented as High, so the Free Tier action adds no standalone sensitive-data path.
No account plan or commercial operation was changed.

### Amazon Fraud Detector (`frauddetector`) — 2026-09-09

A disposable event type stored a private email-like variable and customer entity ID. A role with
only `frauddetector:GetEvent` on `Resource: *` retrieved both values for the known event type and
event ID while `GetEventTypes` was denied. An empty role was denied the same known-ID call.

The action is High because production events commonly hold email, IP, phone, billing/shipping,
payment, fingerprint, order, and authentication fields. Enumeration is not required: identifiers
can instead come from application code/configuration, logs, traces, tickets, exports, shell history,
IaC, or CloudTrail already available to the compromised workload.

The event was deleted with its audit history, followed by the event type, variable, entity type,
two IAM roles/policies, and local test harness. A final `GetEvent` returned `Event not found` and
exact prefixed inventories were empty.

### Amazon GameLift Servers (`gamelift`) — 2026-09-09

A disposable Amazon Linux 2023 managed EC2 fleet installed a private file on one c5.large compute.
A role with only `gamelift:GetComputeAccess` on `Resource: *` received temporary credentials issued
from a GameLift service account plus the exact SSM target. Those credentials opened the default
encrypted Session Manager shell and read `BENIGN-GAMELIFT-CANARY-20260909` from the host. The role
was denied `DescribeInstances`, and an empty role was denied the known-ID getter.

The returned session policy correctly rejected a broader `AWS-StartNonInteractiveCommand`
document. The finding is therefore constrained host access, not unrestricted credentials in the
customer account. It is still Critical: a shell can reach deployed build/configuration, live game
data, application secrets, and any configured fleet-instance-role credentials.

The same build tested `gamelift:RequestUploadCredentials`. A request against the controller's build
after it reached `READY` returned `InvalidRequestException`, matching the immutability guarantee.
The action can take over a known `INITIALIZED` upload, but needs a later fleet/deployment action
before code executes. Its former standalone Critical entry was removed and it is explicitly Medium.

`GetInstanceAccess` rejected this Server SDK 5 fleet and directed the caller to
`GetComputeAccess`; no SSH-key claim is added without a separate SDK 4 fixture. The desired fleet
capacity was set to zero, and the managed fleet/build, service-owned upload, four roles/policies,
and local credential material were removed. No new service role remained, and exact active
inventories were empty after GameLift's activation/deletion state machine completed.

### Amazon GameLift Streams (`gameliftstreams`) — 2026-09-09

A disposable Ubuntu application wrote a private canary under its user profile, and a zero-idle
`gen6n_small` stream group ran one short on-demand session. A role with only
`gameliftstreams:CreateStreamSessionAdminShell` received the service's SSM connection material and
opened a real terminal. The terminal read the profile canary and successfully exercised the IAM
role passed to that stream session. An empty role was denied the same known-ID request. This action
is Critical because it grants application-equivalent access to the live runtime, including data,
user/session state, and any IAM role made available to the application.

Three newly published read operations also produced independently tested sensitive disclosures:

- `gameliftstreams:GetStreamSession` alone returned a private environment value, user ID, and the
  passed role ARN; its empty-role control was denied.
- `gameliftstreams:GetStreamUrl` alone returned an existing full accountless stream URL, its passed
  role ARN, and its private environment value; its empty-role control was denied.
- `gameliftstreams:ListStreamUrls` alone required no prior URL identifier and returned that full
  bearer-style URL. Both URL reads are High because AWS explicitly treats the URL as a secret and
  anyone holding it can start the private application until its expiry/use limit.

The role-bearing entry points were tested as boundaries rather than assumed escalation paths.
`StartStreamSession` without `iam:PassRole` was denied, while the exact service action plus a scoped
pass-role grant started the session and exposed the role to the application. `CreateStreamUrl`
likewise enforced `iam:PassRole`, and also enforced the newly observed dependent
`gameliftstreams:StartStreamSession` permission on the application.

`ExportStreamSessionFiles` alone was denied specifically on missing `s3:PutObject`; after adding
only that documented dependency, it exported an archive containing the private profile canary.
Separately, `UpdateApplication` alone changed the supported log path to the private profile file and
the log destination to a same-account service-write bucket; the next controller-started session
exported that canary automatically. Both actions remain Medium in isolation because retrieving the
result needs suitable bucket access, and the update path additionally relies on a subsequent
session.

The test session was terminated, capacity was returned to zero, every stream URL was revoked, and
the stream group, application, S3 bucket/objects/policy, twelve IAM roles/policies, temporary SDK,
and local harness were removed. Exact prefixed inventories were empty after the asynchronous
GameLift Streams deletion completed.

### Amazon Location v2 data planes (`geo-maps`, `geo-places`, `geo-routes`) — 2026-09-09

Three action-only roles and one empty control exercised the current Location v2 data planes in
`us-west-2` without creating any Location resource:

- `geo-maps:GetStaticMap` returned a valid JPEG for caller-supplied Madrid center, zoom, and image
  dimensions. The service's other operations return tiles, styles, sprites, and glyphs from the
  public basemap rather than stored customer data.
- `geo-places:SearchText` returned a public place match for a caller-supplied query and bias
  coordinate. The API surface performs autocomplete, geocoding, place lookup, nearby/text search,
  and suggestions; it has no customer search-history getter.
- `geo-routes:CalculateRoutes` returned a road route between two caller-supplied coordinates. The
  other operations calculate isolines/matrices, optimize supplied waypoints, or snap supplied
  traces to public roads; they do not retrieve stored tenant routes.

The empty role was denied all three equivalent calls. No response contained tenant state,
credentials, or a privilege boundary, so no High/Critical finding was added. Static map reads stay
Low; place search and route calculation stay Medium as billable caller-driven computation. When
IAM calls are denied, public basemap/place/routing sources (for example OpenStreetMap, Nominatim,
OSRM, or local road data) provide permissionless equivalents. A Location API key exposed by a
legitimate client is a non-IAM bearer fallback but remains constrained by the key's configured
actions, resources, expiry, and referrer rules. All four temporary roles/policies and the local
harness were removed; the tests created no persistent Location infrastructure.

### Amazon S3 Glacier direct vaults (`glacier`) — 2026-09-09

Every one of the 17 Glacier regions enabled for the account returned an empty direct-vault
inventory. A controller `CreateVault` request in `us-west-2` was rejected with
`NoLongerSupportedException`: the legacy direct-vault API is not available to this account, and
AWS directs new customers to S3 Glacier storage classes.

`SetVaultAccessPolicy` could theoretically overwrite a vault resource policy to grant archive
retrieval, and `GetJobOutput` returns a completed inventory/archive retrieval. Neither is marked
as a tested High/Critical technique here because there is no authorized vault/archive/job on which
to prove the effective access. No resource, role, job, or billing state was created. Fallback
discovery when direct-vault permissions or eligibility are absent includes already accessible S3
Glacier-object metadata/content, backup catalogs, application references, CloudTrail/SIEM copies,
local restore caches, and offline backups.

### AWS Global Accelerator (`globalaccelerator`) — 2026-09-09

An isolated standard TCP accelerator initially routed its unchanged public DNS name and addresses
to a legitimate caged HTTP canary. A role with only
`globalaccelerator:UpdateEndpointGroup` on `Resource: *` replaced that endpoint with a second
attacker-controlled Elastic IP. The same public accelerator endpoint then returned the attacker
canary after deployment. The role was denied `DescribeEndpointGroup`, had no EC2 permission,
and received the endpoint-group ARN and attacker allocation ID out of band; an empty role was
denied the update.

This is High traffic hijack. It can redirect production ingress to an attacker service, expose
plaintext requests/session material, serve malicious content, or blackhole traffic. The impact is
conditional enough not to claim unconditional Critical: the replacement must be a valid active
endpoint in the group's Region (or be authorized through a cross-account attachment), and TLS
clients still validate the certificate presented by the new backend. The same IAM permission also
authorizes the newer add/remove-endpoint operations, so defenders must monitor all three API paths.

For enumeration without Global Accelerator list/describe permission, search DNS/CNAME records,
IaC state, application configuration, CloudTrail/SIEM copies, deployment pipelines, runbooks, and
monitoring exports for accelerator/listener/endpoint-group ARNs. DNS resolution itself reveals the
accelerator anycast addresses without AWS permission. If the mutation is denied, an already
compromised current endpoint, load balancer target, DNS layer, or application deployment path is a
permissionless alternative traffic position rather than a Global Accelerator policy bypass.

The accelerator, listener, endpoint group, two Elastic IPs, security group, both disposable
backends, two roles/policies, and local harness were removed. Exact accelerator/EIP/security-group
and role inventories are empty; both test instances are in `terminated` state.

### Ground Station and console-only GroundTruth (`groundstation`, `groundtruthlabeling`) — 2026-09-09

Ground Station config, dataflow-endpoint-group, mission-profile, satellite, and ground-station
inventories were empty in all ten enabled service Regions. Changing a victim mission profile or
dataflow route could redirect satellite data, and reserving or cancelling a contact could affect
operations, but those hypotheses require a satellite already onboarded by AWS and working contact
infrastructure. None can be created as an isolated disposable fixture, so no severity is inferred
from action names and no Ground Station resource was changed.

AWS's current authorization reference describes all 16 `groundtruthlabeling` actions as
permission-only and explicitly lists no callable API operation. Current CLI and Botocore releases
also expose no client. Console-mediated batch/dataset reads and manifest processing therefore need
an authorized GT+ tenant and captured console request/response before their content and downstream
S3 checks can be tested. No GroundTruth project, batch, dataset, job, bucket, or role was created.

Permissionless fallback discovery for both surfaces includes CloudTrail/SIEM copies, IaC and
deployment state, application configuration, S3 manifests/output, logs, support/onboarding records,
and locally cached exports. These may reveal resource IDs or data without either service's list
permissions, but do not bypass the service authorization boundary.

### Amazon Connect Health (`health-agent`) — 2026-09-09

The newly published Amazon Connect Health client was absent from the installed CLI, so inventory
used disposable Botocore 1.43.90. `ListDomains` returned no domains in either supported Region,
`us-east-1` or `us-west-2`. The authorization surface contains unusually sensitive candidates:
patient-insights and medical-scribe getters, permission-only patient/session/EHR getters, password
reset, and agent/integration mutation. A meaningful test needs an existing configured domain,
subscription, EHR integration, and protected patient/session/job. Creating the domain also creates
application/Identity Center setup state and would merely manufacture synthetic health data, so it
was not used to overstate any permission as High or Critical. No domain, subscription, integration,
job, session, identity assignment, role, or account setting was changed.

When Connect Health enumeration is denied, useful non-IAM sources are Connect flows and instance
configuration, IAM Identity Center application assignments, CloudTrail/SIEM copies, application
URLs, EHR integration configuration, S3 input/output references, client telemetry, and IaC. These
are discovery fallbacks, not authorization bypasses.

### Retired and unreachable data-transfer surfaces (`honeycode`, `importexport`) — 2026-09-09

AWS CLI 2.32.21 and Botocore 1.43.90 no longer expose Honeycode, and current AWS documentation
records removal of Honeycode integration material following service discontinuation. Historical
row/screen reads and automation invocation require known workbook resources in an existing retired
tenant; there is no current workbook-discovery API or authorized target. No Honeycode state was
created or changed.

The legacy AWS Import/Export Disk SDK model remains, but its sole global endpoint timed out with
explicit short connection/read timeouts. Historical status/shipping-label reads and manifest
updates require a physical-disk job, and ordering a physical shipment is not a disposable security
test. Snowball uses a separate active API and IAM prefix. No job, manifest, address, label, bucket,
role, or device order was created. For both legacy surfaces, permissionless fallbacks are old local
exports, source-control/IaC, CloudTrail/SIEM history, emails and shipping records, S3 source/output
objects already accessible to the caller, and application caches.

### Inspector auxiliary surfaces (`inspector`, `inspector-scan`, `inspector2-telemetry`) — 2026-09-09

Inspector Classic passed its May 20, 2026 end-of-support date, and its `us-east-1` and `us-west-2`
endpoints timed out. AWS states that Classic resources are no longer accessible after that date;
the current Inspector2 control plane is tracked separately.

The single `inspector-scan:ScanSbom` operation returned seven known vulnerabilities for a supplied
CycloneDX 1.5 Log4j 2.14.1 component, while the identical unsigned call failed with
`MissingAuthenticationToken`. It analyzes caller input rather than reading an account's stored
SBOM or findings, so it remains a billable Medium computation and is not sensitive-data access.
Trivy, Grype, OSV-Scanner, vendor advisories, and local vulnerability databases provide
permissionless alternatives.

The `inspector2-telemetry` catalog contains only session/heartbeat/telemetry write actions and has
no public SDK client or read/list surface. A scan-poisoning hypothesis requires an already active
agent's internal session and observed downstream finding impact; action names alone are not proof.
Owned-host agent state/logs, packet capture, CloudTrail/SIEM copies, and Inspector2 findings are
fallback evidence sources. No Inspector resource, role, report, finding, or setting was changed.

### AWS Interconnect (`interconnect`) — 2026-09-09

All eight supported multicloud Regions returned no existing connection. A disposable Direct
Connect gateway successfully appeared in `ListAttachPoints`. An empty role was denied
`CreateConnection`; a role with only `interconnect:CreateConnection` passed the IAM boundary for
that gateway without any `directconnect:*` permission, then AWS rejected the requested free
500 Mbps GCP connection because the account's free-trial billing information could not be verified.

This leaves a valuable but unvalidated hypothesis: a caller who knows a Direct Connect gateway ID
may be able to request a connection to an attacker-controlled GCP, Azure, or OCI account, receive
the activation key, and activate it provider-side without Direct Connect permissions. Actual impact
still requires provider activation plus pre-existing gateway associations/routes, and must be
proved by packets traversing the boundary before assigning High/Critical severity. No connection
was created; the gateway reached deletion, both test roles/policies were deleted, connection
inventory is empty, and no provider network or route was created. DNS/BGP data, Direct Connect
inventories exposed elsewhere, IaC, CloudTrail/SIEM copies, and network diagrams remain useful
permissionless discovery fallbacks.

### CloudWatch Internet Monitor (`internetmonitor`) — 2026-09-09

`ListMonitors` returned empty in all 18 reachable current endpoint Regions. The API observes health,
performance, client geography/ASN, and traffic-volume signals or changes the resource set being
observed; it does not reroute traffic or execute workload code. Existing query results can be useful
operational reconnaissance but do not contain packet payloads or credentials, so no High/Critical
path is promoted. Public AWS health data, DNS/BGP/RIPE sources, browser telemetry, CloudWatch
exports, application logs, and IaC are permissionless discovery alternatives. No monitor, query,
role, log, or setting was changed.

### AWS IoT commands and Jobs DataPlane (`iot`, `iotjobsdata`) — 2026-09-09

A disposable IoT job targeted three things and stored a private URL/token canary in its inline job
document. Three STS sessions were each scoped to one thing ARN and held exactly one data-plane
action:

- `iotjobsdata:DescribeJobExecution` with `jobId=$next` returned the queued execution and complete
  job document without knowing the job ID.
- `iotjobsdata:StartNextPendingJobExecution` likewise returned the document and changed the next
  execution from `QUEUED` to `IN_PROGRESS` without knowing the job ID.
- `iotjobsdata:UpdateJobExecution`, given the job ID, changed a queued execution to `IN_PROGRESS`
  and returned the document when both include flags were requested.

An empty role was denied the equivalent describe call. `GetPendingJobExecutions` returned queued
execution metadata but no job document, so it remains Medium rather than High. The three
document-returning actions are High where production documents contain firmware URLs, bootstrap
tokens, configuration, or operational instructions. The two write actions can also lie about or
terminate device-maintenance state, depending on the requested transition.

A second isolated fixture tested current IoT Device Management Commands. A role with only
`iot:StartCommandExecution` on the exact command and thing ARNs started the execution; a
certificate-authenticated device simulator subscribed to the exact reserved request topic and
received the stored payload canary. An empty role was denied. This is High conditional remote-device
action: it invokes an existing command but neither changes its stored payload nor guarantees how a
device processes it, so it is not labeled unconditional code execution.

No list permission was required for either path once identifiers were known. Useful discovery
fallbacks include device firmware and local agent state, configuration/certificate filenames,
source code and IaC, S3-hosted job documents, deployment pipelines, application logs, MQTT packet
captures from an owned endpoint, and CloudTrail/SIEM copies. The Jobs fixture, executions, things,
certificates/private keys, IoT policies, roles/policies, temporary SDK, and local material were
removed. Four command records created during MQTT calibration/retries are deactivated and in the
service's `pendingDeletion` state; all active thing, certificate, policy, role, execution, and job
inventories are empty.

### IoT Device Tester and Device Advisor (`iot-device-tester`, `iotdeviceadvisor`) — 2026-09-09

The current CLI and SDK expose no IoT Device Tester client. Its authorization-catalog actions are
limited to obtaining public local-test tooling/version information and sending metrics, so they do
not expose tenant IoT state. Device Advisor was reachable in its four supported Regions, but every
suite inventory was empty. `GetEndpoint` returned an account service endpoint rather than a secret.
A role-reuse or report-disclosure test therefore needs an existing suite, device, permission role,
and completed run and remains blocked. Public IDT downloads, local IDT/device artifacts, source and
IaC, CI outputs, owned-device packet capture, and CloudWatch/CloudTrail exports are useful fallbacks.
No suite, run, report, device, role, or setting was created or changed.

### AWS IQ (`iq`, `iq-permission`) — 2026-09-09

AWS IQ and its engagement-specific permission workflow reached end of support in May 2026. There is
no current control plane in which to create/enumerate engagements or reproduce a role assumption.
The historical `AssumePermissionRole` behavior depended on a role deliberately attached to an IQ
engagement and is not a current new escalation. Archived messages/contracts, billing exports,
email, IAM/CloudTrail records, credential caches, and SIEM copies are the non-service fallbacks. No
request, proposal, engagement, role, session, payment, or setting was created or changed.

### Amazon Interactive Video Service (`ivs`) — 2026-09-09

An isolated private BASIC channel produced four independently validated High single-permission
paths. Roles holding only `ivs:GetStreamKey` or `ivs:BatchGetStreamKey` on its stream-key ARN
returned the complete secret; the recovered key successfully started an RTMPS broadcast. After an
administrator deleted that key, `ivs:CreateStreamKey` alone created a replacement secret and that
key also started a confirmed live broadcast. An empty role was denied.

The channel's anonymous playback URL returned HTTP 403 while playback authorization was enabled.
`ivs:UpdateChannel` alone could not modify the channel while it was live, as documented. After the
stream stopped, the same role set `authorized=false`; on the next broadcast, the unchanged URL
returned HTTP 200 without a playback token. This is a conditional playback-access downgrade, not
unconditional account privilege escalation. `ListStreamKeys` exposes identifiers but never key
values, while `StopStream` and `DeleteStreamKey` are availability impacts, so those remain Medium.

No IVS list permission was needed once an ARN was known. Source/IaC, OBS and encoder profiles,
deployment secrets, process environments, application/log output, public pages and DNS, and
CloudTrail/SIEM copies are useful discovery fallbacks. All channels, keys, broadcasts, exact test
roles/policies, ffmpeg processes, and local material were removed; IVS and test-role inventories
are empty.

### MSK Connect (`kafkaconnect`) — 2026-09-09

Connector, custom-plugin, and worker-configuration inventories were empty in every reachable
supported Region. `UpdateConnector` can replace connector configuration without receiving a new
service-execution-role ARN, so retained-role data movement through a compatible source/sink plugin
is plausible. A functioning Kafka network, existing connector/plugin, privileged connector role,
and observable external system are required to prove it; action metadata alone is not a finding.
Source/IaC, Kafka Connect REST/config backups, plugin archives, worker logs, broker metadata, and
CloudTrail/SIEM copies are fallbacks. No connector, plugin, worker configuration, cluster, network,
role, or setting was created or changed.

### Amazon Kendra (`kendra`) — 2026-09-09

All ten supported Regions returned no index. The API documentation shows that `Query` and
`Retrieve` return indexed text and accept caller-supplied `UserContext`; notably, omitting context
returns all documents. A disposable ACL test could not be manufactured because `CreateIndex`
returned `NotAuthorizedException`: Kendra no longer accepts new customers. The hypothesis remains
blocked rather than promoted without live evidence. Public pages/search caches, source and IaC,
data-source repositories, browser history, application logs, CloudTrail/SIEM copies, and local RAG
caches are fallback discovery paths. The temporary service role was deleted and index, test-role,
and log inventories are empty.

### AWS Lake Formation (`lakeformation`) — 2026-09-09

An empty role was denied `PutDataLakeSettings`. A second role whose only permission was
`lakeformation:PutDataLakeSettings` on `Resource: *` successfully submitted the existing settings
plus its own ARN and became the fourth Lake Formation data-lake administrator. This confirms a High
privilege-escalation primitive across Lake Formation's administrator boundary. It is not labeled
unconditional Critical: AWS documents that even a data-lake administrator still needs the IAM
grant/revoke actions to exercise those APIs, and administrators do not automatically receive
`SELECT` on pre-existing data.

Existing legitimate SageMaker/DataZone administrator ARNs were never assumed or used to access
data. Cleanup restored the same three-member administrator set and every other setting and removed
both roles/policies; AWS only returned the original administrator list in a different order. The
disposable ARN is absent. Without IAM enumeration, useful fallbacks are Glue/Athena configuration,
Terraform/CloudFormation, application query code, local credential/config caches, S3 path names,
CloudTrail/SIEM exports, and analytics-engine logs.

### Kendra Intelligent Ranking (`kendra-ranking`) — 2026-09-09

A role with only `kendra-ranking:Rescore` on one disposable plan successfully reranked two
caller-provided documents. The API stores neither a searchable tenant corpus nor result history;
it returned IDs/scores for the submitted text. This remains a billable Medium computation. Local
embedding/reranking models and public search tools are permissionless substitutes. The plan reached
deletion, all roles/policies were removed, and plan/role inventories are empty.

### Launch Wizard (`launchwizard`) — 2026-09-09

There are no deployments. Seven public workload families and their templates are visible, but the
current CLI has no update operation and there is no retained victim provisioning context to test.
Manufacturing a large CloudFormation-backed application solely to infer behavior is not justified.
Public solution templates, source/IaC, CloudFormation history, deployment logs, SSM/EC2 inventory,
and CloudTrail/SIEM copies are fallbacks. No stack, deployment, instance, role, or network changed.

### License Manager family — 2026-09-09

Core License Manager has no active configuration, license, grant, or token. A token-to-web-identity
hypothesis was tested carefully: reserved `aws:` token properties were rejected; an administrator
could create a token, but both an IAM role and IAM user holding `CreateToken` plus `GetLicense` were
denied by License Manager's internal license authorization. The empty role was separately denied by
IAM. Thus no permission-only role assumption is promoted. Synthetic license/token records are
`DELETED`; users, access keys, roles, and policies are absent.

Linux subscription discovery and organization integration are disabled with no source Regions.
User Subscriptions has no service-linked role, identity provider, endpoint, instance, product, or
association, so its mutating workflow cannot be tested without onboarding managed infrastructure.
Local license files, package-manager/SSM inventory, directory configuration, contracts, billing
exports, application logs, and CloudTrail/SIEM copies are fallbacks. No setting or SLR changed.

### Lookout services — 2026-09-09

Lookout for Metrics and Lookout for Vision reached full shutdown in October 2025 and current clients
no longer expose their APIs. Lookout for Equipment is in sunset through October 7, 2026, but all
three supported Regions have zero datasets. Historical industrial telemetry/model/scheduler paths
remain plausible only for an existing customer fixture. Source S3/CSV/images, sensor historians,
IoT SiteWise, exported models/anomalies, replacement anomaly services, edge caches, logs, and SIEM
archives are fallbacks. No dataset, detector, project, model, scheduler, role, or setting changed.

### Mainframe Modernization (`m2`) — 2026-09-09

A role holding only `m2:GetSignedBluinsightsUrl` on `Resource: *` obtained a short-lived SSO URL for
`bluinsights.aws`. The embedded signed claims identified the exact assumed-role session, while an
empty role was denied. Consuming the link followed the BluInsights authentication flow to HTTP 200.
This is High sensitive-workspace access because it requires no application/list permission and the
portal can hold migration assessments and source-analysis projects. The link had 30 seconds left
and was consumed; both roles/policies were deleted. M2 application/environment inventories are
empty. Source repositories, exported assessments, browser history, CI artifacts, local exports,
and CloudTrail/SIEM copies are fallbacks.

### Managed Blockchain (`managedblockchain`, `managedblockchain-query`) — 2026-09-09

`managedblockchain:GetAccessor` alone on one exact accessor ARN returned the complete 42-character
billing token; an empty role was denied and `ListAccessors` omitted it. AWS warns that this token
replaces SigV4 for Ethereum-node calls. It remains Medium under the review rubric: the token enables
account-billed public-chain RPC, not private tenant data or AWS privilege escalation. The roles are
gone; AWS retains the accessor in asynchronous `PENDING_DELETION`, and the token was never printed
or stored.

`managedblockchain-query:GetTransaction` returned the Bitcoin genesis transaction from its public
ID. Query APIs operate on public addresses, contracts, balances, transactions, and events, so they
remain Medium billable intelligence. Public explorers/RPC nodes, self-hosted nodes, offline chain
indexes, IaC, application configs, process environments, and logs are fallbacks.

### MAP Credits, Mechanical Turk, and AmazonMediaImport — 2026-09-09

MAP Credits exposes three permission-only list actions for agreements, quarterly credits, and
eligible spend, but no public API/CLI/SDK operation. This remains Medium financial enumeration.
Mechanical Turk's balance and HIT calls both rejected this account because it is not linked to a
Requester account. Although the API documentation says assignment reads contain worker IDs and
answers, no such read is promoted without a completed live fixture. `mediaimport` similarly exposes
only the permission-only `CreateDatabaseBinarySnapshot` action and no callable client. Billing
exports, payer reports, contracts, requester databases/exports, public HIT pages, local CSV/JSON,
database-native snapshots, migration logs, S3 artifacts, source/IaC, browser history, application
logs, and CloudTrail/SIEM copies are fallbacks. No resource or account link was created.

### MediaConnect (`mediaconnect`) — 2026-09-09

Three single-action roles were independently validated against one disposable flow carrying a
synthetic RTP test pattern. `DescribeFlowSourceThumbnail` returned a non-empty base64 frame and
timecode. `AddFlowOutputs` added an RTP destination at a disposable EC2 receiver, which observed a
packet from the flow's AWS egress IP. `UpdateFlowOutput` changed that output to a second UDP port,
where an independent listener again observed a packet. An empty role was denied each operation.
All three permissions are High because they directly reveal a private frame or duplicate/redirect
the continuing live feed.

`AddFlowOutputs` required authorization on both the flow and the deterministically named new output;
`UpdateFlowOutput` required the flow and existing output. Listing is optional if the ARNs are found
in source/IaC, encoder profiles, process environments, shell history, monitoring exports, DNS,
application logs, or CloudTrail/SIEM copies. The flow/output and the EC2 receiver, security group,
instance profile, roles, and policies were deleted. The flow and matching role inventories are
zero and the instance is terminated.

### MediaLive (`medialive`) — 2026-09-09

A single-pipeline channel ingested a synthetic RTP test pattern and emitted UDP to a disposable
receiver. A role holding only `DescribeThumbnails` on its exact channel ARN returned a current JPEG;
an empty role was denied. A different role holding only `UpdateChannel` changed the destination
while the channel was idle. After restart, the new UDP port received packets from the same channel
egress IP. Both are High private-live-content paths: one reads a frame and the other redirects the
continuing feed. Channel IDs, input addresses, and destinations can be recovered without list
permissions from encoder profiles, source/IaC, environments, shell history, DNS, monitoring, logs,
and CloudTrail/SIEM copies.

`CreateNodeRegistrationScript` was also tested but is not promoted. The MediaLive action plus the
documented SSM activation/tag actions still failed until `iam:PassRole` on the cluster instance role
was granted. At that point the principal can already use `ssm:CreateActivation` directly, so the
MediaLive operation adds no privilege-escalation primitive. Two unused activations and the test node,
cluster, network, channel, input, input security group, EC2 receiver, instance profile, roles, and
policies were deleted; all exact inventories are zero and the instance is terminated.

### MediaPackage VOD (`mediapackage-vod`) — 2026-09-09

A disposable HLS source in S3, source role, packaging group/configuration, and asset tested the
hypothesis that `DescribeAsset` alone reveals a usable opaque playback URL. The operation did
return an egress URL, but packaging reached `FAILED` and the URL never served content. No
capability-URL access was reproduced, so the read remains Medium enumeration rather than a new
High. Source manifests, application/CDN configuration, browser history, player telemetry,
source/IaC, deployment output, logs, and CloudTrail/SIEM copies are fallbacks. The failed asset,
packaging configuration/group, source role/policy, every S3 object, bucket, and local media file
were deleted; exact inventories are zero.

### MediaPackage v2 (`mediapackagev2`) — 2026-09-09

Two resource-policy mutations were independently validated on one disposable channel and origin
endpoint. A role holding only `PutOriginEndpointPolicy` on the exact endpoint attached a wildcard
read policy; the same unsigned egress request changed from forbidden (`403`) to authorized but
empty (`404`). This is High when an endpoint contains private media because the action alone can
publish it. A role holding only `PutChannelPolicy` on the exact channel attached a wildcard ingest
policy constrained to the tester's source IP. Unsigned `PUT` requests from that host to valid HLS
object paths then returned `200`, proving a High content-injection primitive. The empty role was
denied both operations.

AWS rejected a globally wildcard ingest policy without an `aws:SourceIp` condition, so this result
does not imply worldwide anonymous ingest. The synthetic objects also did not produce playable
output, so only accepted attacker-host ingestion—not end-to-end playback—is claimed. Channel and
endpoint names are often recoverable without list permissions from player/encoder URLs, DNS,
source/IaC, environments, deployment output, browser history, monitoring, logs, and CloudTrail/SIEM
copies. Both policies, the endpoint, channel, group, exact/empty roles, and local media were deleted;
exact inventories are zero.

### Migration Hub (`mgh`) — 2026-09-09

Botocore calls in `us-east-1` and `us-west-2` returned empty progress-update-stream,
migration-task, and application-state inventories. The installed AWS CLI no longer exposes the
legacy `migrationhub` command, so the SDK provides the resilient fallback. API-model review found
metadata association and state-update operations, but no returned credential, role-passing
execution, resource-policy, or independent sensitive-content path. Migration task, source, and
artifact data remain Medium infrastructure enumeration. ADS exports, inventory databases,
source/IaC, migration-agent logs, local SDK scripts, application catalogs, and CloudTrail/SIEM
copies are fallbacks. No resource or setting was created or changed.

### Migration Hub Orchestrator (`migrationhub-orchestrator`) — 2026-09-09

`ListWorkflows` and `ListTemplates` both returned an explicit denial because Migration Hub has not
accepted new customers since 2025-11-07. Workflow/template reads can expose commands, S3 script and
output locations, and workflow inputs; `StartWorkflow` may execute an existing workflow. This
account cannot create the disposable workflow needed to isolate those effects, so no execution
permission is promoted without evidence. Workflow exports, template YAML, S3 scripts/output,
migration runbooks, ADS inventory, source/IaC, logs, and CloudTrail/SIEM copies are fallbacks. No
workflow, template, step, role, bucket, or setting was created or changed.

### Migration Hub Strategy Recommendations (`migrationhub-strategy`) — 2026-09-09

Server and application-component inventories were empty in both tested Regions, and there was no
latest assessment. Assessment, import, report, and configuration shapes were reviewed, including
source-code locations and Secrets Manager key identifiers, but no credential-return or execution
primitive exists without an onboarded collector and assessment. These reports remain Medium
environment metadata. Collector exports, ADS inventory, source/IaC, imported CSV, report S3
buckets, local reports, agent logs, and CloudTrail/SIEM copies are fallbacks. No resource or
setting was created or changed.

### Amazon Pinpoint (`mobiletargeting`) — 2026-09-09

`GetApps` was empty. A tagged disposable app could be created, but `UpdateEndpoint` returned the
new-customer sunset denial, so endpoint PII reads could not be isolated. A synthetic Baidu channel
was accepted, but `GetBaiduChannel` returned only `HasCredential=true` and no credential value;
GCM validated and rejected a fake credential as unregistered. Existing-customer endpoint reads may
still be sensitive, but no untested PII path is promoted. Segment exports, Connect Customer
Profiles, campaign exports, source/IaC, browser/app caches, logs, and CloudTrail/SIEM copies are
fallbacks. Every disposable app was deleted and the inventory is zero.

### Amazon Monitron (`monitron`) — 2026-09-09

Current AWS CLI and Botocore expose no Monitron client, and AWS has not accepted new customers
since 2024-10-31. This account cannot create the project/sensor fixture required to isolate
industrial telemetry reads or project mutations. Existing-customer fallbacks include mobile-app
exports, local sensor/gateway caches, equipment maintenance systems, IoT/industrial historians,
browser history, application logs, and CloudTrail/SIEM copies. No resource or setting was created.

### Multi-party approval (`mpa`) — 2026-09-09

Approval-team inventory was empty. Complete API-model review covered teams, identity sources,
policies, sessions, deletion windows, updates, and cancellation. The API has no direct
approve/respond operation; team updates themselves create a pending approval workflow instead of
silently bypassing the quorum. Session and team reads remain Medium because they can reveal
requester, approver, protected-resource, action, comment, and policy metadata. Identity Center
exports, protected-service logs, tickets, source/IaC, notifications, browser history, and
CloudTrail/SIEM copies are fallbacks. No resource or setting was created or changed.

### AWS User Notifications (`notifications`) — 2026-09-09

Two reads were independently isolated against existing AWS-managed Health events. A role holding
only `ListManagedNotificationEvents` on `Resource: "*"` returned account-specific event ARNs,
related account IDs, sources, and headlines. A different role holding only
`GetManagedNotificationEvent` on one exact event ARN returned structured full content containing
message components, text parts, and a source-event detail URL. An empty role was denied both.

These are High account-operational-data disclosures: observed categories included billing/account
state, certificate and domain state, resource lifecycle notices, and experiment events. Exact text
was deliberately excluded from stored evidence. `Get` is resource-scoped; identifiers may come
from `List` or permissionless browser history, notification email/chat/tickets, local application
logs, and exported SIEM records. The events pre-existed and were not modified. All one-action and
empty roles/policies were deleted; their inventory is zero.

### AWS User Notifications Contacts (`notifications-contacts`) — 2026-09-09

Email-contact inventory was empty. Read operations return the address, status, and tags but not the
activation code; creation sends that code out of band and activation requires it. Creating a
contact also does not associate it with a notification configuration. Routing events to an
attacker therefore additionally requires mailbox control and `notifications:AssociateChannel` on
a target configuration, a chain not claimed without a controlled mailbox fixture. Notification
email, mail-server logs, ticket/chat exports, browser history, source/IaC, and CloudTrail/SIEM
copies are fallbacks. No contact, activation, association, role, or policy was created or changed.

### Amazon Nova Act (`nova-act`) — 2026-09-09

A disposable workflow definition and two runs exercised the current preview model alias.
`CreateAct` reached `PENDING_CLIENT_ACTION`: the service proposes tool interactions, while the
client must execute tools and submit results to `InvokeActStep`. It did not run the declared local
echo tool and exposes no service role, AWS credential, or autonomous AWS action path. Prompt/task,
tool schema, run metadata, and optional S3 export/log locations remain Medium workflow data. Local
SDK state, browser traces, CloudWatch logs, S3 exports, source/IaC, application logs, and
CloudTrail/SIEM copies are fallbacks. Both runs and definitions were deleted; inventory is zero.

### Amazon MQ (`mq`) — 2026-09-10

One disposable public ActiveMQ broker validated two exact-resource, one-action attacks. A role with
only `CreateUser` added a console-enabled member of the `admins` group. A different role with only
`UpdateUser` reset an existing user's password, enabled console access, and assigned that group.
An empty role was denied both operations. After an administrator reboot applied the pending
changes, both new attacker-controlled credentials returned HTTP `200` from `/admin/`; a wrong
password and the victim's old password returned `401`.

Both are High broker takeover and message-data access paths. Listing is optional when the broker ID,
console URL, or username is recovered from client configs, connection strings, DNS, source/IaC,
process environments, logs, or CloudTrail/SIEM copies. `UpdateBroker` was downgraded to Medium: its
previous LDAP-redirection description is conditional/inferential and was not a reproduced
standalone takeover. The broker, dedicated security group, users, exact/empty roles, and policies
were deleted; exact inventories are zero.

### Nimble Studio (`nimble`) — 2026-09-10

The service reached full shutdown on 2024-06-30, and current AWS CLI/Botocore distributions expose
no client. Historical StudioBuilder state, EC2/FSx resources, NICE DCV/session logs, directory data,
source/IaC, local SDK caches, and CloudTrail/SIEM archives are fallbacks. No resource was created.

### CloudWatch Observability Admin (`observabilityadmin`) — 2026-09-10

Telemetry-pipeline inventory was empty and enrichment was not enabled. Configuration/model review
covered rules, S3-table integration, sources/processors/sinks, test records, and organization
evaluation. Referenced pipeline roles require `iam:PassRole`; CloudWatch Logs sources additionally
require Logs rule permissions. `TestTelemetryPipeline` processes caller-supplied records. No
standalone stored-role or arbitrary external-sink primitive was found. IaC, OpenTelemetry configs,
CloudWatch/S3 exports, agent configs, and CloudTrail/SIEM copies are fallbacks. No resource changed.

### Amazon One Enterprise (`one`) — 2026-09-10

Current AWS CLI and Botocore expose no client and this account has no preview site/device fixture.
User/site/device reads, activation-QR creation, template/device updates, and reboot actions were
reviewed. `ListUsers` may expose enrolled identity metadata and `CreateDeviceActivationQrCode` may
activate a device, but neither is promoted without controlled hardware. Physical-access-controller
exports, badge directories, device/installer logs, source/IaC, browser history, and CloudTrail/SIEM
copies are fallbacks. No resource was created.

### OpenSearch Ingestion (`osis`) — 2026-09-10

Pipeline and endpoint inventories were empty. Pipeline configuration, role ARN, resource policies,
VPC endpoints, lifecycle mutations, and blueprints were reviewed. Pipeline roles require
`iam:PassRole`; source integration changes also need their source/resource-policy permissions, so
`UpdatePipeline` alone is not a stored-role escalation. Data Prepper YAML, OpenSearch/CloudWatch/S3
configs, source/IaC, VPC endpoint DNS, logs, and CloudTrail/SIEM copies are fallbacks. No resource
was created or changed.

### AWS Outposts (`outposts`) — 2026-09-10

Outpost inventory was empty. Sites/addresses, assets, orders/billing, capacity tasks, and the
`StartConnection`/`GetConnection` tunnel were reviewed. The tunnel requires real hardware identifiers,
network interface context, and a client public key, so no action is promoted without an Outpost.
Purchase records, rack inventories, device labels, BMC/network configs, Direct Connect/VPN data,
source/IaC, support cases, and CloudTrail/SIEM copies are fallbacks. No resource was created.

### AWS Panorama (`panorama`) — 2026-09-10

Panorama reached full shutdown on 2026-05-31. `ListDevices` and an exact one-action
`ProvisionDevice` call now return the service-side unknown-operation authorization failure. A
tagged attempt first demonstrated an extra `TagResource` dependency. The modeled certificate bundle
was not obtained and is not promoted. Historical IoT identities, manifests/packages, appliance
storage, camera config, source/IaC, logs, and CloudTrail/SIEM archives are fallbacks. No device was
created and every test role/policy was deleted.

### AWS Partner Central (`partnercentral`) — 2026-09-10

Selling, Benefits, and Channel models were reviewed across invitations, engagements, opportunities,
customer/project snapshots, benefits, relationships, and stored job-role ARNs. Live list calls all
required an active AWS Partner benefit. No cross-account path is promoted without that fixture.
CRM/APN exports, opportunity sheets, contracts, email, source/IaC, browser history, logs, and
CloudTrail/SIEM copies are fallbacks. No resource or setting was created.

### Partner Central account management (`partnercentral-account-management`) — 2026-09-10

Partner and connection inventories were empty. Profile/contact data, invitations, visibility,
verification, training-email association, and update tasks expose business metadata but no
credential, arbitrary role assumption, or access to another participant's AWS resources. CRM/APN
exports, contracts, training records, email, source/IaC, browser history, and logs are fallbacks.

### AWS Payment Cryptography (`payment-cryptography`) — 2026-09-10

The only two keys are `DELETE_PENDING` artifacts tagged as separate concurrent tests and were not
touched. `ExportKey` is a credible exportable-key candidate, but creating a fresh key would leave a
mandatory delayed-deletion tombstone. No export is promoted without a successful isolated unwrap
and cryptographic-use test. HSM ceremony records, TR-31/TR-34 archives, payment configs, KCV/alias
inventories, source/IaC, and CloudTrail/SIEM copies are fallbacks. This review created no resource.

### AWS Payments (`payments`) — 2026-09-10

Financing, payment instruments/preferences, and permission-only `MakePayment` were reviewed. No
current SDK client is exposed, and exercising these actions would cause real financial/external
effects rather than a reversible fixture. Billing exports, bank/processor records, invoices,
funding documents, payer downloads, browser history, and CloudTrail/SIEM copies are fallbacks.

### Private CA Connector for SCEP (`pca-connector-scep`) — 2026-09-10

Connector inventory was empty. `GetChallengePassword` explicitly returns a SCEP enrollment secret,
but a connector requires a live private CA. This account has none, and a new CA cannot be fully
destroyed inside AWS's recovery window. The action is therefore not promoted without a retrieved
password and successful synthetic enrollment. MDM exports, enrollment profiles, setup artifacts,
CA audit records, source/IaC, client caches, and CloudTrail/SIEM copies are fallbacks.

### Parallel Computing Service (`pcs`) — 2026-09-10

Cluster inventory was empty. Cluster, queue, node-group, launch-template, AMI, scaling, registration,
and instance-profile paths were reviewed. AWS declares `iam:PassRole` to EC2 as a dependency for
both node-group create and update, so no standalone stored-role escalation is claimed. Slurm
configs/accounting, launch templates, EC2/SSM inventory, shared storage, source/IaC, scheduler logs,
and CloudTrail/SIEM copies are fallbacks. No resource was created.

### Amazon Personalize (`personalize`) — 2026-09-10

Dataset-group inventory was empty. Dataset/schema import/export, trackers, campaigns, filters,
recommenders, solutions, batch jobs, S3, KMS, and roles were reviewed. These workflows require
explicit data targets and role/S3 access; no credential-return or standalone execution path was
found. Source datasets, S3, event caches, analytics exports, model artifacts, source/IaC, and
CloudTrail/SIEM copies are fallbacks. No resource changed.

### Performance Insights (`pi`) — 2026-09-10

All 18 enabled Regions were checked for RDS and DocumentDB instances/clusters; none exist. SQL
dimensions/details and analysis reports may contain query text and topology, but expose no database
credential or AWS execution primitive. Database/slow-query logs, engine views, CloudWatch/APM
exports, source/IaC, local reports, and CloudTrail/SIEM copies are fallbacks.

### AWS Price List (`pricing`) — 2026-09-10

The API returns public product catalogs and price-list file URLs, not account-owned pricing,
credentials, workload data, or execution. Public AWS pricing pages and offer files, public query
endpoints, local cost models, contracts, and calculator exports are permissionless fallbacks.

### Pricing and purchase-order consoles (`pricingplanmanager`, `purchase-orders`) — 2026-09-10

Neither prefix has a current AWS CLI/Botocore client. Pricing-plan subscription approval/purchase
and purchase-order balance/status administration can create real billing commitments, so those
mutations were not exercised against the account. Model review found no credential, workload
payload, execution, or identity-assumption return path. Billing exports, contracts, invoices,
procurement systems, payer reports, email approvals, browser history, and CloudTrail/SIEM copies are
fallbacks. No financial record, subscription, plan, approval, role, or setting was changed.

### Amazon Q console and Developer (`q`, `qdeveloper`) — 2026-09-10

These prefixes expose no directly invocable current SDK client. Conversations, OAuth-app controls,
agent sessions, artifact import/export, and code transformation were reviewed. `q:PassRequest`
allows Q to act only with the caller's existing permissions and is not an independent expansion.
Chats, source artifacts, and OAuth configuration remain Medium data. IDE/Q caches, repositories,
build artifacts, browser history, application logs, source/IaC, and CloudTrail/SIEM are fallbacks.
No conversation, app, session, artifact, transform, subscription, role, or setting was changed.

### Amazon QLDB (`qldb`) — 2026-09-10

QLDB reached full shutdown on 2025-07-31 and current AWS CLI/Botocore no longer expose its client.
Historical S3 journal exports, application database copies, source/IaC, local SDK caches, logs, and
CloudTrail/SIEM archives are fallbacks. No service resource was created or changed.

### AWS Recycle Bin (`rbin`) — 2026-09-10

Retention-rule inventory was empty. Rule administration controls recovery retention but does not
read retained resources, return credentials, or independently grant restore/use permission. IaC,
EBS/EC2 and backup inventories, policy exports, browser history, and CloudTrail/SIEM are fallbacks.

### Migration Hub Refactor Spaces (`refactor-spaces`) — 2026-09-10

A disposable environment and an exact one-action `PutResourcePolicy` role reached the service; an
empty role was denied. Multiple policies reproducing AWS's mandatory RAM environment action and
condition template were rejected before any grant took effect, so no self-grant is promoted.
Source/IaC, API Gateway, Transit Gateway/RAM inventory, deployment logs, browser history, and
CloudTrail/SIEM are identifier fallbacks. The share, role, environment, and managed-network
resources were deleted.

### Amazon Rekognition (`rekognition`) — 2026-09-10

Collection and Custom Labels project inventories were empty; stream-processor/media-analysis lists
were unavailable to this account. Faces, users, liveness results, video jobs, datasets, project
policies, and processors were reviewed. Populated results can be sensitive service data and remain
target-scoped Medium reads, not untested High claims. Source media/S3, application databases, model
datasets, client caches, logs, and CloudTrail/SIEM are fallbacks. No resource was created.

### rePost Private (`repostspace`) — 2026-09-10

Space inventory was empty. Channel, accessor, role, invitation, and admin operations manage the
collaboration workspace without returning an AWS credential or independently accessing workloads.
Workspace content remains Medium. Exports, email invitations, browser caches, support tickets,
source/IaC, application logs, and CloudTrail/SIEM are fallbacks. No resource was created.

### Amazon Bio Discovery (`researchstudio`) — 2026-09-10

There is no current SDK client or onboarded workspace. Research/project/dataset workflows expose no
standalone AWS credential or identity-assumption primitive. Existing scientific datasets may be
sensitive reads. Lab exports, notebooks, object storage, source/IaC, browser caches, logs, and
CloudTrail/SIEM are fallbacks. No resource or setting was created.

### AWS Resilience Hub (`resiliencehub`) — 2026-09-10

Application inventory was empty. Templates/resources, assessments, recommendations, resiliency
policies, imports, and metrics exports expose architecture metadata but no standalone credential or
execution primitive. IaC, Config/resource inventories, assessment exports, runbooks, browser
history, and CloudTrail/SIEM are fallbacks. No resource was created.

### Legacy Tag Editor (`resource-explorer`) — 2026-09-10

This legacy prefix has no current caller-facing SDK; Resource Explorer 2 and the Resource Groups
Tagging API provide current inventory and are reviewed separately. Their searches, service-native
inventories, AWS Config, tag exports, IaC, and CloudTrail/SIEM are fallbacks. No resource changed.

### RHEL Knowledgebase Portal (`rhelkb`) — 2026-09-10

No current SDK client exists. The prefix gates an AWS-managed Red Hat support/knowledge portal, not
customer workload APIs, and exposes no AWS credential or execution primitive. Red Hat exports,
system logs, browser caches, tickets, and local documentation mirrors are fallbacks.

### AWS RoboMaker (`robomaker`) — 2026-09-10

RoboMaker reached full shutdown on 2025-09-10 and current SDKs expose no client. Historical
simulation artifacts, S3 bundles, ROS workspaces, fleet/device state, IaC, CloudWatch logs, and
CloudTrail/SIEM archives are fallbacks. No service resource was created or changed.

### Amazon S3 Tables (`s3tables`) — 2026-09-10

Independent roles holding only `PutTablePolicy` or only `PutTableBucketPolicy` self-granted
`GetTableData`. Each changed a real 792-byte Iceberg metadata-object read from `AccessDenied` to
success; the table policy targeted one table and the bucket policy targeted `table/*`. An empty
control remained denied. Both are Critical because the policy setters independently authorize
reads of table metadata, manifests, and Parquet data objects, with bucket-wide scope for the latter.
Listing is optional: recover identifiers and warehouse paths from Glue/Athena/Redshift catalogs,
query-engine configuration, source/IaC, deployment output, logs, browser history, or CloudTrail/SIEM
copies. Both policies, tables, namespaces, buckets, exact/empty roles, and IAM policies were
deleted; exact inventories are zero.

### Route 53 recovery and resolver services — 2026-09-10

ARC clusters, control panels, recovery groups, cells, checks, resource sets, and cross-account
authorizations were empty. Route 53 Profiles were empty. Resolver endpoints, query-log configs,
firewall groups, and Outpost resolvers were empty; only AWS-managed recursive/threat-list resources
exist. Failover and DNS mutations can affect availability or routing, but no standalone credential,
identity, log-object read, or victim-VPC access path was found. IaC, Route 53 health checks, VPC
DNS/DHCP configuration, DNS/query logs, runbooks, monitoring, browser history, and CloudTrail/SIEM
copies are fallbacks. No recovery, profile, or customer Resolver resource changed.

The preview `route53globalresolver` model includes access tokens, but publishes no supported
commercial Region and its modeled endpoint is not resolvable. No token impact is promoted without
a successful controlled DNS-query test. Global Resolver client configuration, DNS logs, IaC,
deployment output, browser history, and CloudTrail/SIEM are fallbacks. No preview resource changed.

### RTB Fabric (`rtbfabric`) — 2026-09-10

Requester/responder gateway inventories were empty and the preview model publishes no supported
commercial Region. Bidstream/configuration data can be sensitive but no credential or AWS identity
primitive was found. Ad-platform exports, network captures, partner configs, IaC, application logs,
and CloudTrail/SIEM copies are fallbacks. No resource changed.

### S3 on Outposts and S3 Files (`s3-outposts`, `s3files`) — 2026-09-10

S3 on Outposts endpoints and Outposts-with-S3 inventories were empty. Endpoint lifecycle needs
physical Outposts context and does not authorize object reads. The `s3files` prefix has no current
SDK client; underlying file/object access remains governed by S3. S3/access-point inventories,
mounted filesystem/gateway configs, endpoint ENIs/DNS, IaC, device/client logs, browser downloads,
and CloudTrail/SIEM are fallbacks. No resource changed.

### SageMaker MLflow and Unified Studio MCP — 2026-09-10

MLflow tracking-server and app inventories were empty. The presigned-URL path remains documented,
but there is no target to newly isolate its UI/experiment/artifact permissions. Unified Studio MCP
has no dedicated SDK client or fixture; its modeled permissions gate hosted tool calls rather than
independently returning credentials or assuming a role. MLflow/S3 exports, Studio and IDE caches,
DataZone exports, MCP configs/tool logs, source/IaC, browser history, and CloudTrail/SIEM are
fallbacks. No app, server, MCP session, tool call, role, or setting changed.

### Savings Plans (`savingsplans`) — 2026-09-10

Plan inventory was empty. Purchase, queued-plan deletion, and eligible-plan return cause real
billing effects and were not exercised; they expose no workload credential or AWS identity. Billing
and Cost Explorer exports, invoices, contracts, payer reports, browser history, and CloudTrail/SIEM
are fallbacks. No plan or financial setting changed.

### EventBridge Schemas (`schemas`) — 2026-09-10

Only the AWS-managed `aws.events` registry exists. Customer schemas and generated bindings can be
sensitive integration metadata but provide no credential or execution primitive. Event archives,
repositories, registry exports, IaC, local SDK caches, logs, and CloudTrail/SIEM are fallbacks. No
registry, schema, discoverer, binding, or policy changed.

### AWS Supply Chain (`scn`) — 2026-09-10

Instance inventory was empty. Data-lake datasets/namespaces, integration flows/events, and bill-of-
material imports contain potentially sensitive business data but expose no standalone credential
or AWS identity primitive. ERP/EDI and data-lake exports, integration logs, IaC, browser caches, and
CloudTrail/SIEM are fallbacks. No resource changed.

### AWS Cloud Map (`servicediscovery`) — 2026-09-10

A role holding only `RegisterInstance` on one exact HTTP service overwrote the existing trusted
instance ID from `127.0.0.1` / `legitimate.internal` to `127.0.0.2` / `attacker.example`.
`DiscoverInstances` then returned only the attacker-controlled attributes; an empty role was denied.
This is High because applications that trust Cloud Map can be redirected for traffic and credential
interception. Listing is optional: recover service and instance IDs from DNS/client configuration,
ECS definitions, environment variables, source/IaC, deployment output, logs, browser history, or
CloudTrail/SIEM copies. The instance, service, namespace, exact/empty roles, and policies were
deleted; the asynchronous namespace deletion operation completed successfully and the namespace
inventory is empty.

### Amazon Textract (`textract`) — 2026-09-10

Separate exact-action roles holding only `GetDocumentTextDetection`, `GetDocumentAnalysis`, or
`GetExpenseAnalysis` recovered OCR text from jobs started by the administrator. An empty role was
denied all three. A known job ID is therefore sufficient across principals; the reader needs no S3,
start, or list action. These are High protected-document disclosures. Job IDs are available from
start responses, SNS/SQS completion messages, workflow/application state, logs, browser/client
caches, and CloudTrail/SIEM copies. A `DetectDocumentText`-only role could not OCR the private S3
object, so that separate hypothesis was not promoted. The source bucket/object and every test role
and policy were deleted; Textract has no API to delete its fixed-lifetime completed job records.

### VPC Lattice service invocation (`vpc-lattice-svcs`) — 2026-09-10

Two identically networked EC2 clients called an `AWS_IAM`-authenticated disposable Lattice service
backed by a healthy canary HTTP target. The instance role holding only `Invoke` received the exact
canary with HTTP `200`; the empty-role instance received HTTP `403` explicitly for lacking
`vpc-lattice-svcs:Invoke`. This is High direct private-application access. Listing is optional:
recover generated/custom DNS names from client/service-discovery config, DNS/Route 53, source/IaC,
environment variables, deployment output, logs, browser history, or CloudTrail/SIEM copies. Both
generations of instances were terminated; the service/network/listener/associations/auth policy,
roles/profiles, security group, local user-data file, and target group were deleted; the exact
service/network/target inventories are empty.

### AWS Support surfaces (`support-console`, `supportapp`, `supportauthz`, `supportplans`) — 2026-09-10

The account has no Premium Support subscription, so the underlying Support `DescribeCases` API
returned `SubscriptionRequiredException`. Support App Slack workspace and channel inventories were
empty. Console case-draft/help actions, Slack OAuth installation flows, support permits, registered
keys, and commercial plan agreements were reviewed. They can expose support/ticket or billing
metadata when configured, but no caller credential, customer-role assumption, or independent
workload access path was reproduced. Email/ticket exports, downloaded attachments, Slack history,
browser storage, contracts/invoices, source/IaC, and CloudTrail/SIEM copies are fallbacks. No case,
draft, attachment, Slack installation, OAuth exchange, permit, key, plan, role, or setting changed.

### AWS Sustainability (`sustainability`) — 2026-09-10

Aggregate carbon and water estimation/reporting reads expose business-usage trends and remain
Medium. They do not return a credential, protected workload payload, execution primitive, or AWS
identity. Billing/Cost Explorer exports, sustainability reports, invoices, dashboards, browser
caches, and CloudTrail/SIEM copies are fallbacks. No resource or setting changed.

### AWS Tiros (`tiros`) — 2026-09-10

Reachability-query create/extend/read actions return modeled network paths, explanations, and
account scope rather than packet/session access or credentials. The lab has no query fixture or
current SDK client. Reachability Analyzer/Network Access Analyzer results, VPC Flow Logs, Config,
topology/IaC, diagrams, deployment output, and CloudTrail/SIEM copies are fallbacks. No query,
network resource, role, or setting changed.

### AWS Transform (`transform`, `transform-custom`) — 2026-09-10

Profile, connector, agent, repository, analysis, campaign, remediation, source, transformation
package, web-app URL, and artifact/package download URL operations were reviewed. The lab has no
onboarded connector/repository/profile/artifact or current SDK client. Potential URL-backed content
is therefore not promoted without an exact-action successful retrieval. Repository/CI exports,
downloaded artifacts, browser storage, IDE caches, source/IaC, deployment logs, and CloudTrail/SIEM
copies are fallbacks. No profile, connector, agent, session, repository, analysis, package, role, or
setting changed.

### AWS Diagnostic Tools (`ts`) — 2026-09-10

The new partner-led-support API exposes tool/execution metadata and `GetExecutionOutput`; AWS says
outputs are retained for up to 30 days in the destination chosen at execution time. The lab is not
enrolled and has neither a CLI/Botocore client nor an execution fixture, so no protected-output
bypass or credential path is claimed. Execution identifiers may still be recovered from start
responses, destination configuration, partner dashboards, browser storage, application logs,
source/IaC, and CloudTrail/SIEM copies. No execution, output, destination, role, or setting changed.

### User subscriptions and console customization (`user-subscriptions`, `uxc`) — 2026-09-10

Claims, limits, usage, and entitlements manage commercial user licenses; `uxc` actions change
account colors and console presentation. These can expose billing/license metadata or alter UI but
do not return AWS credentials, assume roles, or access protected workloads. Billing/license exports,
invoices, identity-center assignments, application portals, email, screenshots, browser caches, and
CloudTrail/SIEM copies are fallbacks. No claim, entitlement, assignment, customization, or setting
changed.

### AWS Marketplace Vendor Insights (`vendor-insights`) — 2026-09-10

Security profiles, snapshots, and data sources can expose vendor compliance posture and remain
Medium. There is no entitlement/profile fixture or current SDK client, and no credential or
workload-access primitive was identified. Marketplace reports, procurement/GRC exports, downloaded
snapshots, vendor portals, browser caches, email, and CloudTrail/SIEM copies are fallbacks. No
profile, snapshot, data source, entitlement, role, or setting changed.

### Verified Access and PrivateLink dependency prefixes (`verified-access`, `vpce`) — 2026-09-10

Verified Access instances, groups, endpoints, and trust providers were empty.
`verified-access:AllowVerifiedAccess` and `vpce:AllowMultiRegion` are permission-only dependencies
consumed by the owning service workflows, not callable data-plane APIs. Neither independently
creates a session, enumerates a service, or bypasses endpoint/trust policy. Client/DNS configuration,
endpoint/ENI inventories, route tables, device/IdP logs, VPC Flow Logs, source/IaC, browser history,
and CloudTrail/SIEM copies are fallbacks. No endpoint, service, association, policy, or setting
changed.

### Retired Voice ID, WAF Classic, and WorkLink (`voiceid`, `waf`, `waf-regional`, `worklink`) — 2026-09-10

AWS fully shut down Connect Customer Voice ID on 2026-05-20; `ListDomains` now rejects the lab as
unavailable. AWS WAF Classic support ended on 2025-09-30 and both global and regional WebACL
inventories were empty. Amazon WorkLink reached full shutdown on 2021-11-30 and current SDKs expose
no client. Historical Connect recordings/exports, WAF rules and access logs, WorkLink fleet/device
configuration, ACM/DNS/IdP logs, source/IaC, browser/mobile artifacts, and CloudTrail/SIEM archives
are fallbacks. No domain, speaker, ACL, rule, fleet, device, role, or setting changed.

### AWS Well-Architected Tool (`wellarchitected`) — 2026-09-10

Workload and share-invitation inventories were empty. Answers, milestones, reports, lens reviews,
profiles, and findings can expose architecture/business metadata and remain Medium; agent/assistant
operations do not independently return credentials or execute in workloads. Downloaded reports,
diagrams, ticketing/GRC exports, source/IaC, browser storage, application logs, and CloudTrail/SIEM
copies are fallbacks. No workload, invitation, lens, profile, review, agent, role, or setting changed.

### AWS KMS (`kms`) — 2026-09-08

The isolated `kms:CreateGrant` self-grant test is blocked by the mandatory cleanup requirement. The
authorized region currently contains only AWS-managed keys; customers cannot manage grants or key
policies on those keys. Creating a customer-managed test key would leave it in `PendingDeletion`
for AWS's mandatory 7–30-day waiting period, so it could not be destroyed in this review session.
No KMS key, alias, ciphertext, grant, user, or policy was created. Existing documented KMS attack
paths remain classified, but this pass makes no new live-validation claim.

### AWS Private Certificate Authority (`acm-pca`) — 2026-09-08

The planned certificate-issuance and mTLS impersonation test is also blocked by cleanup semantics.
There is no existing private CA in the authorized region. A newly created private CA that reaches
`PENDING_CERTIFICATE` or `DISABLED` remains in a restorable `DELETED` state for a mandatory 7–30
days. Creating it would therefore violate the requirement to remove all infrastructure before the
test completes. No CA, certificate, role, user, policy, or relying service was created, and no
issuance-impact claim is added from this pass.
