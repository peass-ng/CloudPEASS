# AWS cross-service security review tracker

This queue covers trust paths that a service-only inventory misses. A row is a
hypothesis until a least-privilege principal, a permission-removed control, an
observed security effect, and complete cleanup satisfy the evidence gate in
`AWS-service-security-review.md`.

Status values are `queued`, `in_progress`, `validated`, `negative`, and
`conditional`. `Negative` means the tested generic claim did not work; it does
not mean every application-specific composition is safe.

## Mutable code and artifact consumers

| ID | Producer permission or surface | Consumer | Hypothesis | Status |
| --- | --- | --- | --- | --- |
| X001 | `s3:PutObject` | CloudFormation nested stack | Replacing a known mutable child template is applied by a later legitimate parent update under its stored service role. | validated |
| X002 | `ssm:PutParameter` | CloudFormation | Poison an `AWS::SSM::Parameter::Value<String>` value used by an IAM-sensitive property; a later update resolves the latest version. | validated |
| X003 | `glue:StartJobRun` arguments | Glue execution role | Override script or dependency locations without `iam:PassRole`. | validated |
| X004 | `s3:PutObject` | Glue dependency archive | A later trusted Glue run imports a replaced dependency under its execution role. | validated |
| X005 | `s3:PutObject` | CodeBuild | Replace a complete S3 source ZIP; a later trusted build executes its buildspec. | validated |
| X006 | `s3:PutObject` | CodePipeline and CodeBuild | Replace the version consumed by a later trusted pipeline execution. | validated |
| X007 | `s3:PutObject` | SSM `AWS-RunRemoteScript` | Replace a known script before a trusted command or State Manager run executes it on a managed node. | validated |
| X008 | `s3:PutObject` | MWAA | Exact-key overwrite of an existing DAG was automatically imported and executed by the scheduler as the MWAA execution role, without a DAG run or MWAA permission. | validated |
| X009 | `ecr:PutImage` and upload actions | App Runner auto deployment | Repoint a mutable tag and observe automatic deployment with the App Runner role. | validated |
| X010 | `ecr:PutImage` and upload actions | CodeBuild custom image | Repoint a mutable tag and observe the next ordinary build. | validated |
| X011 | `ecr:PutImage` and upload actions | AWS Batch | The next ordinary submission resolved the replacement tag; the image push itself did not create a job. | validated |
| X012 | `ecr:PutImage` and upload actions | ECS | Default task replacements stayed on the recorded digest; force-new-deployment resolved the new tag. | conditional |
| X013 | `ecr:PutImage` and upload actions | EKS | Compare `Always`, `IfNotPresent`, digest pinning, and new-node behavior. | queued |
| X014 | `ecr:PutImage` and upload actions | SageMaker | Test training, processing, inference, and notebook image consumers independently. | queued |
| X015 | `ecr:PutImage` and upload actions | Lambda container image | Determine whether any ordinary update repulls a tag or whether Lambda remains digest-pinned. | queued |
| X016 | `codeartifact:PublishPackageVersion` | CodeBuild/package client | A floating constraint selected the attacker version; an exact version pin remained on the trusted package. | validated |
| X017 | `codecommit:GitPush` | CodePipeline/CodeBuild | A source-change event ran the pushed revision automatically; with polling disabled, a later admin start consumed it. | validated |
| X018 | `s3:PutObject` | EMR bootstrap/step source | Exact-key overwrite was consumed by a later cluster bootstrap or added step under the EC2 instance role. | validated |
| X019 | `s3:PutObject` | SageMaker source bundle | Exact-key training and processing source replacements ran on later jobs under the SageMaker execution role. | validated |
| X020 | `s3:PutObject` | ECS FireLens | Replace an S3-hosted log-router configuration and prove log exfiltration or code loading, not just task failure. | queued |
| X021 | `s3:PutObject` | Elastic Beanstalk | Distinguish cached application versions from bundles fetched during rebuild/deployment. | conditional |
| X022 | `s3:PutObject` | CodeDeploy | Replace a revision consumed by a later deployment to execute lifecycle hooks on targets. | validated |
| X023 | package/image publication | Image Builder | A newer compatible component version was selected by an unchanged wildcard recipe and executed under the build instance profile. | validated |

## Stored service roles and delegated execution

| ID | Entry action | Consumer identity | Hypothesis | Status |
| --- | --- | --- | --- | --- |
| X024 | `scheduler:UpdateSchedule` / `CreateSchedule` | Scheduler execution role | Both APIs required `iam:PassRole`, including reuse of the current role; neither schedule permission is a standalone escalation. | conditional |
| X025 | `pipes:UpdatePipe` / `StartPipe` | EventBridge Pipes role | `StartPipe` reused the stored role; `UpdatePipe` required the role ARN and `iam:PassRole`. | validated |
| X026 | `states:StartExecution` | Step Functions role | Attacker-controlled input reached a preconfigured privileged task under the state-machine role. | validated |
| X027 | `appflow:StartFlow` | Preconfigured AppFlow authority | Start-only copied a private S3 source to the existing destination without source read or PassRole; disclosure still requires destination access. | validated |
| X028 | `transfer:StartFileTransfer` | Transfer connector credentials | Fetch remote content or send controlled content through stored connector credentials. | queued |
| X029 | DMS start actions | Replication roles/endpoints | Start an existing task that copies protected source data to an attacker-readable destination. | queued |
| X030 | `elasticmapreduce:AddJobFlowSteps` | EMR EC2 instance profile | Exact add-step access injected a `command-runner.jar` shell step and wrote proof as the existing cluster's instance profile without PassRole. | validated |
| X031 | `batch:SubmitJob` | Batch job role | Exact-resource submit-only access replaced the container command and executed as the existing job role without `iam:PassRole`. | validated |
| X032 | SageMaker job start/create actions | SageMaker execution role | Separate stored-role reuse from APIs that enforce caller `iam:PassRole`. | queued |
| X033 | `ssm:StartAutomationExecution` | Stored Automation role | Execute a preauthorized runbook without caller `iam:PassRole`. | validated |
| X034 | `fis:StartExperiment` | Stored FIS role | Run an attacker-modified experiment template under its configured role. | validated |
| X035 | `servicecatalog:ProvisionProduct` | Launch constraint role | Execute an attacker-controlled provisioning artifact under a stored launch role. | validated |
| X036 | `datasync:StartTaskExecution` | DataSync role | Copy protected source data through an existing task without caller `iam:PassRole`. | validated |
| X061 | `secretsmanager:RotateSecret` | Configured rotation Lambda | Trigger the existing function through the Secrets Manager service without caller `lambda:InvokeFunction`; impact depends on the fixed rotation code and role. | conditional |
| X063 | `codepipeline:StartPipelineExecution` variables | Pipeline and downstream action roles | Override a V2 pipeline variable that reaches a privileged CodeBuild/deployment action without update, build-start, or PassRole permissions. | validated |
| X065 | `lambda:PutProvisionedConcurrencyConfig` | Lambda initialization code and execution role | Allocate a published version and trigger module/static initialization without `lambda:InvokeFunction`; impact depends on initialization side effects. | conditional |
| X066 | `lambda:UpdateFunctionEventInvokeConfig` plus destination read | Lambda asynchronous destination | Redirect future request/response records to a readable SQS queue through the function role without invoke, code update, or PassRole. | validated |
| X067 | `states:SendTaskSuccess` plus a task-token source | Step Functions role | Submit callback output that a fixed subsequent service integration consumes as privileged parameters without workflow start/update permissions. | validated |
| X068 | `events:UpdateApiDestination` | EventBridge Connection authentication | Redirect an existing API Destination so its retained API-key/OAuth/basic authorization is sent to an attacker endpoint on the next legitimate matching event. | validated |

## Event and message injection

| ID | Injection permission | Consumer | Required proof | Status |
| --- | --- | --- | --- | --- |
| X037 | `sqs:SendMessage` | Lambda/event source mapping | A configured privileged consumer was triggered, but the impact depends on application interpretation. | conditional |
| X038 | `sns:Publish` | Lambda/SQS/HTTP subscription | A configured privileged consumer was triggered, but the impact depends on application interpretation. | conditional |
| X039 | `kinesis:PutRecord` | Lambda consumer | A configured privileged consumer was triggered, but the impact depends on application interpretation. | conditional |
| X040 | `dynamodb:PutItem` | Stream consumer | Put and update events triggered a privileged consumer; impact depends on application interpretation. | conditional |
| X041 | `s3:PutObject` or tagging | S3 notification/EventBridge target | Determine which event fields or object contents create generic security impact. | queued |
| X042 | `cloudwatch:PutMetricData` | Alarm actions | A namespace-scoped writer crossed a threshold and triggered the configured privileged consumer. | conditional |
| X043 | `logs:PutLogEvents` | Metric filter and alarm | An exact-stream writer injected matching logs and triggered the configured privileged consumer. | conditional |
| X044 | `iot:Publish` | IoT rule actions | Exact-topic publish-only access fed an unchanged SQL rule and caused its preconfigured Lambda to write the injected canary under its execution role. | validated |
| X045 | `events:PutEvents` plus `PutTargets` where needed | EventBridge target | Invoke a resource-policy-authorized target without caller `iam:PassRole`. | validated |
| X046 | API/data-plane invocation | Lambda or workflow integration | Separate ordinary public API behavior from IAM-enabled cross-service privilege. | queued |
| X062 | `cloudwatch:SetAlarmState` | Existing alarm action | Force an `ALARM` transition and observe CloudWatch invoke a configured Lambda without caller invoke or metric-write permissions. | conditional |
| X064 | `logs:PutSubscriptionFilter` | Lambda or cross-account Logs destination | Forward future private log records to a preauthorized destination without caller log-read, invoke, PassRole, or sink-write permissions. | conditional |

## Configuration, credentials, and cross-account policy pivots

| ID | Controllable surface | Consumer or boundary | Hypothesis | Status |
| --- | --- | --- | --- | --- |
| X047 | `secretsmanager:PutSecretValue` | CodeBuild/application | An exact secret writer changed the next build's resolved `SECRETS_MANAGER` environment value under the build role. | validated |
| X048 | `ssm:PutParameter` | CloudFormation/CodeBuild/application | An exact parameter writer changed both a later CloudFormation resolution and the next build's `PARAMETER_STORE` environment value. | validated |
| X049 | AppConfig version/deployment actions | Application fleet | `CreateHostedConfigurationVersion` poisoned an inactive immutable version; `StartDeployment` independently selected a pre-existing version for a fixed consumer. Impact remains configuration-specific. | validated |
| X050 | Glue Catalog table/location mutation | Athena/ETL/Lake Formation | Redirect readers or writers to attacker-controlled storage and observe data access or poisoning. | queued |
| X051 | Route 53 record mutation | TLS/application/service consumer | Redirect traffic and measure what authentication material or trusted callbacks cross the boundary. | queued |
| X052 | KMS alias or grant mutation | Encrypted-data consumer | Redirect a mutable alias or grant an external/synthetic principal usable cryptographic access. | queued |
| X053 | S3 access point/bucket policy mutation | External account or protected objects | Establish a denied-before data-plane read through the newly granted path. | queued |
| X054 | ECR repository policy mutation | External account and image consumer | Self-grant publication, replace a trusted tag, and observe downstream execution. | queued |
| X055 | SNS/SQS resource policy mutation | External principal | Grant publish/receive/subscribe and prove message access or injection. | queued |
| X056 | Lambda function URL/resource policy mutation | External principal | Prove unauthenticated or cross-account invocation and resulting role-only effect. | queued |
| X057 | RAM share association/acceptance | External account | Prove usable access to the shared resource, not only an accepted invitation. | queued |
| X058 | Backup copy/restore policy chain | External account/Region | Copy or restore protected data while independently denying source access. | queued |
| X059 | CloudFormation StackSets | Organization/member execution roles | Test cross-account deployment scope and exact delegated-administrator prerequisites. | queued |
| X060 | Bedrock agent invocation/input | Action-group Lambda/service role | Determine whether ordinary model input can generically drive privileged tools or only application-specific agent behavior. | queued |
| X069 | `events:UpdateConnection` | Stored OAuth client secret | Endpoint-only OAuth update was rejected because client parameters were required; omitting only the secret then failed on direct Secrets Manager authorization instead of disclosing it. | negative |
| X070 | `cognito-idp:UpdateIdentityProvider` | Stored OIDC client secret | A partial OIDC issuer redirect required all non-secret provider fields, and omitting `client_secret` cleared it rather than forwarding the previous value to the new token endpoint. | negative |
| X071 | `athena:UpdateWorkGroup` | Future Athena query principals | Redirect an enforced workgroup's later query results to attacker-readable S3 without query execution, result read, or PassRole permission. | validated |
| X072 | `glue:UpdateConnection` | Stored JDBC password | Changing only a JDBC URL, or URL plus username, failed connection-property validation; the existing password was not silently reused or sent elsewhere. | negative |
| X073 | `firehose:UpdateDestination` | Stored HTTP endpoint access key and future records | URL-only update retained the hidden access key and sent both it and the next independently produced record to the replacement HTTPS endpoint. | validated |
| X074 | `codepipeline:PutApprovalResult` | Downstream pipeline action and roles | Exact action-scoped access plus a live approval token bypassed the manual gate and caused the unchanged pipeline to invoke its privileged Lambda action. | validated |
| X075 | `cloudtrail:UpdateTrail` | Future audit-log delivery | Exact update-only access redirected a running trail; CloudTrail delivered a unique later canary event and other audit records to attacker-readable S3. | validated |
| X076 | `sagemaker:StartPipelineExecution` parameters | SageMaker pipeline role and fixed steps | Start-only access injected a parameter into an existing Lambda step, which processed it and wrote proof under its execution role without PassRole or direct invocation. | validated |
| X077 | `appsync:UpdateResolver` | Existing AppSync data-source role | Update-only access rewrote a resolver so the unchanged DynamoDB data source returned a protected canary through a separate existing API-key query path. | validated |
| X078 | `codepipeline:PutJobSuccessResult` | Downstream pipeline actions and roles | With a known acknowledged custom-job ID, result-only access falsely completed a zero-output validation gate and caused the unchanged pipeline to invoke its downstream Lambda role. | validated |
| X080 | `codepipeline:PutThirdPartyJobSuccessResult` | Downstream third-party pipeline actions | A customer pipeline accepted a pre-registered third-party gate, but even the account administrator could not poll its job because provider access is separately whitelisted; exposed execution IDs were not job IDs and result calls did not advance the gate. | negative |
| X081 | `glue:StartWorkflowRun` run properties | Existing Glue job role and trusted property sinks | Start-only access replaced a per-run property consumed by the unchanged job, which wrote proof under its execution role without PassRole or direct sink access. | validated |
| X082 | `transfer:UpdateConnector` | Secrets Manager SFTP credential and partner data | URL-only update retained the connector's role, secret reference, and trusted host key; a later connection sent the exact stored username/password to the redirected endpoint. | validated |
| X083 | `apigateway:PATCH` on an HTTP API integration | Retained API Gateway integration role and replacement backend | URI-only update preserved `CredentialsArn`; the next unsigned request invoked a preauthorized privileged Lambda that the caller could not invoke directly. | validated |
| X084 | `elasticloadbalancing:ModifyRule` | Existing target group and matching application traffic | Exact-rule update redirected only the matching request path to a pre-registered capture target; a separate POST delivered its protected header and body to the target Lambda role. | validated |
