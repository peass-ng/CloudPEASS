from CloudPEASS.permission_risk_classifier import classify_permission
from sensitive_permissions.aws import (
    live_validated_disclosure_documentation,
    sensitive_combinations,
    tested_risk_documentation,
    very_sensitive_combinations,
)


LIVE_VALIDATED_HIGH_ACTIONS = {
    "airflow-serverless:GetTaskInstance",
    "airflow-serverless:GetWorkflow",
    "airflow-serverless:GetWorkflowRun",
    "account:GetContactInformation",
    "amplify:GetApp",
    "amplify:GetArtifactUrl",
    "amplify:GetJob",
    "apigateway:GET",
    "apigateway:PATCH",
    "athena:GetQueryExecution",
    "appstream:CreateStreamingURL",
    "appconfig:GetHostedConfigurationVersion",
    "appsync:GraphQL",
    "appsync:ListApiKeys",
    "autoscaling:DescribeLaunchConfigurations",
    "batch:DescribeJobDefinitions",
    "bedrock:Retrieve",
    "bedrock-agentcore:GetWorkloadAccessTokenForUserId",
    "b2bi:GetProfile",
    "b2bi:GetTransformer",
    "cloudformation:DescribeStacks",
    "cloudformation:DescribeChangeSet",
    "cloudformation:GetTemplate",
    "cloudformation:GetTemplateSummary",
    "cloudformation:ListExports",
    "cloudfront:GetDistribution",
    "cloudfront:GetDistributionConfig",
    "cloudfront:GetFunction",
    "cloudfront:ListDistributions",
    "cloudtrail:LookupEvents",
    "ce:GetCostAndUsage",
    "budgets:ViewBudget",
    "aws-portal:ViewBilling",
    "aws-marketplace:SearchAgreements",
    "aws-marketplace:DescribeAgreement",
    "aws-marketplace:GetAgreementTerms",
    "codebuild:BatchGetBuilds",
    "codebuild:BatchGetProjects",
    "codeartifact:GetPackageVersionAsset",
    "codecommit:GetBlob",
    "codecommit:GetCommit",
    "codecommit:GetFile",
    "codecommit:GitPull",
    "codepipeline:PollForJobs",
    "chime:GetChannelMessage",
    "chime:ListChannelMessages",
    "connect:BatchDescribeDataTableValue",
    "connect:EvaluateDataTableValues",
    "connect:GetAttachedFile",
    "connect:GetContactAttributes",
    "connect:GetFederationToken",
    "cognito-idp:AdminGetUser",
    "cognito-idp:DescribeUserPoolClient",
    "cognito-idp:DescribeIdentityProvider",
    "cognito-idp:ListUsers",
    "cognito-idp:ListUsersInGroup",
    "dynamodb:BatchGetItem",
    "dynamodb:GetItem",
    "dynamodb:Query",
    "dynamodb:Scan",
    "dynamodb:TransactGetItems",
    "deadline:AssumeQueueRoleForRead",
    "deadline:AssumeQueueRoleForUser",
    "datazone:GetEnvironmentCredentials",
    "dms:ModifyEndpoint",
    "ec2:DescribeLaunchTemplateVersions",
    "ec2:DescribeInstanceAttribute",
    "elasticloadbalancing:ModifyListener",
    "elemental-inference:ExportDictionaryEntries",
    "elemental-inference:GetMetadata",
    "ebs:GetSnapshotBlock",
    "ecr:GetDownloadUrlForLayer",
    "ecs:DescribeTaskDefinition",
    "ecs:DescribeTasks",
    "emr-serverless:GetApplication",
    "emr-serverless:GetJobRun",
    "events:ListTargetsByRule",
    "firehose:UpdateDestination",
    "frauddetector:GetEvent",
    "execute-api:Invoke",
    "glue:GetConnection",
    "glue:GetJob",
    "glue:GetWorkflowRunProperties",
    "geo:GetDevicePosition",
    "geo:GetDevicePositionHistory",
    "greengrass:GetComponentVersionArtifact",
    "healthlake:ReadResource",
    "healthlake:SearchEverything",
    "healthlake:SearchWithGet",
    "healthlake:SearchWithPost",
    "imagebuilder:GetComponent",
    "iot:GetThingShadow",
    "iot:StartCommandExecution",
    "iotjobsdata:DescribeJobExecution",
    "iotjobsdata:StartNextPendingJobExecution",
    "iotjobsdata:UpdateJobExecution",
    "ivs:BatchGetStreamKey",
    "ivs:CreateStreamKey",
    "ivs:GetStreamKey",
    "ivs:UpdateChannel",
    "lakeformation:PutDataLakeSettings",
    "m2:GetSignedBluinsightsUrl",
    "mediaconnect:AddFlowOutputs",
    "mediaconnect:DescribeFlowSourceThumbnail",
    "mediaconnect:UpdateFlowOutput",
    "medialive:DescribeThumbnails",
    "medialive:UpdateChannel",
    "mediapackagev2:PutChannelPolicy",
    "mediapackagev2:PutOriginEndpointPolicy",
    "notifications:GetManagedNotificationEvent",
    "notifications:ListManagedNotificationEvents",
    "mq:CreateUser",
    "mq:UpdateUser",
    "iotwireless:GetWirelessDevice",
    "iotsitewise:BatchGetAssetPropertyAggregates",
    "iotsitewise:BatchGetAssetPropertyValue",
    "iotsitewise:BatchGetAssetPropertyValueHistory",
    "iotsitewise:GetAssetPropertyAggregates",
    "iotsitewise:GetAssetPropertyValue",
    "iotsitewise:GetAssetPropertyValueHistory",
    "iotsitewise:GetInterpolatedAssetPropertyValues",
    "ivschat:CreateChatToken",
    "kinesis:GetRecords",
    "kinesisanalytics:DescribeApplication",
    "kinesisvideo:GetClip",
    "kinesisvideo:GetDASHStreamingSessionURL",
    "kinesisvideo:GetHLSStreamingSessionURL",
    "kinesisvideo:GetImages",
    "kinesisvideo:GetMedia",
    "kinesisvideo:GetMediaForFragmentList",
    "lambda:GetFunctionConfiguration",
    "lambda:GetLayerVersion",
    "logs:FilterLogEvents",
    "logs:GetLogRecord",
    "logs:GetLogEvents",
    "logs:GetQueryResults",
    "medical-imaging:GetImageFrame",
    "medical-imaging:GetImageSetMetadata",
    "omics:GetReadSet",
    "invoicing:BatchGetInvoiceProfile",
    "invoicing:GetInvoicePDF",
    "invoicing:ListInvoiceSummaries",
    "sagemaker:DescribeModel",
    "sagemaker:DescribeTrainingJob",
    "s3:GetDataAccess",
    "s3vectors:GetVectors",
    "s3express:CreateSession",
    "scheduler:GetSchedule",
    "servicediscovery:RegisterInstance",
    "pipes:DescribePipe",
    "profile:SearchProfiles",
    "rum:GetAppMonitorData",
    "route53domains:GetDomainDetail",
    "sdb:GetAttributes",
    "sdb:Select",
    "ses:GetSuppressedDestination",
    "ses:GetEmailTemplate",
    "ses:ListSuppressedDestinations",
    "sns:ListSubscriptions",
    "sns:ListSubscriptionsByTopic",
    "sqs:ReceiveMessage",
    "ssm:GetParameterHistory",
    "ssm:GetDocument",
    "ssm:GetOpsItem",
    "states:DescribeStateMachine",
    "states:DescribeExecution",
    "states:GetActivityTask",
    "states:GetExecutionHistory",
    "sts:GetFederationToken",
    "tax:GetTaxRegistration",
    "tax:ListTaxRegistrations",
    "textract:GetDocumentAnalysis",
    "textract:GetDocumentTextDetection",
    "textract:GetExpenseAnalysis",
    "transcribe:GetTranscriptionJob",
    "transfer:ImportSshPublicKey",
    "translate:GetParallelData",
    "translate:GetTerminology",
    "vpc-lattice-svcs:Invoke",
    "wisdom:GetContent",
}


def test_live_validated_disclosures_are_high():
    for action in LIVE_VALIDATED_HIGH_ACTIONS:
        assert classify_permission(
            "aws", action, unknown_default="medium"
        ) == "high"


def test_live_validated_disclosures_have_single_action_findings():
    combinations = {tuple(combination) for combination in sensitive_combinations}
    for action in LIVE_VALIDATED_HIGH_ACTIONS:
        assert (action,) in combinations


def test_live_validated_mwaa_serverless_sensitive_workflow_reads():
    document = "aws-post-exploitation/aws-mwaa-post-exploitation/README.md"
    for action in (
        "airflow-serverless:GetTaskInstance",
        "airflow-serverless:GetWorkflow",
        "airflow-serverless:GetWorkflowRun",
    ):
        assert classify_permission("aws", action, unknown_default="medium") == "high"
        assert [action] in sensitive_combinations
        assert tested_risk_documentation[action] == document
        assert live_validated_disclosure_documentation[action] == document


def test_live_validated_appstream_image_builder_role_takeover():
    action = "appstream:CreateImageBuilderStreamingURL"
    document = "aws-services/aws-workspaces-enum.md"
    assert [action] in very_sensitive_combinations
    assert classify_permission("aws", action, unknown_default="medium") == "critical"
    assert tested_risk_documentation[action] == document
    assert live_validated_disclosure_documentation[action] == document


def test_live_validated_disclosures_have_service_specific_evidence():
    for action in LIVE_VALIDATED_HIGH_ACTIONS:
        document = live_validated_disclosure_documentation[action]
        assert document.endswith(".md")
        assert document.startswith(
            (
                "aws-post-exploitation/",
                "aws-privilege-escalation/",
                "aws-services/",
            )
        )


def test_live_validated_chime_message_disclosures():
    actions = ("chime:GetChannelMessage", "chime:ListChannelMessages")
    for action in actions:
        assert classify_permission(
            "aws", action, unknown_default="medium"
        ) == "high"
        assert live_validated_disclosure_documentation[action] == (
            "aws-services/aws-chime-sdk-enum.md"
        )


def test_live_validated_b2bi_disclosures():
    actions = ("b2bi:GetProfile", "b2bi:GetTransformer")
    for action in actions:
        assert classify_permission(
            "aws", action, unknown_default="medium"
        ) == "high"
        assert live_validated_disclosure_documentation[action] == (
            "aws-services/aws-b2b-data-interchange-enum.md"
        )


def test_live_validated_connect_data_disclosures():
    actions = (
        "connect:BatchDescribeDataTableValue",
        "connect:EvaluateDataTableValues",
        "connect:GetContactAttributes",
    )
    for action in actions:
        assert classify_permission(
            "aws", action, unknown_default="medium"
        ) == "high"
        assert live_validated_disclosure_documentation[action] == (
            "aws-services/aws-connect-enum.md"
        )


def test_live_validated_kinesis_video_disclosures():
    actions = (
        "kinesisvideo:GetClip",
        "kinesisvideo:GetDASHStreamingSessionURL",
        "kinesisvideo:GetHLSStreamingSessionURL",
        "kinesisvideo:GetImages",
        "kinesisvideo:GetMedia",
        "kinesisvideo:GetMediaForFragmentList",
    )
    for action in actions:
        assert classify_permission(
            "aws", action, unknown_default="medium"
        ) == "high"
        assert live_validated_disclosure_documentation[action] == (
            "aws-services/aws-kinesis-video-streams-enum.md"
        )


def test_live_validated_healthlake_fhir_disclosures():
    actions = (
        "healthlake:ReadResource",
        "healthlake:SearchEverything",
        "healthlake:SearchWithGet",
        "healthlake:SearchWithPost",
    )
    for action in actions:
        assert classify_permission(
            "aws", action, unknown_default="medium"
        ) == "high"
        assert live_validated_disclosure_documentation[action] == (
            "aws-services/aws-healthlake-enum.md"
        )


def test_live_validated_iot_sitewise_disclosures():
    actions = (
        "iotsitewise:BatchGetAssetPropertyAggregates",
        "iotsitewise:BatchGetAssetPropertyValue",
        "iotsitewise:BatchGetAssetPropertyValueHistory",
        "iotsitewise:GetAssetPropertyAggregates",
        "iotsitewise:GetAssetPropertyValue",
        "iotsitewise:GetAssetPropertyValueHistory",
        "iotsitewise:GetInterpolatedAssetPropertyValues",
    )
    for action in actions:
        assert classify_permission(
            "aws", action, unknown_default="medium"
        ) == "high"
        assert live_validated_disclosure_documentation[action] == (
            "aws-services/aws-iot-sitewise-enum.md"
        )


def test_live_validated_iot_twinmaker_read_requires_metadata_prerequisites():
    combination = (
        "iottwinmaker:GetWorkspace",
        "iottwinmaker:GetComponentType",
        "iottwinmaker:GetPropertyValue",
    )
    combinations = {tuple(candidate) for candidate in sensitive_combinations}
    assert combination in combinations
    for action in combination:
        assert (action,) not in combinations
        assert classify_permission(
            "aws", action, unknown_default="medium"
        ) == "low"
        assert live_validated_disclosure_documentation[action] == (
            "aws-services/aws-iot-twinmaker-enum.md"
        )


def test_live_validated_simpledb_disclosures():
    actions = ("sdb:GetAttributes", "sdb:Select")
    for action in actions:
        assert classify_permission(
            "aws", action, unknown_default="medium"
        ) == "high"
        assert live_validated_disclosure_documentation[action] == (
            "aws-services/aws-simpledb-enum.md"
        )


def test_live_validated_appconfig_data_disclosure_requires_both_actions():
    combination = (
        "appconfig:StartConfigurationSession",
        "appconfig:GetLatestConfiguration",
    )
    combinations = {tuple(candidate) for candidate in sensitive_combinations}
    assert combination in combinations
    assert (combination[0],) not in combinations
    assert (combination[1],) not in combinations
    for action in combination:
        assert live_validated_disclosure_documentation[action] == (
            "aws-services/aws-appconfig-enum.md"
        )


def test_live_validated_iot_mqtt_read_requires_full_broker_path():
    combination = ("iot:Connect", "iot:Subscribe", "iot:Receive")
    combinations = {tuple(candidate) for candidate in sensitive_combinations}
    assert combination in combinations
    for action in combination:
        assert (action,) not in combinations
        assert live_validated_disclosure_documentation[action] == (
            "aws-services/aws-iot-core-enum.md"
        )


def test_live_validated_backup_restore_requires_passrole():
    combination = ("backup:StartRestoreJob", "iam:PassRole")
    combinations = {tuple(candidate) for candidate in sensitive_combinations}
    assert combination in combinations
    assert (combination[0],) not in combinations
    assert classify_permission(
        "aws", combination[0], unknown_default="medium"
    ) == "medium"
    assert classify_permission(
        "aws", combination[1], unknown_default="medium"
    ) == "critical"
    assert live_validated_disclosure_documentation[combination[0]] == (
        "aws-post-exploitation/aws-backup-post-exploitation/README.md"
    )


def test_live_validated_backup_vault_policy_self_grant_and_deletion():
    policy_action = "backup:PutBackupVaultAccessPolicy"
    deletion_action = "backup:DeleteRecoveryPoint"
    assert [policy_action] in very_sensitive_combinations
    assert [deletion_action] in sensitive_combinations
    assert classify_permission(
        "aws", policy_action, unknown_default="medium"
    ) == "critical"
    assert classify_permission(
        "aws", deletion_action, unknown_default="medium"
    ) == "high"


def test_live_validated_codebuild_sandbox_command_role_takeover():
    action = "codebuild:StartCommandExecution"
    assert [action] in very_sensitive_combinations
    assert classify_permission("aws", action, unknown_default="medium") == "critical"
    expected_document = "aws-privilege-escalation/aws-codebuild-privesc/README.md"
    assert tested_risk_documentation[action] == expected_document
    assert live_validated_disclosure_documentation[action] == expected_document


def test_live_validated_backup_access_point_requires_full_policy_chain():
    combination = (
        "backup:CreateBackupAccessPoint",
        "backup:DescribeBackupAccessPoint",
        "s3:CreateAccessPoint",
        "s3:GetAccessPoint",
        "s3:PutAccessPointPolicy",
    )
    sensitive = {tuple(candidate) for candidate in sensitive_combinations}
    critical = {tuple(candidate) for candidate in very_sensitive_combinations}
    assert combination in sensitive
    assert ("s3:PutAccessPointPolicy",) in critical
    assert ("backup:CreateBackupAccessPoint",) not in sensitive
    assert ("backup:DescribeBackupAccessPoint",) not in sensitive
    assert classify_permission(
        "aws", "backup:CreateBackupAccessPoint", unknown_default="medium"
    ) == "medium"
    assert classify_permission(
        "aws", "backup:DescribeBackupAccessPoint", unknown_default="medium"
    ) == "low"
    assert classify_permission(
        "aws", "s3:PutAccessPointPolicy", unknown_default="medium"
    ) == "critical"
    for action in combination:
        assert live_validated_disclosure_documentation[action] == (
            "aws-post-exploitation/aws-backup-post-exploitation/README.md"
        )


def test_live_validated_service_catalog_launch_role_escalation_requires_pair():
    combination = (
        "servicecatalog:CreateProvisioningArtifact",
        "servicecatalog:ProvisionProduct",
    )
    critical = {tuple(candidate) for candidate in very_sensitive_combinations}
    assert combination in critical
    assert (combination[0],) not in critical
    assert (combination[1],) not in critical
    for action in combination:
        assert classify_permission(
            "aws", action, unknown_default="medium"
        ) == "medium"
        assert live_validated_disclosure_documentation[action] == (
            "aws-privilege-escalation/aws-service-catalog-privesc/README.md"
        )


def test_live_validated_image_builder_wildcard_component_escalation_requires_pair():
    combination = (
        "imagebuilder:CreateComponent",
        "imagebuilder:StartImagePipelineExecution",
    )
    critical = {tuple(candidate) for candidate in very_sensitive_combinations}
    assert combination in critical
    assert (combination[0],) not in critical
    assert (combination[1],) not in critical
    for action in combination:
        assert classify_permission(
            "aws", action, unknown_default="medium"
        ) == "medium"
        assert live_validated_disclosure_documentation[action] == (
            "aws-privilege-escalation/aws-ec2-image-builder-privesc/README.md"
        )


def test_live_validated_codedeploy_instance_profile_escalation_requires_chain():
    combination = (
        "codedeploy:CreateDeployment",
        "codedeploy:GetDeploymentConfig",
        "codedeploy:RegisterApplicationRevision",
    )
    critical = {tuple(candidate) for candidate in very_sensitive_combinations}
    assert combination in critical
    for action in combination:
        assert (action,) not in critical
        assert live_validated_disclosure_documentation[action] == (
            "aws-privilege-escalation/aws-codedeploy-privesc/README.md"
        )
    assert classify_permission(
        "aws", combination[0], unknown_default="medium"
    ) == "medium"
    assert classify_permission(
        "aws", combination[1], unknown_default="medium"
    ) == "low"
    assert classify_permission(
        "aws", combination[2], unknown_default="medium"
    ) == "medium"


def test_live_validated_ssm_stored_automation_role_escalation():
    action = "ssm:StartAutomationExecution"
    critical = {tuple(candidate) for candidate in very_sensitive_combinations}
    assert (action,) in critical
    assert classify_permission(
        "aws", action, unknown_default="medium"
    ) == "critical"
    assert tested_risk_documentation[action] == (
        "aws-privilege-escalation/aws-ssm-privesc/README.md"
    )
    assert live_validated_disclosure_documentation[action] == (
        "aws-privilege-escalation/aws-ssm-privesc/README.md"
    )


def test_live_validated_signer_lambda_code_signing_bypass():
    action = "signer:StartSigningJob"
    high = {tuple(candidate) for candidate in sensitive_combinations}
    assert (action,) in high
    assert classify_permission(
        "aws", action, unknown_default="medium"
    ) == "high"
    assert tested_risk_documentation[action] == (
        "aws-privilege-escalation/aws-lambda-privesc/README.md"
    )
    assert live_validated_disclosure_documentation[action] == (
        "aws-privilege-escalation/aws-lambda-privesc/README.md"
    )


def test_live_validated_eventbridge_target_attachment_escalation_requires_pair():
    combination = ("events:PutTargets", "events:PutEvents")
    critical = {tuple(candidate) for candidate in very_sensitive_combinations}
    assert combination in critical
    for action in combination:
        assert (action,) not in critical
        assert classify_permission(
            "aws", action, unknown_default="medium"
        ) == "medium"
        assert live_validated_disclosure_documentation[action] == (
            "aws-privilege-escalation/aws-eventbridge-privesc/README.md"
        )


def test_live_validated_roles_anywhere_trust_anchor_replacement():
    action = "rolesanywhere:UpdateTrustAnchor"
    critical = {tuple(candidate) for candidate in very_sensitive_combinations}
    assert (action,) in critical
    assert classify_permission(
        "aws", action, unknown_default="medium"
    ) == "critical"
    assert live_validated_disclosure_documentation[action] == (
        "aws-privilege-escalation/aws-sts-privesc/README.md"
    )


def test_live_validated_sagemaker_lifecycle_takeover():
    action = "sagemaker:UpdateNotebookInstanceLifecycleConfig"
    critical = {tuple(candidate) for candidate in very_sensitive_combinations}
    assert (action,) in critical
    assert classify_permission(
        "aws", action, unknown_default="medium"
    ) == "critical"
    assert live_validated_disclosure_documentation[action] == (
        "aws-persistence/aws-sagemaker-persistence/README.md"
    )


def test_live_validated_secrets_manager_resource_policy_self_grant():
    action = "secretsmanager:PutResourcePolicy"
    critical = {tuple(candidate) for candidate in very_sensitive_combinations}
    assert (action,) in critical
    assert classify_permission(
        "aws", action, unknown_default="medium"
    ) == "critical"
    assert live_validated_disclosure_documentation[action] == (
        "aws-privilege-escalation/aws-secrets-manager-privesc/README.md"
    )


def test_live_validated_dynamodb_resource_policy_self_grant():
    action = "dynamodb:PutResourcePolicy"
    critical = {tuple(candidate) for candidate in very_sensitive_combinations}
    assert (action,) in critical
    assert classify_permission(
        "aws", action, unknown_default="medium"
    ) == "critical"
    assert live_validated_disclosure_documentation[action] == (
        "aws-privilege-escalation/aws-dynamodb-privesc/README.md"
    )


def test_live_validated_sqs_queue_policy_self_grant():
    action = "sqs:SetQueueAttributes"
    critical = {tuple(candidate) for candidate in very_sensitive_combinations}
    assert (action,) in critical
    assert classify_permission(
        "aws", action, unknown_default="medium"
    ) == "critical"
    assert live_validated_disclosure_documentation[action] == (
        "aws-post-exploitation/aws-sqs-post-exploitation/README.md"
    )


def test_live_validated_sns_topic_policy_subscription_self_grant():
    action = "sns:SetTopicAttributes"
    critical = {tuple(candidate) for candidate in very_sensitive_combinations}
    assert (action,) in critical
    assert classify_permission(
        "aws", action, unknown_default="medium"
    ) == "critical"
    assert live_validated_disclosure_documentation[action] == (
        "aws-post-exploitation/aws-sns-post-exploitation/README.md"
    )


def test_live_validated_iam_cross_user_access_key_takeover():
    action = "iam:CreateAccessKey"
    critical = {tuple(candidate) for candidate in very_sensitive_combinations}
    assert (action,) in critical
    assert classify_permission(
        "aws", action, unknown_default="medium"
    ) == "critical"
    assert live_validated_disclosure_documentation[action] == (
        "aws-privilege-escalation/aws-iam-privesc/README.md"
    )


def test_live_validated_route53_existing_zone_record_takeover():
    action = "route53:ChangeResourceRecordSets"
    high = {tuple(candidate) for candidate in sensitive_combinations}
    assert (action,) in high
    assert classify_permission(
        "aws", action, unknown_default="medium"
    ) == "high"
    assert live_validated_disclosure_documentation[action] == (
        "aws-services/aws-route53-enum.md"
    )


def test_live_validated_elbv2_listener_redirect_takeover():
    action = "elasticloadbalancing:ModifyListener"
    high = {tuple(candidate) for candidate in sensitive_combinations}
    assert (action,) in high
    assert classify_permission(
        "aws", action, unknown_default="medium"
    ) == "high"
    assert live_validated_disclosure_documentation[action] == (
        "aws-services/aws-ec2-ebs-elb-ssm-vpc-and-vpn-enum/README.md"
    )


def test_live_validated_cognito_identity_public_role_credentials():
    action = "cognito-identity:UpdateIdentityPool"
    critical = {tuple(candidate) for candidate in very_sensitive_combinations}
    assert (action,) in critical
    assert classify_permission(
        "aws", action, unknown_default="medium"
    ) == "critical"
    assert live_validated_disclosure_documentation[action] == (
        "aws-services/aws-cognito-enum/cognito-identity-pools.md"
    )


def test_live_validated_ec2_security_group_replacement():
    action = "ec2:ModifyInstanceAttribute"
    critical = {tuple(candidate) for candidate in very_sensitive_combinations}
    assert (action,) in critical
    assert classify_permission(
        "aws", action, unknown_default="medium"
    ) == "critical"
    assert live_validated_disclosure_documentation[action] == (
        "aws-privilege-escalation/aws-ec2-privesc/README.md"
    )


def test_live_validated_route53_domain_registration_disclosure():
    action = "route53domains:GetDomainDetail"
    high = {tuple(candidate) for candidate in sensitive_combinations}
    assert (action,) in high
    assert classify_permission(
        "aws", action, unknown_default="medium"
    ) == "high"
    assert live_validated_disclosure_documentation[action] == (
        "aws-privilege-escalation/aws-route53-domains-privesc/README.md"
    )


def test_live_validated_acm_private_key_export():
    action = "acm:ExportCertificate"
    critical = {tuple(candidate) for candidate in very_sensitive_combinations}
    assert (action,) in critical
    assert classify_permission(
        "aws", action, unknown_default="medium"
    ) == "critical"
    assert live_validated_disclosure_documentation[action] == (
        "aws-services/aws-certificate-manager-acm-and-private-certificate-authority-pca.md"
    )


def test_live_validated_eks_access_entry_cluster_admin_pair():
    combination = ("eks:CreateAccessEntry", "eks:AssociateAccessPolicy")
    critical = {tuple(candidate) for candidate in very_sensitive_combinations}
    assert combination in critical
    for action in combination:
        assert live_validated_disclosure_documentation[action] == (
            "aws-post-exploitation/aws-eks-post-exploitation/README.md"
        )


def test_live_validated_opensearch_domain_policy_takeover():
    action = "es:UpdateDomainConfig"
    critical = {tuple(candidate) for candidate in very_sensitive_combinations}
    assert (action,) in critical
    assert classify_permission(
        "aws", action, unknown_default="medium"
    ) == "critical"
    assert live_validated_disclosure_documentation[action] == (
        "aws-services/aws-opensearch-enum.md"
    )


def test_live_validated_eks_pod_identity_token_exchange():
    action = "eks-auth:AssumeRoleForPodIdentity"
    critical = {tuple(candidate) for candidate in very_sensitive_combinations}
    assert (action,) in critical
    assert classify_permission(
        "aws", action, unknown_default="medium"
    ) == "critical"
    assert live_validated_disclosure_documentation[action] == (
        "aws-post-exploitation/aws-eks-post-exploitation/README.md"
    )


def test_live_validated_redshift_single_action_database_credentials():
    critical = {tuple(candidate) for candidate in very_sensitive_combinations}
    for action in (
        "redshift:GetClusterCredentials",
        "redshift:GetClusterCredentialsWithIAM",
    ):
        assert (action,) in critical
        assert classify_permission(
            "aws", action, unknown_default="medium"
        ) == "critical"
        assert live_validated_disclosure_documentation[action] == (
            "aws-privilege-escalation/aws-redshift-privesc/README.md"
        )


def test_live_validated_rds_password_takeover_and_iam_database_access():
    critical = {tuple(candidate) for candidate in very_sensitive_combinations}
    high = {tuple(candidate) for candidate in sensitive_combinations}

    modify_action = "rds:ModifyDBInstance"
    assert (modify_action,) in critical
    assert classify_permission(
        "aws", modify_action, unknown_default="medium"
    ) == "critical"

    connect_action = "rds-db:connect"
    assert (connect_action,) in high
    assert classify_permission(
        "aws", connect_action, unknown_default="medium"
    ) == "high"

    for action in (modify_action, connect_action):
        assert live_validated_disclosure_documentation[action] == (
            "aws-privilege-escalation/aws-rds-privesc/README.md"
        )


def test_live_validated_amp_workspace_policy_self_grant():
    action = "aps:PutResourcePolicy"
    critical = {tuple(candidate) for candidate in very_sensitive_combinations}
    assert (action,) in critical
    assert classify_permission(
        "aws", action, unknown_default="medium"
    ) == "critical"
    assert live_validated_disclosure_documentation[action] == (
        "aws-services/aws-managed-prometheus-enum.md"
    )


def test_live_validated_cloudwatch_dashboard_disclosure():
    action = "cloudwatch:GetDashboard"
    high = {tuple(candidate) for candidate in sensitive_combinations}
    assert (action,) in high
    assert classify_permission(
        "aws", action, unknown_default="medium"
    ) == "high"
    assert live_validated_disclosure_documentation[action] == (
        "aws-services/aws-security-and-detection-services/aws-cloudwatch-enum.md"
    )


def test_live_validated_budget_disclosure_uses_view_budget_iam_action():
    action = "budgets:ViewBudget"
    high = {tuple(candidate) for candidate in sensitive_combinations}
    assert (action,) in high
    assert classify_permission(
        "aws", action, unknown_default="medium"
    ) == "high"
    assert live_validated_disclosure_documentation[action] == (
        "aws-services/aws-security-and-detection-services/aws-cost-explorer-enum.md"
    )


def test_live_validated_legacy_billing_console_permission_discloses_credits():
    action = "aws-portal:ViewBilling"
    high = {tuple(candidate) for candidate in sensitive_combinations}
    assert (action,) in high
    assert classify_permission(
        "aws", action, unknown_default="medium"
    ) == "high"
    assert live_validated_disclosure_documentation[action] == (
        "aws-services/aws-security-and-detection-services/aws-cost-explorer-enum.md"
    )


def test_live_validated_marketplace_agreement_disclosures_are_independent():
    actions = (
        "aws-marketplace:SearchAgreements",
        "aws-marketplace:DescribeAgreement",
        "aws-marketplace:GetAgreementTerms",
    )
    high = {tuple(candidate) for candidate in sensitive_combinations}
    for action in actions:
        assert (action,) in high
        assert classify_permission(
            "aws", action, unknown_default="medium"
        ) == "high"
        assert live_validated_disclosure_documentation[action] == (
            "aws-services/aws-marketplace-enum.md"
        )


def test_live_validated_ecr_public_repository_policy_self_grant():
    action = "ecr-public:SetRepositoryPolicy"
    critical = {tuple(candidate) for candidate in very_sensitive_combinations}
    assert (action,) in critical
    assert classify_permission(
        "aws", action, unknown_default="medium"
    ) == "critical"
    assert live_validated_disclosure_documentation[action] == (
        "aws-privilege-escalation/aws-ecr-privesc/README.md"
    )


def test_live_validated_datasync_delegated_copy_requires_destination_access():
    action = "datasync:StartTaskExecution"
    combination = (action, "s3:GetObject")
    high = {tuple(candidate) for candidate in sensitive_combinations}
    assert combination in high
    assert classify_permission(
        "aws", action, unknown_default="medium"
    ) == "high"
    assert live_validated_disclosure_documentation[action] == (
        "aws-services/aws-datasync-enum.md"
    )


def test_live_validated_grafana_admin_token_minting():
    actions = (
        "grafana:CreateWorkspaceApiKey",
        "grafana:CreateWorkspaceServiceAccountToken",
    )
    critical = {tuple(candidate) for candidate in very_sensitive_combinations}
    for action in actions:
        assert (action,) in critical
        assert classify_permission(
            "aws", action, unknown_default="medium"
        ) == "critical"
        assert live_validated_disclosure_documentation[action] == (
            "aws-services/aws-managed-grafana-enum.md"
        )


def test_live_validated_firehose_destination_redirect_reuses_delivery_role():
    action = "firehose:UpdateDestination"
    high = {tuple(candidate) for candidate in sensitive_combinations}
    assert (action,) in high
    assert classify_permission(
        "aws", action, unknown_default="medium"
    ) == "high"
    assert live_validated_disclosure_documentation[action] == (
        "aws-services/aws-kinesis-data-firehose-enum.md"
    )


def test_live_validated_dms_s3_endpoint_redirect_reuses_access_role():
    action = "dms:ModifyEndpoint"
    high = {tuple(candidate) for candidate in sensitive_combinations}
    assert (action,) in high
    assert classify_permission(
        "aws", action, unknown_default="medium"
    ) == "high"
    assert live_validated_disclosure_documentation[action] == (
        "aws-services/aws-dms-enum.md"
    )


def test_live_validated_docdb_elastic_admin_password_takeover():
    action = "docdb-elastic:UpdateCluster"
    critical = {tuple(candidate) for candidate in very_sensitive_combinations}
    assert (action,) in critical
    assert classify_permission(
        "aws", action, unknown_default="medium"
    ) == "critical"
    assert live_validated_disclosure_documentation[action] == (
        "aws-services/aws-documentdb-enum/README.md"
    )


def test_live_validated_elasticache_modify_user_password_takeover():
    action = "elasticache:ModifyUser"
    high = {tuple(candidate) for candidate in sensitive_combinations}
    assert (action,) in high
    assert classify_permission(
        "aws", action, unknown_default="medium"
    ) == "high"
    assert live_validated_disclosure_documentation[action] == (
        "aws-services/aws-elasticache.md"
    )


def test_live_validated_memorydb_update_user_password_takeover():
    action = "memorydb:UpdateUser"
    high = {tuple(candidate) for candidate in sensitive_combinations}
    assert (action,) in high
    assert classify_permission(
        "aws", action, unknown_default="medium"
    ) == "high"
    assert live_validated_disclosure_documentation[action] == (
        "aws-services/aws-memorydb-enum.md"
    )


def test_live_validated_msk_authentication_bypass_and_topic_read():
    critical = {tuple(candidate) for candidate in very_sensitive_combinations}
    high = {tuple(candidate) for candidate in sensitive_combinations}
    update_action = "kafka:UpdateSecurity"
    reader = (
        "kafka-cluster:Connect",
        "kafka-cluster:DescribeTopic",
        "kafka-cluster:ReadData",
        "kafka-cluster:DescribeGroup",
        "kafka-cluster:AlterGroup",
    )

    assert (update_action,) in critical
    assert classify_permission(
        "aws", update_action, unknown_default="medium"
    ) == "critical"
    assert reader in high
    assert live_validated_disclosure_documentation[update_action] == (
        "aws-privilege-escalation/aws-msk-privesc/README.md"
    )
    for action in reader:
        assert live_validated_disclosure_documentation[action] == (
            "aws-services/aws-msk-enum.md"
        )


def test_live_validated_synthetics_dry_run_role_reuse_requires_full_chain():
    combination = (
        "synthetics:StartCanaryDryRun",
        "lambda:GetFunctionConfiguration",
        "lambda:PublishLayerVersion",
        "lambda:GetLayerVersion",
        "lambda:UpdateFunctionConfiguration",
        "lambda:PublishVersion",
        "lambda:AddPermission",
        "iam:PassRole",
    )
    critical = {tuple(candidate) for candidate in very_sensitive_combinations}
    high = {tuple(candidate) for candidate in sensitive_combinations}

    assert combination in critical
    assert (combination[0],) not in critical
    assert (combination[0],) not in high
    assert classify_permission(
        "aws", combination[0], unknown_default="medium"
    ) == "medium"
    assert tested_risk_documentation[combination[0]] == (
        "aws-privilege-escalation/aws-synthetics-privesc/README.md"
    )


def test_live_validated_transfer_ssh_key_injection():
    action = "transfer:ImportSshPublicKey"
    high = {tuple(candidate) for candidate in sensitive_combinations}

    assert (action,) in high
    assert classify_permission(
        "aws", action, unknown_default="medium"
    ) == "high"
    assert live_validated_disclosure_documentation[action] == (
        "aws-privilege-escalation/aws-transfer-family-privesc/README.md"
    )


def test_live_validated_lightsail_credential_and_bucket_takeovers():
    actions = (
        "lightsail:CreateBucketAccessKey",
        "lightsail:DownloadDefaultKeyPair",
        "lightsail:GetInstanceAccessDetails",
        "lightsail:UpdateBucket",
    )
    critical = {tuple(candidate) for candidate in very_sensitive_combinations}

    for action in actions:
        assert (action,) in critical
        assert classify_permission(
            "aws", action, unknown_default="medium"
        ) == "critical"
        assert live_validated_disclosure_documentation[action] == (
            "aws-privilege-escalation/aws-lightsail-privesc/README.md"
        )


def test_live_validated_mediapackage_ingest_credential_takeovers():
    actions = (
        "mediapackage:RotateChannelCredentials",
        "mediapackage:RotateIngestEndpointCredentials",
    )
    critical = {tuple(candidate) for candidate in very_sensitive_combinations}
    high = {tuple(candidate) for candidate in sensitive_combinations}

    for action in actions:
        assert (action,) not in critical
        assert (action,) in high
        assert classify_permission(
            "aws", action, unknown_default="medium"
        ) == "high"
        assert live_validated_disclosure_documentation[action] == (
            "aws-privilege-escalation/aws-mediapackage-privesc/README.md"
        )


def test_live_validated_neptune_data_disclosures():
    actions = (
        "neptune-db:GetStreamRecords",
        "neptune-db:ReadDataViaQuery",
        "neptune-graph:ReadDataViaQuery",
    )
    high = {tuple(candidate) for candidate in sensitive_combinations}

    for action in actions:
        assert (action,) in high
        assert classify_permission(
            "aws", action, unknown_default="medium"
        ) == "high"
        assert live_validated_disclosure_documentation[action] == (
            "aws-services/aws-neptune-enum.md"
        )


def test_live_validated_keyspaces_read_and_write_paths():
    select_action = "cassandra:Select"
    modify_chain = ("cassandra:Modify", select_action)
    high = {tuple(candidate) for candidate in sensitive_combinations}

    assert (select_action,) in high
    assert modify_chain in high
    assert classify_permission(
        "aws", select_action, unknown_default="medium"
    ) == "high"
    assert classify_permission(
        "aws", modify_chain[0], unknown_default="medium"
    ) == "medium"
    for action in modify_chain:
        assert live_validated_disclosure_documentation[action] == (
            "aws-services/aws-keyspaces-enum.md"
        )


def test_live_validated_dax_inherited_table_access():
    read_actions = (
        "dax:BatchGetItem",
        "dax:GetItem",
        "dax:Query",
        "dax:Scan",
    )
    write_and_oracle_actions = (
        "dax:BatchWriteItem",
        "dax:ConditionCheckItem",
        "dax:DeleteItem",
        "dax:PutItem",
        "dax:UpdateItem",
    )
    high = {tuple(candidate) for candidate in sensitive_combinations}

    for action in read_actions:
        assert (action,) in high
        assert classify_permission(
            "aws", action, unknown_default="medium"
        ) == "high"
    for action in write_and_oracle_actions:
        assert (action,) not in high
        assert classify_permission(
            "aws", action, unknown_default="medium"
        ) == "medium"
    for action in read_actions + write_and_oracle_actions:
        assert live_validated_disclosure_documentation[action] == (
            "aws-services/aws-dynamodb-enum.md"
        )


def test_live_validated_device_farm_session_and_artifact_disclosures():
    actions = (
        "devicefarm:GetRemoteAccessSession",
        "devicefarm:ListArtifacts",
    )
    high = {tuple(candidate) for candidate in sensitive_combinations}

    for action in actions:
        assert (action,) in high
        assert classify_permission(
            "aws", action, unknown_default="medium"
        ) == "high"
        assert live_validated_disclosure_documentation[action] == (
            "aws-services/aws-device-farm-enum.md"
        )


def test_live_validated_aurora_dsql_database_access_and_policy_escalation():
    database_actions = ("dsql:DbConnect", "dsql:DbConnectAdmin")
    policy_action = "dsql:PutClusterPolicy"
    high = {tuple(candidate) for candidate in sensitive_combinations}
    critical = {tuple(candidate) for candidate in very_sensitive_combinations}

    for action in database_actions:
        assert (action,) in high
        assert (action,) not in critical
        assert classify_permission(
            "aws", action, unknown_default="medium"
        ) == "high"
    assert (policy_action,) in critical
    assert classify_permission(
        "aws", policy_action, unknown_default="medium"
    ) == "critical"
    for action in database_actions + (policy_action,):
        assert live_validated_disclosure_documentation[action] == (
            "aws-services/aws-aurora-dsql-enum.md"
        )


def test_live_validated_ec2_instance_connect_access_paths():
    critical_action = "ec2-instance-connect:SendSSHPublicKey"
    high_actions = (
        "ec2-instance-connect:OpenTunnel",
        "ec2-instance-connect:SendSerialConsoleSSHPublicKey",
    )
    critical = {tuple(candidate) for candidate in very_sensitive_combinations}
    high = {tuple(candidate) for candidate in sensitive_combinations}

    assert (critical_action,) in critical
    assert (critical_action,) not in high
    assert classify_permission(
        "aws", critical_action, unknown_default="medium"
    ) == "critical"
    for action in high_actions:
        assert (action,) in high
        assert (action,) not in critical
        assert classify_permission(
            "aws", action, unknown_default="medium"
        ) == "high"
    assert live_validated_disclosure_documentation[critical_action] == (
        "aws-privilege-escalation/aws-ec2-privesc/README.md"
    )
    assert live_validated_disclosure_documentation[high_actions[0]].endswith(
        "aws-ec2-instance-connect-endpoint-backdoor.md"
    )
    assert live_validated_disclosure_documentation[high_actions[1]] == (
        "aws-privilege-escalation/aws-ec2-privesc/README.md"
    )


def test_hosted_mcp_gates_remain_medium_without_underlying_permissions():
    actions = (
        "ecs-mcp:InvokeReadOnlyTools",
        "ecs-mcp:UseMcp",
        "eks-mcp:CallPrivilegedTool",
        "eks-mcp:CallReadOnlyTool",
        "eks-mcp:InvokeMcp",
    )
    critical = {tuple(candidate) for candidate in very_sensitive_combinations}
    high = {tuple(candidate) for candidate in sensitive_combinations}

    for action in actions:
        assert (action,) not in critical
        assert (action,) not in high
        assert classify_permission(
            "aws", action, unknown_default="high"
        ) == "medium"


def test_live_validated_efs_policy_client_and_posix_paths():
    policy_actions = (
        "elasticfilesystem:DeleteFileSystemPolicy",
        "elasticfilesystem:PutFileSystemPolicy",
    )
    mount_action = "elasticfilesystem:ClientMount"
    companion_actions = (
        "elasticfilesystem:ClientRootAccess",
        "elasticfilesystem:ClientWrite",
        "elasticfilesystem:CreateAccessPoint",
    )
    network_actions = (
        "elasticfilesystem:CreateMountTarget",
        "elasticfilesystem:ModifyMountTargetSecurityGroups",
    )
    critical = {tuple(candidate) for candidate in very_sensitive_combinations}
    high = {tuple(candidate) for candidate in sensitive_combinations}

    for action in policy_actions:
        assert (action,) in critical
        assert classify_permission(
            "aws", action, unknown_default="medium"
        ) == "critical"
    assert (mount_action,) in high
    assert classify_permission(
        "aws", mount_action, unknown_default="medium"
    ) == "high"
    for action in companion_actions:
        assert (action,) not in high
        assert (mount_action, action) in high
        assert classify_permission(
            "aws", action, unknown_default="high"
        ) == "medium"
    for action in network_actions:
        assert (action,) not in high
        assert classify_permission(
            "aws", action, unknown_default="high"
        ) == "medium"
    for action in policy_actions + (mount_action,) + companion_actions:
        assert live_validated_disclosure_documentation[action] == (
            "aws-privilege-escalation/aws-efs-privesc/README.md"
        )


def test_live_validated_elemental_inference_data_paths():
    high_actions = (
        "elemental-inference:ExportDictionaryEntries",
        "elemental-inference:GetMetadata",
    )
    integrity_actions = (
        "elemental-inference:PutMedia",
        "elemental-inference:UpdateDictionary",
    )
    high = {tuple(candidate) for candidate in sensitive_combinations}

    for action in high_actions:
        assert (action,) in high
        assert classify_permission(
            "aws", action, unknown_default="medium"
        ) == "high"
    for action in integrity_actions:
        assert (action,) not in high
        assert classify_permission(
            "aws", action, unknown_default="high"
        ) == "medium"
    for action in high_actions + integrity_actions:
        assert live_validated_disclosure_documentation[action] == (
            "aws-services/aws-elemental-inference-enum.md"
        )


def test_live_validated_entity_resolution_policy_self_grant():
    action = "entityresolution:PutPolicy"
    critical = {tuple(candidate) for candidate in very_sensitive_combinations}

    assert (action,) in critical
    assert classify_permission(
        "aws", action, unknown_default="medium"
    ) == "critical"
    assert live_validated_disclosure_documentation[action] == (
        "aws-services/aws-entity-resolution-enum.md"
    )


def test_lightsail_network_and_service_role_toggles_are_not_critical_alone():
    critical = {tuple(candidate) for candidate in very_sensitive_combinations}
    for action in (
        "lightsail:OpenInstancePublicPorts",
        "lightsail:PutInstancePublicPorts",
        "lightsail:SetResourceAccessForBucket",
        "lightsail:UpdateContainerService",
    ):
        assert (action,) not in critical
        assert classify_permission(
            "aws", action, unknown_default="medium"
        ) == "medium"


def test_dlm_create_lifecycle_policy_is_not_high_without_passrole():
    action = "dlm:CreateLifecyclePolicy"
    high = {tuple(candidate) for candidate in sensitive_combinations}
    assert (action,) not in high
    assert classify_permission(
        "aws", action, unknown_default="medium"
    ) == "medium"


def test_elasticbeanstalk_rebuild_is_not_high_without_code_control():
    action = "elasticbeanstalk:RebuildEnvironment"
    high = {tuple(candidate) for candidate in sensitive_combinations}
    assert (action,) not in high
    assert classify_permission(
        "aws", action, unknown_default="medium"
    ) == "medium"


def test_emr_launch_and_legacy_editor_actions_are_not_high_alone():
    critical = {tuple(candidate) for candidate in very_sensitive_combinations}
    high = {tuple(candidate) for candidate in sensitive_combinations}
    for action in (
        "elasticmapreduce:OpenEditorInConsole",
        "elasticmapreduce:RunJobFlow",
    ):
        assert (action,) not in critical
        assert (action,) not in high
        assert classify_permission(
            "aws", action, unknown_default="medium"
        ) == "medium"


def test_live_validated_lex_export_disclosure_requires_export_workflow():
    combination = ("lex:CreateExport", "lex:DescribeExport")
    combinations = {tuple(candidate) for candidate in sensitive_combinations}
    assert combination in combinations
    for action in combination:
        assert live_validated_disclosure_documentation[action] == (
            "aws-services/aws-lex-v2-enum.md"
        )


def test_live_validated_agentcore_api_key_disclosure_requires_full_chain():
    combination = (
        "bedrock-agentcore:GetWorkloadAccessTokenForUserId",
        "bedrock-agentcore:GetResourceApiKey",
        "secretsmanager:GetSecretValue",
    )
    combinations = {tuple(candidate) for candidate in very_sensitive_combinations}
    assert combination in combinations
    assert live_validated_disclosure_documentation[combination[0]] == (
        "aws-services/aws-bedrock-enum.md"
    )
    assert live_validated_disclosure_documentation[combination[1]] == (
        "aws-services/aws-bedrock-enum.md"
    )
    assert live_validated_disclosure_documentation[combination[2]] == (
        "aws-services/aws-secrets-manager-enum.md"
    )


def test_live_validated_s3_vectors_plaintext_disclosure_paths():
    combinations = {tuple(candidate) for candidate in sensitive_combinations}
    assert ("s3vectors:GetVectors",) in combinations
    assert ("s3vectors:ListVectors", "s3vectors:GetVectors") in combinations
    assert ("s3vectors:QueryVectors", "s3vectors:GetVectors") in combinations
    for action in (
        "s3vectors:GetVectors",
        "s3vectors:ListVectors",
        "s3vectors:QueryVectors",
    ):
        assert live_validated_disclosure_documentation[action] == (
            "aws-services/aws-bedrock-enum.md"
        )


def test_live_validated_fis_template_role_reuse_requires_update_and_start():
    combination = (
        "fis:UpdateExperimentTemplate",
        "fis:StartExperiment",
    )
    critical = {tuple(candidate) for candidate in very_sensitive_combinations}
    assert combination in critical
    for action in combination:
        assert (action,) not in critical
        assert classify_permission(
            "aws", action, unknown_default="medium"
        ) == "medium"
        assert live_validated_disclosure_documentation[action] == (
            "aws-privilege-escalation/aws-fis-privesc/README.md"
        )


def test_live_validated_fraud_detector_event_disclosure():
    action = "frauddetector:GetEvent"
    high = {tuple(candidate) for candidate in sensitive_combinations}
    assert (action,) in high
    assert classify_permission(
        "aws", action, unknown_default="medium"
    ) == "high"
    assert live_validated_disclosure_documentation[action] == (
        "aws-services/aws-fraud-detector-enum.md"
    )


def test_live_validated_gamelift_compute_host_access_and_upload_boundary():
    action = "gamelift:GetComputeAccess"
    critical = {tuple(candidate) for candidate in very_sensitive_combinations}
    assert (action,) in critical
    assert classify_permission(
        "aws", action, unknown_default="medium"
    ) == "critical"
    assert live_validated_disclosure_documentation[action] == (
        "aws-services/aws-gamelift-enum.md"
    )

    upload_action = "gamelift:RequestUploadCredentials"
    assert (upload_action,) not in critical
    assert classify_permission(
        "aws", upload_action, unknown_default="medium"
    ) == "medium"


def test_live_validated_gamelift_streams_shell_and_secret_disclosures():
    critical_action = "gameliftstreams:CreateStreamSessionAdminShell"
    critical = {tuple(candidate) for candidate in very_sensitive_combinations}
    assert (critical_action,) in critical
    assert classify_permission(
        "aws", critical_action, unknown_default="medium"
    ) == "critical"

    high = {tuple(candidate) for candidate in sensitive_combinations}
    for action in (
        "gameliftstreams:GetStreamSession",
        "gameliftstreams:GetStreamUrl",
        "gameliftstreams:ListStreamUrls",
    ):
        assert (action,) in high
        assert classify_permission("aws", action, unknown_default="medium") == "high"
        assert live_validated_disclosure_documentation[action] == (
            "aws-services/aws-gamelift-streams-enum.md"
        )

    assert live_validated_disclosure_documentation[critical_action] == (
        "aws-services/aws-gamelift-streams-enum.md"
    )

    # The role-bearing entry points correctly enforce iam:PassRole, while the
    # file export also needs its documented downstream S3 permission.
    for action in (
        "gameliftstreams:CreateStreamUrl",
        "gameliftstreams:StartStreamSession",
        "gameliftstreams:ExportStreamSessionFiles",
        "gameliftstreams:UpdateApplication",
    ):
        assert classify_permission("aws", action, unknown_default="medium") == "medium"


def test_live_validated_global_accelerator_endpoint_hijack():
    action = "globalaccelerator:UpdateEndpointGroup"
    high = {tuple(candidate) for candidate in sensitive_combinations}
    assert (action,) in high
    assert classify_permission("aws", action, unknown_default="medium") == "high"
    assert live_validated_disclosure_documentation[action] == (
        "aws-services/aws-global-accelerator-enum.md"
    )


def test_live_validated_iot_jobs_documents_and_remote_command_execution():
    high = {tuple(candidate) for candidate in sensitive_combinations}
    actions = (
        "iot:StartCommandExecution",
        "iotjobsdata:DescribeJobExecution",
        "iotjobsdata:StartNextPendingJobExecution",
        "iotjobsdata:UpdateJobExecution",
    )
    for action in actions:
        assert (action,) in high
        assert classify_permission("aws", action, unknown_default="medium") == "high"
        assert live_validated_disclosure_documentation[action] == (
            "aws-services/aws-iot-core-enum.md"
        )

    assert tested_risk_documentation["iot:StartCommandExecution"] == (
        "aws-services/aws-iot-core-enum.md"
    )
    assert tested_risk_documentation[
        "iotjobsdata:StartNextPendingJobExecution"
    ] == "aws-services/aws-iot-core-enum.md"
    assert tested_risk_documentation["iotjobsdata:UpdateJobExecution"] == (
        "aws-services/aws-iot-core-enum.md"
    )

    # This listing action returned only execution metadata, not a job document.
    assert (
        "iotjobsdata:GetPendingJobExecutions",
    ) not in high
    assert classify_permission(
        "aws", "iotjobsdata:GetPendingJobExecutions", unknown_default="medium"
    ) == "medium"


def test_live_validated_ivs_stream_key_and_playback_authorization_attacks():
    high = {tuple(candidate) for candidate in sensitive_combinations}
    actions = (
        "ivs:BatchGetStreamKey",
        "ivs:CreateStreamKey",
        "ivs:GetStreamKey",
        "ivs:UpdateChannel",
    )
    for action in actions:
        assert (action,) in high
        assert classify_permission("aws", action, unknown_default="medium") == "high"
        assert live_validated_disclosure_documentation[action] == (
            "aws-services/aws-ivs-enum.md"
        )

    for action in ("ivs:CreateStreamKey", "ivs:UpdateChannel"):
        assert tested_risk_documentation[action] == "aws-services/aws-ivs-enum.md"

    # Listing exposes identifiers but never the stream-key value. Stopping a
    # stream and deleting its key are availability impacts, not secret access.
    for action in (
        "ivs:ListStreamKeys",
        "ivs:StopStream",
        "ivs:DeleteStreamKey",
    ):
        assert (action,) not in high
        assert classify_permission("aws", action, unknown_default="medium") == "medium"


def test_live_validated_lake_formation_self_admin_assignment():
    action = "lakeformation:PutDataLakeSettings"
    high = {tuple(candidate) for candidate in sensitive_combinations}
    assert (action,) in high
    assert classify_permission("aws", action, unknown_default="medium") == "high"
    assert tested_risk_documentation[action] == (
        "aws-services/aws-lake-formation-enum.md"
    )
    assert live_validated_disclosure_documentation[action] == (
        "aws-services/aws-lake-formation-enum.md"
    )


def test_live_validated_mainframe_modernization_sso_url():
    action = "m2:GetSignedBluinsightsUrl"
    high = {tuple(candidate) for candidate in sensitive_combinations}
    assert (action,) in high
    assert classify_permission("aws", action, unknown_default="medium") == "high"
    assert tested_risk_documentation[action] == (
        "aws-services/aws-mainframe-modernization-enum.md"
    )
    assert live_validated_disclosure_documentation[action] == (
        "aws-services/aws-mainframe-modernization-enum.md"
    )


def test_live_validated_managed_blockchain_reads_stay_medium():
    high = {tuple(candidate) for candidate in sensitive_combinations}
    for action in (
        "managedblockchain:GetAccessor",
        "managedblockchain-query:GetTransaction",
    ):
        assert (action,) not in high
        assert classify_permission("aws", action, unknown_default="medium") == "medium"


def test_live_validated_mediaconnect_content_access():
    actions = (
        "mediaconnect:AddFlowOutputs",
        "mediaconnect:DescribeFlowSourceThumbnail",
        "mediaconnect:UpdateFlowOutput",
    )
    high = {tuple(candidate) for candidate in sensitive_combinations}
    for action in actions:
        assert (action,) in high
        assert classify_permission("aws", action, unknown_default="medium") == "high"
        assert tested_risk_documentation[action] == (
            "aws-services/aws-mediaconnect-enum.md"
        )
        assert live_validated_disclosure_documentation[action] == (
            "aws-services/aws-mediaconnect-enum.md"
        )


def test_live_validated_medialive_content_access():
    actions = (
        "medialive:DescribeThumbnails",
        "medialive:UpdateChannel",
    )
    high = {tuple(candidate) for candidate in sensitive_combinations}
    for action in actions:
        assert (action,) in high
        assert classify_permission("aws", action, unknown_default="medium") == "high"
        assert tested_risk_documentation[action] == (
            "aws-services/aws-medialive-enum.md"
        )
        assert live_validated_disclosure_documentation[action] == (
            "aws-services/aws-medialive-enum.md"
        )


def test_live_validated_mediapackage_v2_policy_attacks():
    actions = (
        "mediapackagev2:PutChannelPolicy",
        "mediapackagev2:PutOriginEndpointPolicy",
    )
    high = {tuple(candidate) for candidate in sensitive_combinations}
    for action in actions:
        assert (action,) in high
        assert classify_permission("aws", action, unknown_default="medium") == "high"
        assert tested_risk_documentation[action] == (
            "aws-services/aws-mediapackage-v2-enum.md"
        )
        assert live_validated_disclosure_documentation[action] == (
            "aws-services/aws-mediapackage-v2-enum.md"
        )


def test_live_validated_user_notifications_health_event_disclosure():
    actions = (
        "notifications:GetManagedNotificationEvent",
        "notifications:ListManagedNotificationEvents",
    )
    high = {tuple(candidate) for candidate in sensitive_combinations}
    for action in actions:
        assert (action,) in high
        assert classify_permission("aws", action, unknown_default="medium") == "high"
        assert tested_risk_documentation[action] == (
            "aws-services/aws-user-notifications-enum.md"
        )
        assert live_validated_disclosure_documentation[action] == (
            "aws-services/aws-user-notifications-enum.md"
        )


def test_live_validated_mq_user_takeover():
    actions = ("mq:CreateUser", "mq:UpdateUser")
    high = {tuple(candidate) for candidate in sensitive_combinations}
    for action in actions:
        assert (action,) in high
        assert classify_permission("aws", action, unknown_default="medium") == "high"
        assert tested_risk_documentation[action] == (
            "aws-privilege-escalation/aws-mq-privesc/README.md"
        )
        assert live_validated_disclosure_documentation[action] == (
            "aws-privilege-escalation/aws-mq-privesc/README.md"
        )
    assert ("mq:UpdateBroker",) not in high
    assert classify_permission(
        "aws", "mq:UpdateBroker", unknown_default="medium"
    ) == "medium"


def test_live_validated_s3_tables_policy_self_grant():
    actions = ("s3tables:PutTableBucketPolicy", "s3tables:PutTablePolicy")
    critical = {tuple(candidate) for candidate in very_sensitive_combinations}
    for action in actions:
        assert (action,) in critical
        assert classify_permission("aws", action, unknown_default="medium") == "critical"
        assert tested_risk_documentation[action] == (
            "aws-services/aws-s3-tables-and-vectors-enum.md"
        )
        assert live_validated_disclosure_documentation[action] == (
            "aws-services/aws-s3-tables-and-vectors-enum.md"
        )


def test_live_validated_cloud_map_instance_overwrite():
    action = "servicediscovery:RegisterInstance"
    high = {tuple(candidate) for candidate in sensitive_combinations}
    assert (action,) in high
    assert classify_permission("aws", action, unknown_default="medium") == "high"
    assert tested_risk_documentation[action] == "aws-services/aws-cloud-map-enum.md"
    assert live_validated_disclosure_documentation[action] == (
        "aws-services/aws-cloud-map-enum.md"
    )


def test_live_validated_textract_completed_job_disclosures():
    actions = (
        "textract:GetDocumentAnalysis",
        "textract:GetDocumentTextDetection",
        "textract:GetExpenseAnalysis",
    )
    high = {tuple(candidate) for candidate in sensitive_combinations}
    for action in actions:
        assert (action,) in high
        assert classify_permission("aws", action, unknown_default="medium") == "high"
        assert tested_risk_documentation[action] == "aws-services/aws-textract-enum.md"
        assert live_validated_disclosure_documentation[action] == (
            "aws-services/aws-textract-enum.md"
        )


def test_live_validated_vpc_lattice_service_invocation():
    action = "vpc-lattice-svcs:Invoke"
    high = {tuple(candidate) for candidate in sensitive_combinations}
    assert (action,) in high
    assert classify_permission("aws", action, unknown_default="medium") == "high"
    assert tested_risk_documentation[action] == "aws-services/aws-vpc-lattice-enum.md"
    assert live_validated_disclosure_documentation[action] == (
        "aws-services/aws-vpc-lattice-enum.md"
    )
