import re
from pathlib import Path

from CloudPEASS.permission_risk_classifier import classify_permission
from sensitive_permissions.aws import (
    hacktricks_pr_heading_exclusions,
    hacktricks_reconciled_true_positive_actions,
    live_validated_disclosure_documentation,
    sensitive_combinations,
    tested_risk_documentation,
    very_sensitive_combinations,
)


def test_live_validated_cloudformation_artifact_poisoning_is_high_risk():
    assert sensitive_combinations.count(["s3:PutObject"]) == 1
    assert ["ssm:PutParameter"] in sensitive_combinations

    expected_doc = "aws-privilege-escalation/aws-cloudformation-privesc/README.md"
    assert live_validated_disclosure_documentation["s3:PutObject"] == expected_doc
    assert live_validated_disclosure_documentation["ssm:PutParameter"] == expected_doc
    assert tested_risk_documentation["s3:PutObject"] == expected_doc
    assert tested_risk_documentation["ssm:PutParameter"] == expected_doc


def test_start_job_run_is_critical_after_live_script_override():
    expected_doc = "aws-privilege-escalation/aws-glue-privesc/README.md"
    assert ["glue:StartJobRun"] in very_sensitive_combinations
    assert ["glue:StartJobRun"] not in sensitive_combinations
    assert tested_risk_documentation["glue:StartJobRun"] == expected_doc
    assert live_validated_disclosure_documentation["glue:StartJobRun"] == expected_doc


def test_batch_submit_job_is_critical_after_live_command_override():
    expected_doc = "aws-privilege-escalation/aws-batch-privesc/README.md"
    assert ["batch:SubmitJob"] in very_sensitive_combinations
    assert ["batch:SubmitJob"] not in sensitive_combinations
    assert tested_risk_documentation["batch:SubmitJob"] == expected_doc
    assert live_validated_disclosure_documentation["batch:SubmitJob"] == expected_doc


def test_emr_add_steps_is_critical_after_live_command_injection():
    expected_doc = "aws-privilege-escalation/aws-emr-privesc/README.md"
    assert ["elasticmapreduce:AddJobFlowSteps"] in very_sensitive_combinations
    assert ["elasticmapreduce:AddJobFlowSteps"] not in sensitive_combinations
    assert tested_risk_documentation["elasticmapreduce:AddJobFlowSteps"] == expected_doc
    assert live_validated_disclosure_documentation["elasticmapreduce:AddJobFlowSteps"] == expected_doc


def test_stored_role_entry_actions_match_live_passrole_controls():
    assert ["scheduler:CreateSchedule", "scheduler:UpdateSchedule"] not in sensitive_combinations
    assert ["scheduler:CreateSchedule", "iam:PassRole"] in very_sensitive_combinations
    assert ["scheduler:UpdateSchedule", "iam:PassRole"] in very_sensitive_combinations
    assert ["pipes:UpdatePipe", "iam:PassRole"] in very_sensitive_combinations

    assert ["scheduler:CreateSchedule"] not in sensitive_combinations
    assert ["scheduler:UpdateSchedule"] not in sensitive_combinations
    assert ["pipes:UpdatePipe"] not in sensitive_combinations
    assert ["pipes:StartPipe"] in sensitive_combinations
    assert ["states:StartExecution"] in sensitive_combinations

    pipes_doc = "aws-services/eventbridgescheduler-enum.md"
    states_doc = "aws-post-exploitation/aws-stepfunctions-post-exploitation/README.md"
    for registry in (tested_risk_documentation, live_validated_disclosure_documentation):
        assert registry["pipes:StartPipe"] == pipes_doc
        assert registry["states:StartExecution"] == states_doc


def test_pipeline_start_variable_sink_is_conditionally_high():
    expected_doc = "aws-privilege-escalation/aws-codepipeline-privesc/README.md"
    assert ["codepipeline:StartPipelineExecution"] in sensitive_combinations
    assert ["codepipeline:StartPipelineExecution"] not in very_sensitive_combinations
    assert tested_risk_documentation["codepipeline:StartPipelineExecution"] == expected_doc
    assert live_validated_disclosure_documentation["codepipeline:StartPipelineExecution"] == expected_doc


def test_pipeline_manual_approval_bypass_is_conditionally_high():
    expected_doc = "aws-privilege-escalation/aws-codepipeline-privesc/README.md"
    assert ["codepipeline:PutApprovalResult"] in sensitive_combinations
    assert ["codepipeline:PutApprovalResult"] not in very_sensitive_combinations
    assert tested_risk_documentation["codepipeline:PutApprovalResult"] == expected_doc
    assert live_validated_disclosure_documentation["codepipeline:PutApprovalResult"] == expected_doc


def test_pipeline_custom_gate_success_forgery_is_conditionally_high():
    expected_doc = "aws-privilege-escalation/aws-codepipeline-privesc/README.md"
    assert ["codepipeline:PutJobSuccessResult"] in sensitive_combinations
    assert ["codepipeline:PutJobSuccessResult"] not in very_sensitive_combinations
    assert tested_risk_documentation["codepipeline:PutJobSuccessResult"] == expected_doc
    assert live_validated_disclosure_documentation["codepipeline:PutJobSuccessResult"] == expected_doc


def test_cloudtrail_destination_redirect_is_conditionally_high():
    expected_doc = "aws-services/aws-security-and-detection-services/aws-cloudtrail-enum.md"
    assert ["cloudtrail:UpdateTrail"] in sensitive_combinations
    assert ["cloudtrail:UpdateTrail"] not in very_sensitive_combinations
    assert tested_risk_documentation["cloudtrail:UpdateTrail"] == expected_doc
    assert live_validated_disclosure_documentation["cloudtrail:UpdateTrail"] == expected_doc


def test_config_delivery_channel_redirect_is_conditionally_high():
    expected_doc = "aws-services/aws-security-and-detection-services/aws-config-enum.md"
    assert ["config:PutDeliveryChannel"] in sensitive_combinations
    assert ["config:PutDeliveryChannel"] not in very_sensitive_combinations
    assert tested_risk_documentation["config:PutDeliveryChannel"] == expected_doc
    assert live_validated_disclosure_documentation[
        "config:PutDeliveryChannel"
    ] == expected_doc


def test_config_evaluation_runs_the_fixed_evaluator_role():
    expected_doc = "aws-services/aws-security-and-detection-services/aws-config-enum.md"
    action = "config:StartConfigRulesEvaluation"
    assert [action] in sensitive_combinations
    assert [action] not in very_sensitive_combinations
    assert tested_risk_documentation[action] == expected_doc
    assert live_validated_disclosure_documentation[action] == expected_doc


def test_eventbridge_replay_reemits_stored_events_to_fixed_targets():
    expected_doc = "aws-privilege-escalation/aws-eventbridge-privesc/README.md"
    action = "events:StartReplay"
    assert [action] in sensitive_combinations
    assert [action] not in very_sensitive_combinations
    assert tested_risk_documentation[action] == expected_doc
    assert live_validated_disclosure_documentation[action] == expected_doc


def test_cognito_client_update_discloses_existing_client_secret():
    expected_doc = "aws-privilege-escalation/aws-cognito-privesc/README.md"
    assert ["cognito-idp:UpdateUserPoolClient"] in sensitive_combinations
    assert ["cognito-idp:UpdateUserPoolClient"] not in very_sensitive_combinations
    assert tested_risk_documentation["cognito-idp:UpdateUserPoolClient"] == expected_doc
    assert live_validated_disclosure_documentation[
        "cognito-idp:UpdateUserPoolClient"
    ] == expected_doc


def test_codebuild_retry_reexecutes_the_stored_build_role():
    expected_doc = "aws-privilege-escalation/aws-codebuild-privesc/README.md"
    assert ["codebuild:RetryBuild"] in sensitive_combinations
    assert ["codebuild:RetryBuild"] not in very_sensitive_combinations
    assert tested_risk_documentation["codebuild:RetryBuild"] == expected_doc
    assert live_validated_disclosure_documentation["codebuild:RetryBuild"] == expected_doc


def test_codepipeline_retry_reexecutes_the_failed_stage_roles():
    expected_doc = "aws-privilege-escalation/aws-codepipeline-privesc/README.md"
    assert ["codepipeline:RetryStageExecution"] in sensitive_combinations
    assert ["codepipeline:RetryStageExecution"] not in very_sensitive_combinations
    assert tested_risk_documentation["codepipeline:RetryStageExecution"] == expected_doc
    assert live_validated_disclosure_documentation[
        "codepipeline:RetryStageExecution"
    ] == expected_doc


def test_codepipeline_enable_transition_releases_waiting_stored_roles():
    expected_doc = "aws-privilege-escalation/aws-codepipeline-privesc/README.md"
    action = "codepipeline:EnableStageTransition"
    assert [action] in sensitive_combinations
    assert [action] not in very_sensitive_combinations
    assert tested_risk_documentation[action] == expected_doc
    assert live_validated_disclosure_documentation[action] == expected_doc


def test_codepipeline_override_condition_releases_waiting_stored_roles():
    expected_doc = "aws-privilege-escalation/aws-codepipeline-privesc/README.md"
    action = "codepipeline:OverrideStageCondition"
    assert [action] in sensitive_combinations
    assert [action] not in very_sensitive_combinations
    assert tested_risk_documentation[action] == expected_doc
    assert live_validated_disclosure_documentation[action] == expected_doc


def test_codepipeline_rollback_replays_the_prior_stage_artifact_and_role():
    expected_doc = "aws-privilege-escalation/aws-codepipeline-privesc/README.md"
    action = "codepipeline:RollbackStage"
    assert [action] in sensitive_combinations
    assert [action] not in very_sensitive_combinations
    assert tested_risk_documentation[action] == expected_doc
    assert live_validated_disclosure_documentation[action] == expected_doc


def test_start_associations_once_runs_the_fixed_managed_node_workload():
    expected_doc = "aws-privilege-escalation/aws-ssm-privesc/README.md"
    action = "ssm:StartAssociationsOnce"
    assert [action] in sensitive_combinations
    assert [action] not in very_sensitive_combinations
    assert tested_risk_documentation[action] == expected_doc
    assert live_validated_disclosure_documentation[action] == expected_doc


def test_start_canary_runs_the_fixed_canary_execution_role():
    expected_doc = "aws-privilege-escalation/aws-synthetics-privesc/README.md"
    action = "synthetics:StartCanary"
    assert [action] in sensitive_combinations
    assert [action] not in very_sensitive_combinations
    assert tested_risk_documentation[action] == expected_doc
    assert live_validated_disclosure_documentation[action] == expected_doc


def test_step_functions_redrive_reexecutes_the_stored_failed_path():
    expected_doc = "aws-post-exploitation/aws-stepfunctions-post-exploitation/README.md"
    assert ["states:RedriveExecution"] in sensitive_combinations
    assert ["states:RedriveExecution"] not in very_sensitive_combinations
    assert tested_risk_documentation["states:RedriveExecution"] == expected_doc
    assert live_validated_disclosure_documentation["states:RedriveExecution"] == expected_doc


def test_sagemaker_retry_reexecutes_stored_role_and_parameters():
    expected_doc = "aws-privilege-escalation/aws-sagemaker-privesc/README.md"
    assert ["sagemaker:RetryPipelineExecution"] in sensitive_combinations
    assert ["sagemaker:RetryPipelineExecution"] not in very_sensitive_combinations
    assert tested_risk_documentation["sagemaker:RetryPipelineExecution"] == expected_doc
    assert live_validated_disclosure_documentation[
        "sagemaker:RetryPipelineExecution"
    ] == expected_doc


def test_sagemaker_pipeline_parameters_reach_privileged_steps():
    expected_doc = "aws-privilege-escalation/aws-sagemaker-privesc/README.md"
    assert ["sagemaker:StartPipelineExecution"] in sensitive_combinations
    assert ["sagemaker:StartPipelineExecution"] not in very_sensitive_combinations
    assert tested_risk_documentation["sagemaker:StartPipelineExecution"] == expected_doc
    assert live_validated_disclosure_documentation["sagemaker:StartPipelineExecution"] == expected_doc


def test_appsync_resolver_rewrite_reuses_fixed_data_source_role():
    expected_doc = "aws-services/aws-appsync-enum.md"
    assert ["appsync:UpdateResolver"] in sensitive_combinations
    assert ["appsync:UpdateResolver"] not in very_sensitive_combinations
    assert tested_risk_documentation["appsync:UpdateResolver"] == expected_doc
    assert live_validated_disclosure_documentation["appsync:UpdateResolver"] == expected_doc


def test_glue_workflow_run_properties_reach_trusting_job():
    expected_doc = "aws-privilege-escalation/aws-glue-privesc/README.md"
    assert ["glue:StartWorkflowRun"] in sensitive_combinations
    assert ["glue:StartWorkflowRun"] not in very_sensitive_combinations
    assert tested_risk_documentation["glue:StartWorkflowRun"] == expected_doc
    assert live_validated_disclosure_documentation["glue:StartWorkflowRun"] == expected_doc


def test_glue_table_location_redirect_reaches_trusted_writer():
    expected_doc = "aws-post-exploitation/aws-glue-post-exploitation/README.md"
    assert ["glue:UpdateTable"] in sensitive_combinations
    assert ["glue:UpdateTable"] not in very_sensitive_combinations
    assert tested_risk_documentation["glue:UpdateTable"] == expected_doc
    assert live_validated_disclosure_documentation["glue:UpdateTable"] == expected_doc


def test_glue_partition_location_redirect_reaches_trusted_writer():
    expected_doc = "aws-post-exploitation/aws-glue-post-exploitation/README.md"
    assert ["glue:UpdatePartition"] in sensitive_combinations
    assert ["glue:UpdatePartition"] not in very_sensitive_combinations
    assert ["glue:BatchUpdatePartition"] not in sensitive_combinations
    assert tested_risk_documentation["glue:UpdatePartition"] == expected_doc
    assert live_validated_disclosure_documentation["glue:UpdatePartition"] == expected_doc


def test_glue_batch_create_partition_poisoning_is_conditionally_high():
    expected_doc = "aws-post-exploitation/aws-glue-post-exploitation/README.md"
    action = "glue:BatchCreatePartition"
    assert [action] in sensitive_combinations
    assert [action] not in very_sensitive_combinations
    assert tested_risk_documentation[action] == expected_doc
    assert live_validated_disclosure_documentation[action] == expected_doc


def test_lambda_event_source_mapping_redirect_is_conditionally_high():
    expected_doc = (
        "aws-post-exploitation/aws-lambda-post-exploitation/"
        "aws-lambda-event-source-mapping-hijack.md"
    )
    assert ["lambda:UpdateEventSourceMapping"] in sensitive_combinations
    assert ["lambda:UpdateEventSourceMapping"] not in very_sensitive_combinations
    assert tested_risk_documentation["lambda:UpdateEventSourceMapping"] == expected_doc
    assert live_validated_disclosure_documentation[
        "lambda:UpdateEventSourceMapping"
    ] == expected_doc


def test_lambda_event_source_mapping_creation_reuses_fixed_role():
    expected_doc = (
        "aws-post-exploitation/aws-lambda-post-exploitation/"
        "aws-lambda-event-source-mapping-hijack.md"
    )
    assert ["lambda:CreateEventSourceMapping"] in sensitive_combinations
    assert ["lambda:CreateEventSourceMapping"] not in very_sensitive_combinations
    assert tested_risk_documentation["lambda:CreateEventSourceMapping"] == expected_doc
    assert live_validated_disclosure_documentation[
        "lambda:CreateEventSourceMapping"
    ] == expected_doc


def test_lambda_add_permission_function_url_exposure_is_conditionally_high():
    expected_doc = "aws-privilege-escalation/aws-lambda-privesc/README.md"
    assert ["lambda:AddPermission"] in sensitive_combinations
    assert ["lambda:AddPermission"] not in very_sensitive_combinations
    assert tested_risk_documentation["lambda:AddPermission"] == expected_doc
    assert live_validated_disclosure_documentation["lambda:AddPermission"] == expected_doc


def test_firelens_exact_key_poisoning_remains_conditionally_high_s3_write():
    assert ["s3:PutObject"] in sensitive_combinations
    assert ["s3:PutObject"] not in very_sensitive_combinations


def test_ecr_mutable_tag_retargeting_reaches_new_sagemaker_processing_job():
    assert ["ecr:BatchGetImage", "ecr:PutImage"] in sensitive_combinations
    assert ["ecr:BatchGetImage", "ecr:PutImage"] not in very_sensitive_combinations


def test_ecr_auth_tokens_alone_are_not_sensitive_and_push_is_conditional_high():
    private_push = [
        "ecr:GetAuthorizationToken",
        "ecr:BatchCheckLayerAvailability",
        "ecr:CompleteLayerUpload",
        "ecr:InitiateLayerUpload",
        "ecr:PutImage",
        "ecr:UploadLayerPart",
    ]
    public_push = [
        "ecr-public:GetAuthorizationToken",
        "ecr-public:BatchCheckLayerAvailability",
        "ecr-public:CompleteLayerUpload",
        "ecr-public:InitiateLayerUpload",
        "ecr-public:PutImage",
        "ecr-public:UploadLayerPart",
    ]
    for combination in (private_push, public_push):
        assert combination in sensitive_combinations
        assert combination not in very_sensitive_combinations


def test_ecr_repository_policy_setter_self_grants_private_image_access():
    expected_doc = "aws-privilege-escalation/aws-ecr-privesc/README.md"
    assert ["ecr:SetRepositoryPolicy"] in sensitive_combinations
    assert ["ecr:SetRepositoryPolicy"] not in very_sensitive_combinations
    assert tested_risk_documentation["ecr:SetRepositoryPolicy"] == expected_doc
    assert live_validated_disclosure_documentation["ecr:SetRepositoryPolicy"] == expected_doc


def test_ecr_public_repository_policy_setter_is_conditional_high():
    assert ["ecr-public:SetRepositoryPolicy"] in sensitive_combinations
    assert ["ecr-public:SetRepositoryPolicy"] not in very_sensitive_combinations


def test_eks_oidc_association_reaches_preexisting_privileged_rbac_group():
    expected_doc = "aws-post-exploitation/aws-eks-post-exploitation/README.md"
    assert ["eks:AssociateIdentityProviderConfig"] in very_sensitive_combinations
    assert ["eks:AssociateIdentityProviderConfig"] not in sensitive_combinations
    assert tested_risk_documentation["eks:AssociateIdentityProviderConfig"] == expected_doc
    assert live_validated_disclosure_documentation[
        "eks:AssociateIdentityProviderConfig"
    ] == expected_doc


def test_glue_resume_workflow_run_replays_stored_job_role():
    expected_doc = "aws-privilege-escalation/aws-glue-privesc/README.md"
    assert ["glue:ResumeWorkflowRun"] in sensitive_combinations
    assert ["glue:ResumeWorkflowRun"] not in very_sensitive_combinations
    assert tested_risk_documentation["glue:ResumeWorkflowRun"] == expected_doc
    assert live_validated_disclosure_documentation[
        "glue:ResumeWorkflowRun"
    ] == expected_doc


def test_cloudformation_execute_change_set_uses_stored_service_role():
    expected_doc = "aws-privilege-escalation/aws-cloudformation-privesc/README.md"
    assert ["cloudformation:ExecuteChangeSet"] in sensitive_combinations
    assert ["cloudformation:ExecuteChangeSet"] not in very_sensitive_combinations
    assert tested_risk_documentation["cloudformation:ExecuteChangeSet"] == expected_doc
    assert live_validated_disclosure_documentation[
        "cloudformation:ExecuteChangeSet"
    ] == expected_doc


def test_cloudformation_signal_resource_releases_waiting_stored_role():
    expected_doc = "aws-privilege-escalation/aws-cloudformation-privesc/README.md"
    action = "cloudformation:SignalResource"
    assert [action] in sensitive_combinations
    assert [action] not in very_sensitive_combinations
    assert tested_risk_documentation[action] == expected_doc
    assert live_validated_disclosure_documentation[action] == expected_doc


def test_route53_record_redirect_reaches_fixed_privileged_http_consumer():
    expected_doc = "aws-services/aws-route53-enum.md"
    assert ["route53:ChangeResourceRecordSets"] in sensitive_combinations
    assert ["route53:ChangeResourceRecordSets"] not in very_sensitive_combinations
    assert tested_risk_documentation["route53:ChangeResourceRecordSets"] == expected_doc
    assert live_validated_disclosure_documentation[
        "route53:ChangeResourceRecordSets"
    ] == expected_doc


def test_dms_start_replication_task_uses_stored_endpoint_role():
    expected_doc = "aws-services/aws-dms-enum.md"
    assert ["dms:StartReplicationTask"] in sensitive_combinations
    assert ["dms:StartReplicationTask"] not in very_sensitive_combinations
    assert tested_risk_documentation["dms:StartReplicationTask"] == expected_doc
    assert live_validated_disclosure_documentation[
        "dms:StartReplicationTask"
    ] == expected_doc


def test_eventbridge_put_rule_enables_preexisting_stored_target():
    expected_doc = "aws-privilege-escalation/aws-eventbridge-privesc/README.md"
    assert ["events:PutRule"] in sensitive_combinations
    assert ["events:PutRule"] not in very_sensitive_combinations
    assert tested_risk_documentation["events:PutRule"] == expected_doc
    assert live_validated_disclosure_documentation["events:PutRule"] == expected_doc


def test_eventbridge_put_permission_self_grants_bus_publish():
    expected_doc = "aws-privilege-escalation/aws-eventbridge-privesc/README.md"
    assert ["events:PutPermission"] in sensitive_combinations
    assert ["events:PutPermission"] not in very_sensitive_combinations
    assert tested_risk_documentation["events:PutPermission"] == expected_doc
    assert live_validated_disclosure_documentation["events:PutPermission"] == expected_doc


def test_autoscaling_set_desired_capacity_reuses_instance_profile():
    expected_doc = "aws-privilege-escalation/aws-ec2-privesc/README.md"
    assert ["autoscaling:SetDesiredCapacity"] in sensitive_combinations
    assert ["autoscaling:SetDesiredCapacity"] not in very_sensitive_combinations
    assert tested_risk_documentation["autoscaling:SetDesiredCapacity"] == expected_doc
    assert live_validated_disclosure_documentation[
        "autoscaling:SetDesiredCapacity"
    ] == expected_doc


def test_cloudwatch_set_alarm_state_triggers_fixed_alarm_action():
    expected_doc = (
        "aws-services/aws-security-and-detection-services/aws-cloudwatch-enum.md"
    )
    assert ["cloudwatch:SetAlarmState"] in sensitive_combinations
    assert ["cloudwatch:SetAlarmState"] not in very_sensitive_combinations
    assert tested_risk_documentation["cloudwatch:SetAlarmState"] == expected_doc
    assert live_validated_disclosure_documentation[
        "cloudwatch:SetAlarmState"
    ] == expected_doc


def test_ecs_update_service_desired_count_reuses_fixed_task_role():
    expected_doc = "aws-privilege-escalation/aws-ecs-privesc/README.md"
    assert ["ecs:UpdateService"] in sensitive_combinations
    assert ["ecs:UpdateService"] not in very_sensitive_combinations
    assert tested_risk_documentation["ecs:UpdateService"] == expected_doc
    assert live_validated_disclosure_documentation["ecs:UpdateService"] == expected_doc


def test_s3_put_bucket_notification_wires_preauthorized_lambda():
    expected_doc = "aws-services/aws-s3-athena-and-glacier-enum.md"
    assert ["s3:PutBucketNotification"] in sensitive_combinations
    assert ["s3:PutBucketNotification"] not in very_sensitive_combinations
    assert tested_risk_documentation["s3:PutBucketNotification"] == expected_doc
    assert live_validated_disclosure_documentation[
        "s3:PutBucketNotification"
    ] == expected_doc


def test_sns_subscribe_wires_preauthorized_lambda_for_future_publish():
    expected_doc = "aws-privilege-escalation/aws-sns-privesc/README.md"
    assert ["sns:Subscribe"] in sensitive_combinations
    assert ["sns:Subscribe"] not in very_sensitive_combinations
    assert tested_risk_documentation["sns:Subscribe"] == expected_doc
    assert live_validated_disclosure_documentation["sns:Subscribe"] == expected_doc


def test_logs_subscription_filter_forwards_future_record_to_fixed_lambda():
    expected_doc = (
        "aws-services/aws-security-and-detection-services/aws-cloudwatch-enum.md"
    )
    assert ["logs:PutSubscriptionFilter"] in sensitive_combinations
    assert ["logs:PutSubscriptionFilter"] not in very_sensitive_combinations
    assert tested_risk_documentation["logs:PutSubscriptionFilter"] == expected_doc
    assert live_validated_disclosure_documentation[
        "logs:PutSubscriptionFilter"
    ] == expected_doc


def test_transfer_connector_url_redirect_exposes_stored_sftp_credential():
    expected_doc = "aws-privilege-escalation/aws-transfer-family-privesc/README.md"
    assert ["transfer:UpdateConnector"] in sensitive_combinations
    assert ["transfer:UpdateConnector"] not in very_sensitive_combinations
    assert tested_risk_documentation["transfer:UpdateConnector"] == expected_doc
    assert live_validated_disclosure_documentation["transfer:UpdateConnector"] == expected_doc


def test_transfer_start_reuses_connector_role_for_private_s3_data():
    expected_doc = "aws-privilege-escalation/aws-transfer-family-privesc/README.md"
    assert ["transfer:StartFileTransfer"] in sensitive_combinations
    assert ["transfer:StartFileTransfer"] not in very_sensitive_combinations
    assert tested_risk_documentation["transfer:StartFileTransfer"] == expected_doc
    assert live_validated_disclosure_documentation["transfer:StartFileTransfer"] == expected_doc


def test_api_destination_endpoint_redirect_exposes_stored_connection_auth():
    expected_doc = "aws-privilege-escalation/aws-eventbridge-privesc/README.md"
    assert ["events:UpdateApiDestination"] in sensitive_combinations
    assert ["events:UpdateApiDestination"] not in very_sensitive_combinations
    assert tested_risk_documentation["events:UpdateApiDestination"] == expected_doc
    assert live_validated_disclosure_documentation["events:UpdateApiDestination"] == expected_doc


def test_api_gateway_patch_can_reuse_stored_integration_role():
    expected_doc = "aws-post-exploitation/aws-api-gateway-post-exploitation/README.md"
    assert ["apigateway:PATCH"] in sensitive_combinations
    assert ["apigateway:PATCH"] not in very_sensitive_combinations
    assert tested_risk_documentation["apigateway:PATCH"] == expected_doc
    assert live_validated_disclosure_documentation["apigateway:PATCH"] == expected_doc


def test_alb_rule_redirect_can_intercept_matching_sensitive_requests():
    expected_doc = "aws-services/aws-ec2-ebs-elb-ssm-vpc-and-vpn-enum/README.md"
    assert ["elasticloadbalancing:ModifyRule"] in sensitive_combinations
    assert ["elasticloadbalancing:ModifyRule"] not in very_sensitive_combinations
    assert tested_risk_documentation["elasticloadbalancing:ModifyRule"] == expected_doc
    assert live_validated_disclosure_documentation["elasticloadbalancing:ModifyRule"] == expected_doc


def test_iot_publish_can_feed_preconfigured_privileged_rule_action():
    expected_doc = "aws-services/aws-iot-core-enum.md"
    assert ["iot:Publish"] in sensitive_combinations
    assert ["iot:Publish"] not in very_sensitive_combinations
    assert tested_risk_documentation["iot:Publish"] == expected_doc


def test_athena_workgroup_result_redirect_is_conditionally_high():
    expected_doc = "aws-services/aws-s3-athena-and-glacier-enum.md"
    assert ["athena:UpdateWorkGroup"] in sensitive_combinations
    assert ["athena:UpdateWorkGroup"] not in very_sensitive_combinations
    assert tested_risk_documentation["athena:UpdateWorkGroup"] == expected_doc
    assert live_validated_disclosure_documentation["athena:UpdateWorkGroup"] == expected_doc


def test_athena_prepared_statement_poisoning_is_conditionally_high():
    expected_doc = "aws-services/aws-s3-athena-and-glacier-enum.md"
    assert ["athena:UpdatePreparedStatement"] in sensitive_combinations
    assert ["athena:UpdatePreparedStatement"] not in very_sensitive_combinations
    assert tested_risk_documentation["athena:UpdatePreparedStatement"] == expected_doc
    assert live_validated_disclosure_documentation[
        "athena:UpdatePreparedStatement"
    ] == expected_doc


def test_athena_named_query_poisoning_is_conditionally_high():
    expected_doc = "aws-services/aws-s3-athena-and-glacier-enum.md"
    assert ["athena:UpdateNamedQuery"] in sensitive_combinations
    assert ["athena:UpdateNamedQuery"] not in very_sensitive_combinations
    assert tested_risk_documentation["athena:UpdateNamedQuery"] == expected_doc
    assert live_validated_disclosure_documentation["athena:UpdateNamedQuery"] == expected_doc


def test_athena_notebook_poisoning_is_conditionally_high():
    expected_doc = "aws-services/aws-s3-athena-and-glacier-enum.md"
    assert ["athena:UpdateNotebook"] in sensitive_combinations
    assert ["athena:UpdateNotebook"] not in very_sensitive_combinations
    assert tested_risk_documentation["athena:UpdateNotebook"] == expected_doc
    assert live_validated_disclosure_documentation["athena:UpdateNotebook"] == expected_doc


def test_firehose_update_retains_stored_http_destination_key():
    expected_doc = "aws-services/aws-kinesis-data-firehose-enum.md"
    assert ["firehose:UpdateDestination"] in sensitive_combinations
    assert ["firehose:UpdateDestination"] not in very_sensitive_combinations
    assert tested_risk_documentation["firehose:UpdateDestination"] == expected_doc
    assert live_validated_disclosure_documentation["firehose:UpdateDestination"] == expected_doc


def test_runtime_configuration_writes_have_tested_consumers():
    assert ["secretsmanager:PutSecretValue"] in sensitive_combinations
    assert ["ssm:PutParameter"] in sensitive_combinations
    assert tested_risk_documentation["secretsmanager:PutSecretValue"] == (
        "aws-privilege-escalation/aws-codebuild-privesc/README.md"
    )


def test_appflow_start_needs_a_readable_destination_for_disclosure():
    assert ["appflow:StartFlow", "s3:GetObject"] in sensitive_combinations
    assert ["appflow:StartFlow"] not in sensitive_combinations
    assert live_validated_disclosure_documentation["appflow:StartFlow"] == (
        "aws-services/aws-appflow-enum.md"
    )


def test_databrew_start_needs_a_readable_destination_for_disclosure():
    assert ["databrew:StartJobRun", "s3:GetObject"] in sensitive_combinations
    assert ["databrew:StartJobRun"] not in sensitive_combinations
    assert live_validated_disclosure_documentation["databrew:StartJobRun"] == (
        "aws-services/aws-databrew-enum.md"
    )


def test_async_destination_redirect_or_fixed_consumer_is_conditionally_high():
    combination = ["lambda:UpdateFunctionEventInvokeConfig", "sqs:ReceiveMessage"]
    assert combination in sensitive_combinations
    expected_doc = "aws-persistence/aws-lambda-persistence/README.md"
    for action in (
        "lambda:PutFunctionEventInvokeConfig",
        "lambda:UpdateFunctionEventInvokeConfig",
    ):
        assert [action] in sensitive_combinations
        assert [action] not in very_sensitive_combinations
        assert tested_risk_documentation[action] == expected_doc
        assert live_validated_disclosure_documentation[action] == expected_doc


def test_sagemaker_create_actions_are_not_high_without_required_delegation():
    incomplete = {
        "sagemaker:CreateNotebookInstance",
        "sagemaker:CreateProcessingJob",
        "sagemaker:CreateTrainingJob",
        "sagemaker:CreateHyperParameterTuningJob",
    }
    for action in incomplete:
        assert [action] not in sensitive_combinations
        assert [action] not in very_sensitive_combinations

    assert ["sagemaker:CreateProcessingJob", "iam:PassRole"] in very_sensitive_combinations
    assert ["sagemaker:CreateTrainingJob", "iam:PassRole"] in very_sensitive_combinations
    assert [
        "sagemaker:CreateHyperParameterTuningJob",
        "iam:PassRole",
    ] in very_sensitive_combinations


def test_callback_output_injection_requires_a_live_task_token():
    combination = ["states:SendTaskSuccess", "sqs:ReceiveMessage"]
    assert combination in sensitive_combinations
    assert ["states:SendTaskSuccess"] not in sensitive_combinations
    assert live_validated_disclosure_documentation["states:SendTaskSuccess"] == (
        "aws-post-exploitation/aws-stepfunctions-post-exploitation/README.md"
    )
    assert [
        "sagemaker:CreateNotebookInstance",
        "iam:PassRole",
        "sagemaker:CreatePresignedNotebookInstanceUrl",
    ] in very_sensitive_combinations


def test_singleton_attack_registry_and_runtime_classifier_agree():
    critical_singletons = {
        combination[0]
        for combination in very_sensitive_combinations
        if len(combination) == 1
    }
    high_singletons = {
        combination[0]
        for combination in sensitive_combinations
        if len(combination) == 1
    }

    for action in critical_singletons:
        assert classify_permission(
            "aws", action, unknown_default="medium"
        ) == "critical", action
    for action in high_singletons - critical_singletons:
        assert classify_permission(
            "aws", action, unknown_default="medium"
        ) == "high", action


def test_hacktricks_reconciliation_is_complete_and_evidenced():
    expected = {
        "amplifybackend:CreateToken",
        "amplifybackend:GetToken",
        "apigateway:POST",
        "apigateway:PUT",
        "appconfig:CreateHostedConfigurationVersion",
        "appconfig:StartDeployment",
        "backup:PutBackupVaultAccessPolicy",
        "codebuild:StartBuild",
        "codebuild:StartBuildBatch",
        "codecommit:GitPush",
        "ecr:GetAuthorizationToken",
        "ecr:BatchCheckLayerAvailability",
        "ecr:CompleteLayerUpload",
        "ecr:InitiateLayerUpload",
        "ecr:PutImage",
        "ecr:UploadLayerPart",
        "ec2:GetPasswordData",
        "iam:PutRolePermissionsBoundary",
        "iam:PutUserPermissionsBoundary",
        "lambda:PutProvisionedConcurrencyConfig",
        "lambda:UpdateFunctionCode",
        "pipes:UpdatePipe",
        "rds:StartExportTask",
        "secretsmanager:RotateSecret",
        "secretsmanager:ListSecrets",
        "ssm:GetParametersByPath",
        "sso:GetRoleCredentials",
        "sts:GetDelegatedAccessToken",
    }
    assert hacktricks_reconciled_true_positive_actions == expected
    assert expected <= set(live_validated_disclosure_documentation)


def test_hacktricks_pr_heading_exclusions_are_explicit():
    assert hacktricks_pr_heading_exclusions == {
        "elasticbeanstalk:DeleteApplication": "cleanup/availability action",
        "elasticbeanstalk:SwapEnvironmentCNAMEs": "cleanup/availability action",
        "elasticbeanstalk:TerminateEnvironment": "cleanup/availability action",
        "elasticmapreduce:OpenEditorInConsole": "negative legacy-console boundary",
        "iam:PassRole": "dependency already registered as standalone Critical",
        "rds:CreateDBInstance": (
            "resource creation succeeded without credential exposure or privilege escalation"
        ),
    }


def test_complete_known_positive_inventory_matches_evidence_and_classifier():
    tracker = (
        Path(__file__).resolve().parents[1]
        / "docs"
        / "AWS-cross-service-security-review.md"
    ).read_text(encoding="utf-8")
    begin = "<!-- BEGIN GENERATED KNOWN-POSITIVE AWS TEST INVENTORY -->"
    end = "<!-- END GENERATED KNOWN-POSITIVE AWS TEST INVENTORY -->"
    assert tracker.count(begin) == tracker.count(end) == 1
    generated = tracker.split(begin, 1)[1].split(end, 1)[0]
    rows = {
        action: level.lower()
        for action, level in re.findall(
            r"^\| `([^`]+)` \| (Critical|High|Medium|Low) \|",
            generated,
            flags=re.MULTILINE,
        )
    }
    assert set(rows) == set(live_validated_disclosure_documentation)
    for action, documented_level in rows.items():
        assert documented_level == classify_permission(
            "aws", action, unknown_default="medium"
        ), action
