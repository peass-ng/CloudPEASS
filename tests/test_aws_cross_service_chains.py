from sensitive_permissions.aws import (
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


def test_transfer_connector_url_redirect_exposes_stored_sftp_credential():
    expected_doc = "aws-privilege-escalation/aws-transfer-family-privesc/README.md"
    assert ["transfer:UpdateConnector"] in sensitive_combinations
    assert ["transfer:UpdateConnector"] not in very_sensitive_combinations
    assert tested_risk_documentation["transfer:UpdateConnector"] == expected_doc
    assert live_validated_disclosure_documentation["transfer:UpdateConnector"] == expected_doc


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


def test_async_destination_redirect_needs_a_readable_sink():
    combination = ["lambda:UpdateFunctionEventInvokeConfig", "sqs:ReceiveMessage"]
    assert combination in sensitive_combinations
    assert ["lambda:UpdateFunctionEventInvokeConfig"] not in sensitive_combinations
    assert live_validated_disclosure_documentation[
        "lambda:UpdateFunctionEventInvokeConfig"
    ] == "aws-persistence/aws-lambda-persistence/README.md"


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
