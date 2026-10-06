import subprocess
import re
import os
import json
import threading
from datetime import date, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError
from tqdm import tqdm
import shutil
import shlex
from functools import lru_cache

import boto3

from colorama import Fore, init


class AWSBruteForce():

    CLI_MODEL_ALIASES = {
        "configservice": "config",
        "deploy": "codedeploy",
        "s3api": "s3",
    }

    MAX_DISCOVERY_RESPONSE_BYTES = 1_000_000
    MAX_DISCOVERY_VALUES_PER_FIELD = 8
    MAX_REAL_ID_PROBES_PER_COMMAND = 3
    IDENTIFIER_FIELD_SUFFIXES = ("arn", "id", "identifier", "name")
    SENSITIVE_FIELD_PARTS = (
        "accesskey", "credential", "password", "secretstring", "secretbinary",
        "token", "privatekey", "publickey", "certificatebody", "content",
    )
    CREDENTIAL_ERROR_RE = re.compile(
        r"ExpiredToken|InvalidClientTokenId|UnrecognizedClientException|"
        r"InvalidSignatureException|SignatureDoesNotMatch|RequestExpired|"
        r"TokenRefreshRequired|Unable to locate credentials|SSO session .*expired",
        re.I,
    )

    # CloudTrail can preserve resource identifiers after list access is lost or
    # after a resource is deleted. Only use formats validated for these EUC
    # services; arbitrary historical strings would make probes less reliable.
    HISTORICAL_EVENT_SOURCES = {
        "workmail": "workmail.amazonaws.com",
        "workspaces": "workspaces.amazonaws.com",
        "workspaces-web": "workspaces-web.amazonaws.com",
        "workspaces-thin-client": "workspaces-thin-client.amazonaws.com",
        "workspaces-instances": "workspaces-instances.amazonaws.com",
    }
    HISTORICAL_ID_PATTERNS = {
        ("workmail", "organization-id"): re.compile(r"^m-[0-9a-f]{32}$", re.I),
        ("workspaces", "workspace-id"): re.compile(r"^ws-[0-9a-z]{8,63}$", re.I),
        ("workspaces", "pool-id"): re.compile(r"^wspool-[0-9a-z]{9}$", re.I),
        ("workspaces-web", "portal-id"): re.compile(r"^[0-9a-z-]{36}$", re.I),
        ("workspaces-web", "session-id"): re.compile(r"^[0-9a-z-]{36}$", re.I),
        ("workspaces-instances", "workspace-instance-id"): re.compile(
            r"^wsinst-[0-9a-z]{8,63}$", re.I
        ),
    }

    # These are named like reads but mint temporary credentials/tokens.
    # They are unnecessary for permission discovery and therefore never probed.
    BLOCKED_COMMANDS = {
        ("amplifybackend", "get-token"),
        ("bedrock-agentcore", "get-resource-oauth2-token"),
        ("bedrock-agentcore", "get-workload-access-token"),
        ("bedrock-agentcore", "get-workload-access-token-for-jwt"),
        ("bedrock-agentcore", "get-workload-access-token-for-user-id"),
        ("codeartifact", "get-authorization-token"),
        ("cognito-identity", "get-credentials-for-identity"),
        ("cognito-identity", "get-open-id-token"),
        ("cognito-identity", "get-open-id-token-for-developer-identity"),
        ("cognito-idp", "get-tokens-from-refresh-token"),
        ("connect", "get-federation-token"),
        ("datazone", "get-environment-credentials"),
        ("ecr", "get-authorization-token"),
        ("ecr", "get-login-password"),
        ("ecr-public", "get-authorization-token"),
        ("ecr-public", "get-login-password"),
        ("emr", "get-cluster-session-credentials"),
        ("emr-containers", "get-managed-endpoint-session-credentials"),
        ("finspace-data", "get-programmatic-access-credentials"),
        ("gamelift", "get-compute-auth-token"),
        ("lakeformation", "get-temporary-glue-partition-credentials"),
        ("lakeformation", "get-temporary-glue-table-credentials"),
        ("license-manager", "get-access-token"),
        ("quicksight", "get-session-embed-url"),
        ("redshift", "get-cluster-credentials"),
        ("redshift", "get-cluster-credentials-with-iam"),
        ("redshift", "get-identity-center-auth-token"),
        ("redshift-serverless", "get-credentials"),
        ("redshift-serverless", "get-identity-center-auth-token"),
        ("route53globalresolver", "get-access-token"),
        ("secretsmanager", "get-random-password"),
        ("ssm", "get-access-token"),
        ("sso", "get-role-credentials"),
        ("sts", "get-delegated-access-token"),
        ("sts", "get-federation-token"),
        ("sts", "get-session-token"),
        ("sts", "get-web-identity-token"),
        ("waf", "get-change-token"),
        ("waf-regional", "get-change-token"),
    }

    # Guard new AWS CLI releases even before their token/credential getters are
    # added to the explicit list above. These patterns intentionally do not
    # block read-only token metadata/balance APIs.
    BLOCKED_COMMAND_PATTERNS = (
        re.compile(r"^get-.*credentials(?:-|$)"),
        re.compile(
            r"^get-(?:.*-)?(?:authorization|auth|access|identity-center-auth|open-id|"
            r"federation|session|workload-access)-token(?:-|$)"
        ),
        re.compile(r"^get-(?:random-password|session-embed-url|change-token)$"),
    )

    def __init__(
        self,
        debug,
        region,
        profile,
        aws_services,
        threads,
        access_key_id=None,
        secret_access_key=None,
        session_token=None,
        profile_uses_environment_credentials=False,
    ):
        self.debug = debug
        self.region = region
        self.profile = profile
        self.aws_services = [a.lower() for a in aws_services]
        self.num_threads = max(1, min(int(threads), 64))
        self.found_permissions = []
        self.lock = threading.Lock()
        self.access_key_id = access_key_id
        self.secret_access_key = secret_access_key
        self.session_token = session_token
        self.profile_uses_environment_credentials = profile_uses_environment_credentials
        self.probe_stats = {"timeouts": 0, "os_errors": 0, "credential_errors": 0}
        self.stop_event = threading.Event()
        self.history_lock = threading.Lock()
        self.history_cache = {}
        self.historical_values_used = set()
        self.discovered_identifiers = {}
        self.discovery_lock = threading.Lock()
        self.discovery_stats = {"values": 0, "real_id_probes": 0, "real_id_confirmed": 0}

        self.aws_cli = shutil.which("aws")

    # Utility functions
    def transform_command(self, command):
        substitutions = [
            (r'^accessanaly[sz]er:', 'access-analyzer:'),
            (r'^amp:', 'aps:'),
            (r'apigateway:Get.*', 'apigateway:GET'),
            (r'apigatewayv2:Get.*', 'apigateway:GET'),
            (r'^appintegrations:', 'app-integrations:'),
            (r'^application-insights:', 'applicationinsights:'),
            (r'athena:ListApplicationDpuSizes', 'athena:ListApplicationDPUSizes'),
            (r'^chime-.*:', 'chime:'),
            (r'^(?:cloudcontrol|cloudcontrolapi):', 'cloudformation:'),
            (r'cloudfront:ListDistributionsByWebAclId', 'cloudfront:ListDistributionsByWebACLId'),
            (r'^cloudhsmv2:', 'cloudhsm:'),
            (r'^codeguruprofiler:', 'codeguru-profiler:'),
            (r'comprehendmedical:ListIcd10CmInferenceJobs', 'comprehendmedical:ListICD10CMInferenceJobs'),
            (r'comprehendmedical:ListPhiDetectionJobs', 'comprehendmedical:ListPHIDetectionJobs'),
            (r'comprehendmedical:ListSnomedctInferenceJobs', 'comprehendmedical:ListSNOMEDCTInferenceJobs'),
            (r'^configservice:', 'config:'),
            (r'^connectcampaigns:', 'connect-campaigns:'),
            (r'^connectcases:', 'cases:'),
            (r'^customer-profiles:', 'profile:'),
            (r'^deploy:', 'codedeploy:'),
            (r'detective:ListOrganizationAdminAccounts', 'detective:ListOrganizationAdminAccount'),
            (r'^docdb:', 'rds:'),
            (r'^dynamodbstreams:', 'dynamodb:'),
            (r'ecr:GetLoginPassword', 'ecr:GetAuthorizationToken'),
            (r'^efs:', 'elasticfilesystem:'),
            (r'^elbv2:', 'elasticloadbalancing:'),
            (r'^elb:', 'elasticloadbalancing:'),
            (r'^emr:', 'elasticmapreduce:'),
            (r'frauddetector:GetKmsEncryptionKey', 'frauddetector:GetKMSEncryptionKey'),
            (r'gamelift:DescribeEc2InstanceLimits', 'gamelift:DescribeEC2InstanceLimits'),
            (r'glue:GetMlTransforms', 'glue:GetMLTransforms'),
            (r'glue:ListMlTransforms', 'glue:ListMLTransforms'),
            (r'^greengrassv2:', 'greengrass:'),
            (r'healthlake:ListFhirDatastores', 'healthlake:ListFHIRDatastores'),
            (r'iam:ListMfaDevices', 'iam:ListMFADevices'),
            (r'iam:ListOpenIdConnectProviders', 'iam:ListOpenIDConnectProviders'),
            (r'iam:ListSamlProviders', 'iam:ListSAMLProviders'),
            (r'iam:ListSshPublicKeys', 'iam:ListSSHPublicKeys'),
            (r'iam:ListVirtualMfaDevices', 'iam:ListVirtualMFADevices'),
            (r'iot:ListCaCertificates', 'iot:ListCACertificates'),
            (r'iot:ListOtaUpdates', 'iot:ListOTAUpdates'),
            (r'^(?:iot-data|iotdata):', 'iot:'),
            (r'^(?:iotsecuretunneling|IoTSecuredTunneling):', 'iot:'),
            (r'^ivs-realtime:', 'ivs:'),
            (r'^kinesis-video-archived-media:', 'kinesisvideo:'),
            (r'^kinesis-video-signaling:', 'kinesisvideo:'),
            (r'^kinesisanalyticsv2:', 'kinesisanalytics:'),
            (r'lakeformation:ListLfTags', 'lakeformation:ListLFTags'),
            (r'^lex-models:', 'lex:'),
            (r'^lexv2-models:', 'lex:'),
            (r'lightsail:GetContainerApiMetadata', 'lightsail:GetContainerAPIMetadata'),
            (r'^location:', 'geo:'),
            (r'^marketplace-entitlement:', 'aws-marketplace:'),
            (r'^migration-hub-refactor-spaces:', 'refactor-spaces:'),
            (r'^migrationhub-config:', 'mgh:'),
            (r'^migrationhuborchestrator:', 'migrationhub-orchestrator:'),
            (r'^migrationhubstrategy:', 'migrationhub-strategy:'),
            (r'^monitoring:', 'cloudwatch:'),
            (r'^mwaa:', 'airflow:'),
            (r'^neptune:', 'rds:'),
            (r'network-firewall:ListTlsInspectionConfigurations', 'network-firewall:ListTLSInspectionConfigurations'),
            (r'^opensearch:', 'es:'),
            (r'^opensearchserverless:', 'aoss:'),
            (r'organizations:ListAwsServiceAccessForOrganization', 'organizations:ListAWSServiceAccessForOrganization'),
            (r'^pinpoint:', 'mobiletargeting:'),
            (r'^pinpoint-email:', 'ses:'),
            (r'^pinpoint-sms-voice-v2:', 'sms-voice:'),
            (r'^privatenetworks:', 'private-networks:'),
            (r'Db', 'DB'),
            (r'^(?:resourcegroupstaggingapi|tagging):', 'tag:'),
            (r'^s3outposts:', 's3-outposts:'),
            (r'sagemaker:ListAutoMlJobs', 'sagemaker:ListAutoMLJobs'),
            (r'sagemaker:ListCandidatesForAutoMlJob', 'sagemaker:ListCandidatesForAutoMLJob'),
            (r'^service-quotas:', 'servicequotas:'),
            (r'servicecatalog:GetAwsOrganizationsAccessStatus', 'servicecatalog:GetAWSOrganizationsAccessStatus'),
            (r'^servicecatalog-appregistry:', 'servicecatalog:'),
            (r'^sesv2:', 'ses:'),
            (r'sns:GetSmsAttributes', 'sns:GetSMSAttributes'),
            (r'sns:GetSmsSandboxAccountStatus', 'sns:GetSMSSandboxAccountStatus'),
            (r'sns:ListSmsSandboxPhoneNumbers', 'sns:ListSMSSandboxPhoneNumbers'),
            (r'^(?:sso-admin|awsssoportal):', 'sso:'),
            (r'^stepfunctions:', 'states:'),
            (r'^support-app:', 'supportapp:'),
            (r'^taxsettings:', 'tax:'),
            (r'^timestream-query:', 'timestream:'),
            (r'^timestream-write:', 'timestream:'),
            (r'^voice-id:', 'voiceid:'),
            (r'waf:ListIpSets', 'waf:ListIPSets'),
            (r'waf:ListWebAcls', 'waf:ListWebACLs'),
            (r'waf-regional:ListIpSets', 'waf-regional:ListIPSets'),
            (r'waf-regional:ListWebAcls', 'waf-regional:ListWebACLs'),
            (r'^keyspaces:ListKeyspaces', 'cassandra:Select'),
            (r'^keyspaces:ListTables', 'cassandra:Select'),
            (r'^s3api:ListBuckets', 's3:ListAllMyBuckets'),
            (r'^s3api:', 's3:'),
        ]

        for pattern, replacement in substitutions:
            command = re.sub(pattern, replacement, command)

        return command

    def capitalize(self, command):
        return ''.join(word.capitalize() for word in command.split('-'))

    @classmethod
    @lru_cache(maxsize=None)
    def _service_model(cls, service):
        model_service = cls.CLI_MODEL_ALIASES.get(service, service)
        return boto3.Session()._session.get_service_model(model_service)

    @classmethod
    @lru_cache(maxsize=None)
    def _operation_map(cls, service):
        try:
            model = cls._service_model(service)
        except Exception:
            return {}
        result = {}
        for operation in model.operation_names:
            cli_name = re.sub(r"(.)([A-Z][a-z]+)", r"\1-\2", operation)
            cli_name = re.sub(r"([a-z0-9])([A-Z])", r"\1-\2", cli_name).lower()
            result[cli_name] = operation
        return result

    def permission_for_command(self, service, command):
        operation = self._operation_map(service).get(command, self.capitalize(command))
        return self.transform_command(f"{service}:{operation}")

    @classmethod
    def _is_blocked_command(cls, service, command):
        return (service, command) in cls.BLOCKED_COMMANDS or any(
            pattern.search(command) for pattern in cls.BLOCKED_COMMAND_PATTERNS
        )

    def _build_command(self, profile, region, service, command, extra):
        base = [
            self.aws_cli or "aws",
            "--cli-connect-timeout",
            "5",
            "--cli-read-timeout",
            "10",
        ]
        if profile:
            base.extend(["--profile", profile])
        if region:
            base.extend(["--region", region])
        base.extend([service, command])
        if extra:
            base.extend(extra if isinstance(extra, list) else shlex.split(extra))
        return base

    def _build_env(self, profile):
        env = os.environ.copy()
        env["AWS_PAGER"] = ""
        env["AWS_CLI_AUTO_PROMPT"] = "off"
        env["AWS_MAX_ATTEMPTS"] = "2"
        env["AWS_DEFAULT_OUTPUT"] = "json"
        # --profile must not silently probe as unrelated ambient credentials,
        # except when its source chain explicitly uses credential_source=Environment.
        if not (profile and self.profile_uses_environment_credentials):
            for var_name in (
                "AWS_ACCESS_KEY_ID",
                "AWS_SECRET_ACCESS_KEY",
                "AWS_SESSION_TOKEN",
                "AWS_SECURITY_TOKEN",
                "AWS_WEB_IDENTITY_TOKEN_FILE",
                "AWS_ROLE_ARN",
                "AWS_ROLE_SESSION_NAME",
                "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
                "AWS_CONTAINER_CREDENTIALS_FULL_URI",
                "AWS_CONTAINER_AUTHORIZATION_TOKEN",
            ):
                env.pop(var_name, None)
        if profile:
            return env
        for var_name in (
            "AWS_PROFILE",
            "AWS_DEFAULT_PROFILE",
            "AWS_SHARED_CREDENTIALS_FILE",
            "AWS_CONFIG_FILE",
            "AWS_SDK_LOAD_CONFIG",
            "AWS_CREDENTIAL_EXPIRATION",
        ):
            env.pop(var_name, None)
        if self.access_key_id:
            env['AWS_ACCESS_KEY_ID'] = self.access_key_id
        if self.secret_access_key:
            env['AWS_SECRET_ACCESS_KEY'] = self.secret_access_key
        if self.session_token:
            env['AWS_SESSION_TOKEN'] = self.session_token
        else:
            env.pop("AWS_SESSION_TOKEN", None)
        env["AWS_EC2_METADATA_DISABLED"] = "true"
        return env

    def _get_aws_help(self, service=None):
        env = os.environ.copy()
        # AWS CLI help may inherit an interactive pager from the user's shell.
        # Force plain output so help parsing behaves consistently across systems.
        env["AWS_PAGER"] = ""
        env["PAGER"] = "cat"
        env["MANPAGER"] = "cat"

        if not self.aws_cli:
            return []

        command = [self.aws_cli]
        if service:
            command.append(service)
        command.append("help")

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                timeout=30,
                env=env,
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            if self.debug:
                print(f"[DEBUG] Could not read AWS CLI help for {' '.join(command)}: {exc}")
            return []

        if result.returncode != 0:
            if self.debug:
                error = result.stderr.decode(errors="replace").strip()
                print(f"[DEBUG] Failed to run {' '.join(command)}: {error}")
            return []

        output = result.stdout
        if shutil.which("col"):
            try:
                col_result = subprocess.run(
                    ["col", "-b"],
                    input=output,
                    capture_output=True,
                    timeout=5,
                )
                if col_result.returncode == 0:
                    output = col_result.stdout
            except (OSError, subprocess.TimeoutExpired):
                pass

        return output.decode(errors="replace").splitlines()

    @staticmethod
    def _display_command(command):
        # Successful probes can now use real resource identifiers. Keep those
        # identifiers out of terminal output and logs.
        safe = list(command)
        visible_options = {
            "--cli-connect-timeout", "--cli-read-timeout", "--profile", "--region",
            "--output", "--query", "--max-results", "--max-items", "--no-paginate",
        }
        for index, item in enumerate(safe[:-1]):
            if item.startswith("--") and item not in visible_options and not safe[index + 1].startswith("--"):
                safe[index + 1] = "<resource>"
        return shlex.join(safe)

    @staticmethod
    def _placeholder_for(option, service=None, command=None):
        option_name = option.lstrip("-").lower()
        if (
            service == "invoicing"
            and command == "list-invoice-summaries"
            and option_name == "selector"
        ):
            return "ResourceType=INVOICE_ID,Value=CloudPEASSProbe"
        if service == "ce" and command == "get-cost-and-usage":
            if option_name == "time-period":
                end = date.today()
                start = end - timedelta(days=1)
                return f"Start={start.isoformat()},End={end.isoformat()}"
            if option_name == "granularity":
                return "DAILY"
            if option_name == "metrics":
                return "UnblendedCost"
        if service == "workspaces" and option_name == "workspace-id":
            return "ws-00000000"
        if service == "workspaces-web" and option_name in {
            "portal-id",
            "session-id",
        }:
            return "00000000-0000-0000-0000-000000000000"
        if service == "workspaces-thin-client" and option_name == "id":
            if command == "get-device":
                return "000000000000000000000000"
            if command == "get-environment":
                return "000000000"
        if (
            service == "workspaces-instances"
            and option_name == "workspace-instance-id"
        ):
            return "wsinst-00000000"
        if service == "workmail" and option_name == "organization-id":
            return "m-00000000000000000000000000000000"
        if "email" in option_name:
            return "cloudpeass-probe@example.invalid"
        if "arn" in option_name:
            return "arn:aws:iam::123456789012:role/CloudPEASSProbe"
        if any(part in option_name for part in ("account", "owner")):
            return "123456789012"
        if "region" in option_name:
            return "us-east-1"
        if any(part in option_name for part in ("max-items", "max-results", "limit", "size")):
            return "1"
        return "CloudPEASSProbe"

    @staticmethod
    def _walk_named_strings(value, field_name=""):
        if isinstance(value, str):
            normalized = re.sub(r"[^a-z0-9]", "", field_name.casefold())
            yield normalized, value
        elif isinstance(value, dict):
            for key, child in value.items():
                yield from AWSBruteForce._walk_named_strings(child, str(key))
        elif isinstance(value, (list, tuple)):
            for child in value:
                yield from AWSBruteForce._walk_named_strings(child, field_name)

    def _historical_identifiers(self, profile, region, service):
        """Return validated IDs from recent CloudTrail events, cached per service."""
        event_source = self.HISTORICAL_EVENT_SOURCES.get(service)
        if not event_source or not self.aws_cli:
            return []
        cache_key = (profile or "", region or "", service)
        with self.history_lock:
            if cache_key in self.history_cache:
                return self.history_cache[cache_key]

            command = self._build_command(
                profile,
                region,
                "cloudtrail",
                "lookup-events",
                [
                    "--lookup-attributes",
                    f"AttributeKey=EventSource,AttributeValue={event_source}",
                    "--max-results",
                    "50",
                    "--no-paginate",
                    "--output",
                    "json",
                ],
            )
            values = []
            try:
                result = subprocess.run(
                    command,
                    capture_output=True,
                    timeout=20,
                    env=self._build_env(profile),
                )
                if result.returncode == 0:
                    response = json.loads(result.stdout.decode(errors="replace"))
                    events = response.get("Events", []) if isinstance(response, dict) else []
                    for event in events:
                        if not isinstance(event, dict):
                            continue
                        candidates = []
                        try:
                            payload = json.loads(event.get("CloudTrailEvent", "{}"))
                            # Never recycle a syntactically valid ID from a failed
                            # probe. That creates a feedback loop where our own
                            # dummy request is mistaken for an observed resource.
                            # A WorkMail organization-state response is the one
                            # tested exception: it identifies a real organization
                            # after authorization but before the requested lookup.
                            trusted_error = isinstance(payload, dict) and payload.get(
                                "errorCode"
                            ) in {None, "OrganizationStateException"}
                            if trusted_error:
                                candidates.extend(
                                    [
                                        payload.get("requestParameters"),
                                        payload.get("responseElements"),
                                        payload.get("resources"),
                                    ]
                                )
                        except (TypeError, ValueError, json.JSONDecodeError):
                            pass
                        for candidate in candidates:
                            values.extend(self._walk_named_strings(candidate))
            except (
                OSError,
                subprocess.TimeoutExpired,
                UnicodeError,
                ValueError,
                json.JSONDecodeError,
            ) as exc:
                if self.debug:
                    print(
                        f"[DEBUG] Could not mine historical {service} IDs from "
                        f"CloudTrail: {exc}"
                    )

            self.history_cache[cache_key] = list(dict.fromkeys(values))
            return self.history_cache[cache_key]

    def _probe_value_for(self, option, profile, region, service, command):
        """Prefer a real historical ID, then fall back to a safe dummy value."""
        option_name = option.lstrip("-").lower()
        normalized_option = re.sub(r"[^a-z0-9]", "", option_name.casefold())
        pattern = self.HISTORICAL_ID_PATTERNS.get((service, option_name))
        fallback = self._placeholder_for(option, service, command)
        if pattern:
            for field_name, value in self._historical_identifiers(
                profile, region, service
            ):
                if (
                    field_name in {normalized_option, f"{normalized_option}s"}
                    and value != fallback
                    and pattern.fullmatch(value)
                ):
                    with self.lock:
                        self.historical_values_used.add((service, option_name, value))
                    if self.debug:
                        print(
                            f"[DEBUG] Using CloudTrail {service} {option} value: {value}"
                        )
                    return value
        return fallback

    @staticmethod
    def _required_options(output):
        """Extract required CLI options without depending on bullet or line characters."""
        matches = re.findall(
            r"(?:following arguments are required|arguments are required):\s*([^\r\n]+)",
            output,
            flags=re.I,
        )
        options = []
        for match in matches:
            options.extend(re.findall(r"--[a-zA-Z0-9][a-zA-Z0-9-]*", match))
        return list(dict.fromkeys(options))

    @classmethod
    @lru_cache(maxsize=None)
    def _has_no_required_input(cls, service, command):
        """Use the SDK model to run resource-listing calls before ID-based calls."""
        operation = cls._operation_map(service).get(command)
        if not operation:
            return False
        try:
            model = cls._service_model(service)
            shape = model.operation_model(operation).input_shape
            return shape is None or not shape.required_members
        except Exception:
            return False

    @staticmethod
    def _identifier_key(field):
        key = re.sub(r"[^a-z0-9]", "", str(field).casefold())
        if not key or any(part in key for part in AWSBruteForce.SENSITIVE_FIELD_PARTS):
            return None
        if key.endswith(("arns", "ids", "identifiers", "names", "queueurls")):
            key = key[:-1]
        if key == "bucket" or key == "queueurl" or key.endswith(
            AWSBruteForce.IDENTIFIER_FIELD_SUFFIXES
        ):
            return key
        return None

    def _remember_identifiers(self, service, command, output):
        """Keep only bounded, non-secret identifiers from a successful read response."""
        if not output or len(output) > self.MAX_DISCOVERY_RESPONSE_BYTES:
            return
        try:
            payload = json.loads(output)
        except (TypeError, ValueError, UnicodeError):
            return
        pending = [(payload, "", 0)]
        examined = 0
        found = []
        while pending and examined < 1000:
            node, path, depth = pending.pop()
            examined += 1
            if depth > 6:
                continue
            if isinstance(node, dict):
                for field, value in list(node.items())[:100]:
                    field_key = self._identifier_key(field)
                    if field_key:
                        scalar_values = (
                            value[: self.MAX_DISCOVERY_VALUES_PER_FIELD]
                            if isinstance(value, list) else [value]
                        )
                        for scalar in scalar_values:
                            if not isinstance(scalar, str):
                                continue
                            scalar = scalar.strip()
                            if (
                                1 <= len(scalar) <= 512
                                and not any(ord(char) < 32 for char in scalar)
                                and "CloudPEASSProbe" not in scalar
                                and (not field_key.endswith("arn") or scalar.startswith("arn:"))
                            ):
                                found.append((field_key, scalar, command, path))
                    if isinstance(value, (dict, list)):
                        pending.append((value, f"{path}/{field}", depth + 1))
            elif isinstance(node, list):
                for value in node[:20]:
                    if isinstance(value, (dict, list)):
                        pending.append((value, path, depth + 1))
        if not found:
            return
        with self.discovery_lock:
            fields = self.discovered_identifiers.setdefault(service, {})
            for field_key, value, source, path in found:
                values = fields.setdefault(field_key, [])
                if len(values) >= self.MAX_DISCOVERY_VALUES_PER_FIELD:
                    continue
                if not any(item[0] == value for item in values):
                    values.append((value, source, path))
                    self.discovery_stats["values"] += 1

    @staticmethod
    def _resource_tokens(command):
        return {
            token.rstrip("s")
            for token in command.split("-")
            if token not in {"get", "list", "describe", "batch", "head", "lookup", "search", "by", "for"}
        }

    def _real_values_for_option(self, service, command, option):
        field = re.sub(r"[^a-z0-9]", "", option.lstrip("-").casefold())
        field_keys = [field]
        if field.endswith("s"):
            field_keys.append(field[:-1])
        stem = field_keys[-1]
        if stem.endswith(("name", "id", "arn")):
            stem = re.sub(r"(?:name|id|arn)$", "", stem)
        if len(stem) >= 4:
            field_keys.extend(stem + suffix for suffix in ("arn", "id", "name"))
        aliases = {
            ("s3api", "bucket"): ("name", "list-buckets", "Buckets"),
            ("ssm", "documentname"): ("name", "list-documents", "DocumentIdentifiers"),
            ("athena", "workgroup"): ("name", "list-work-groups", "WorkGroups"),
        }
        special = aliases.get((service, field))
        if special:
            field_keys.append(special[0])
        if field == "resourcearn":
            field_keys.append("arn")
        if field == "resourceid":
            field_keys.append("id")
        with self.discovery_lock:
            fields = self.discovered_identifiers.get(service, {})
            candidates = [
                (value, source, path, field_key)
                for field_key in field_keys
                for value, source, path in fields.get(field_key, [])
            ]
        if special:
            candidates = [
                item for item in candidates
                if item[3] != special[0]
                or (item[1] == special[1] and special[2] in item[2])
            ]
        target_tokens = self._resource_tokens(command)
        candidates.sort(
            key=lambda item: (
                item[3] == field,
                len(target_tokens & self._resource_tokens(item[1])),
            ),
            reverse=True,
        )
        return list(dict.fromkeys(item[0] for item in candidates))[
            : self.MAX_REAL_ID_PROBES_PER_COMMAND
        ]

    def _real_argument_sets(self, service, command, required_options, extra):
        missing = [option for option in required_options if option not in extra]
        values_by_option = {
            option: self._real_values_for_option(service, command, option)
            for option in missing
        }
        if not any(values_by_option.values()):
            return []
        attempts = []
        for index in range(self.MAX_REAL_ID_PROBES_PER_COMMAND):
            args = list(extra)
            for option in missing:
                values = values_by_option[option]
                value = values[index % len(values)] if values else self._placeholder_for(
                    option, service, command
                )
                args.extend([option, value])
            if args not in attempts:
                attempts.append(args)
        return attempts

    def _caller_account_id(self, profile, region):
        """Return the caller account for probes that reject fabricated IDs."""
        command = self._build_command(
            profile,
            region,
            "sts",
            "get-caller-identity",
            ["--query", "Account", "--output", "text"],
        )
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                timeout=10,
                env=self._build_env(profile),
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
        account_id = result.stdout.decode(errors="replace").strip()
        if result.returncode == 0 and re.fullmatch(r"\d{12}", account_id):
            return account_id
        return None

    def run_command(self, profile, region, service, command, extra=None, cont=0):
        if getattr(self, "stop_event", None) and self.stop_event.is_set():
            return None
        extra = list(extra or [])
        full_command = self._build_command(profile, region, service, command, extra)
        display_command = self._display_command(full_command)
        env = self._build_env(profile)
        
        try:
            result = subprocess.run(full_command, capture_output=True, timeout=20, env=env)
            output = result.stdout.decode(errors="replace") + result.stderr.decode(errors="replace")

            if result.returncode == 0 or re.search(
                r'NoSuchEntity|ResourceNotFoundException|NotFoundException|OrganizationStateException',
                output,
                re.I,
            ):
                if self.debug:
                    print(
                        f"[DEBUG] Successful or authorization-passing service response: "
                        f"{display_command}"
                    )
                perm_command = self.permission_for_command(service, command)
                if result.returncode == 0:
                    confidence = "confirmed"
                elif re.search(r"OrganizationStateException", output, re.I):
                    confidence = "likely; authorized resource-state response"
                else:
                    confidence = "likely; resource was not found"
                print(f"{Fore.YELLOW}[+] {Fore.WHITE}Read access ({confidence}): {Fore.YELLOW}{service} {command} {Fore.BLUE}({display_command}) {Fore.GREEN}({perm_command}){Fore.RESET}")
                
                with self.lock:
                    self.found_permissions.append(perm_command)
                if result.returncode == 0:
                    self._remember_identifiers(service, command, result.stdout)
                    return "confirmed"
                return "likely"

            elif self.CREDENTIAL_ERROR_RE.search(output):
                # Some service endpoints return UnrecognizedClientException to
                # valid credentials. Stop only if STS rejects the same profile.
                identity_command = self._build_command(
                    profile, region, "sts", "get-caller-identity",
                    ["--query", "Arn", "--output", "text"],
                )
                try:
                    identity = subprocess.run(
                        identity_command, capture_output=True, timeout=10, env=env
                    )
                    invalid = identity.returncode != 0 and bool(
                        self.CREDENTIAL_ERROR_RE.search(
                            identity.stdout.decode(errors="replace")
                            + identity.stderr.decode(errors="replace")
                        )
                    )
                except (OSError, subprocess.TimeoutExpired):
                    invalid = False
                if invalid:
                    with self.lock:
                        self.probe_stats["credential_errors"] += 1
                        self.stop_event.set()
                    if self.debug:
                        print(f"[DEBUG] Credentials became unusable while running: {display_command}")
                elif self.debug:
                    print(f"[DEBUG] Service-specific credential error: {service} {command}")

            elif re.search(
                r"AccessDenied|Forbidden|Unauthorized|NotAuthorized|AuthFailure|"
                r"OperationNotPermitted|PermissionDenied|AuthorizationException",
                output,
                re.I,
            ):
                if self.debug:
                    print(f"[DEBUG] Access denied for: {display_command}")

            elif self._required_options(output):
                if cont < 3:
                    required = self._required_options(output)
                    if cont == 0:
                        for real_args in self._real_argument_sets(
                            service, command, required, extra
                        ):
                            with self.discovery_lock:
                                self.discovery_stats["real_id_probes"] += 1
                            outcome = self.run_command(
                                profile, region, service, command, real_args, cont + 1
                            )
                            if outcome == "confirmed":
                                with self.discovery_lock:
                                    self.discovery_stats["real_id_confirmed"] += 1
                                return outcome
                    added = False
                    for required_arg in required:
                        if required_arg not in extra:
                            placeholder = self._probe_value_for(
                                required_arg,
                                profile,
                                region,
                                service,
                                command,
                            )
                            if (
                                service == "invoicing"
                                and command == "batch-get-invoice-profile"
                                and required_arg == "--account-ids"
                            ):
                                placeholder = (
                                    self._caller_account_id(profile, region) or placeholder
                                )
                            extra.extend(
                                [
                                    required_arg,
                                    placeholder,
                                ]
                            )
                            added = True
                    if added:
                        return self.run_command(profile, region, service, command, extra, cont + 1)
                    elif self.debug:
                        print(f"[DEBUG] Required CLI arguments made no progress for: {command}")
                elif self.debug:
                    print(f"[DEBUG] Stopped adding required args for: {command}\n{output.strip()}")

            elif re.search(r'ValidationException|ValidationError|InvalidArnException|InvalidRequestException|InvalidParameterValueException|InvalidARNFault|Invalid ARN|InvalidIpamScopeId.Malformed|InvalidParameterException|invalid literal for', output, re.I):
                if self.debug:
                    print(f"[DEBUG] Validation error for: {display_command}")

            elif re.search(r'Could not connect to the endpoint URL', output, re.I):
                if self.debug:
                    print(f"[DEBUG] Could not connect to endpoint: {display_command}")

            elif re.search(r'Unknown options|MissingParameter|InvalidInputException|error: argument', output, re.I):
                if self.debug:
                    print(f"[DEBUG] Option error for: {display_command}")

            else:
                if self.debug:
                    print(f"[DEBUG] Unhandled response for: {display_command}\n{output.strip()}")

        except subprocess.TimeoutExpired:
            if self.debug:
                print(f"[DEBUG] Command timed out: {display_command}")
            with self.lock:
                self.probe_stats["timeouts"] += 1
        except OSError as exc:
            if self.debug:
                print(f"[DEBUG] Could not run {display_command}: {exc}")
            with self.lock:
                self.probe_stats["os_errors"] += 1

    @staticmethod
    def _help_entries(output, heading):
        """Parse AWS help sections across groff/plain/Unicode bullet formats."""
        entries = []
        in_range = False
        for raw_line in output:
            line = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", raw_line)
            while "\b" in line:
                line = re.sub(r".\x08", "", line)
            line = line.strip()
            upper = line.upper()
            if heading in upper:
                in_range = True
                continue
            if in_range and ("SEE ALSO" in upper or re.match(r"^[A-Z][A-Z ]{3,}$", line)):
                if heading not in upper:
                    in_range = False
            if not in_range or not line:
                continue
            line = re.sub(r"^(?:o|\*|\+|•|·|▪|‣|-)\s+", "", line)
            if re.fullmatch(r"[a-z0-9][a-z0-9-]*", line):
                entries.append(line)
        return list(dict.fromkeys(entries))

    @staticmethod
    def _botocore_services():
        return boto3.Session().get_available_services()

    @staticmethod
    def _botocore_commands(service):
        service = AWSBruteForce.CLI_MODEL_ALIASES.get(service, service)
        try:
            model = boto3.Session()._session.get_service_model(service)
        except Exception:
            return []
        commands = []
        for operation in model.operation_names:
            if operation.startswith(("List", "Describe", "Get", "BatchGet", "Head", "Lookup", "Search")):
                command = re.sub(r"(.)([A-Z][a-z]+)", r"\1-\2", operation)
                command = re.sub(r"([a-z0-9])([A-Z])", r"\1-\2", command).lower()
                commands.append(command)
        return commands

    def get_aws_services(self):
        output = self._get_aws_help()
        return self._help_entries(output, "AVAILABLE SERVICES") or self._botocore_services()

    def get_commands_for_service(self, service):
        output = self._get_aws_help(service)
        commands = self._help_entries(output, "AVAILABLE COMMANDS")
        commands = [c for c in commands if re.match(r'^(list|ls|describe|get|batch-get|head|lookup|search)', c)]
        commands = commands or self._botocore_commands(service)
        return [command for command in commands if not self._is_blocked_command(service, command)]

    def brute_force_permissions(self):
        self.found_permissions = []
        self.probe_stats = {"timeouts": 0, "os_errors": 0, "credential_errors": 0}
        self.historical_values_used = set()
        self.discovered_identifiers = {}
        self.discovery_stats = {"values": 0, "real_id_probes": 0, "real_id_confirmed": 0}
        if not getattr(self, "stop_event", None):
            self.stop_event = threading.Event()
        else:
            self.stop_event.clear()
        commands_to_run = []
        print(f"{Fore.GREEN}Starting permission enumeration...")

        if not self.aws_cli:
            print(
                f"{Fore.YELLOW}AWS CLI is not installed; skipping live read-only probes. "
                f"IAM policy parsing, simulation, and public-dataset inference remain available.{Fore.RESET}"
            )
            return []

        services = self.get_aws_services()

        if self.aws_services:
            filterred_services = [service for service in services if service.lower() in self.aws_services ]
            if not filterred_services:
                print(f"{Fore.RED}No services found to test. Please check your input because you probably misspelled the filtering. Exiting...{Fore.RESET}")
                return []
            else:
                print(f"{Fore.YELLOW}Filtered services to bf: {', '.join(filterred_services)}{Fore.RESET}")

        else:
            filterred_services = services

        with ThreadPoolExecutor(max_workers=self.num_threads) as executor:
            future_to_service = {
                executor.submit(self.get_commands_for_service, service): service 
                for service in filterred_services
            }
            pbar = tqdm(total=len(future_to_service), desc="Getting commands to test")
            for future in as_completed(future_to_service):
                pbar.update(1)
                service = future_to_service[future]
                try:
                    commands = future.result(timeout=30)
                    for command in commands:
                        commands_to_run.append((self.profile, self.region, service, command))
                except TimeoutError:
                    if self.debug:
                        print(f"[DEBUG] Timeout getting commands for {service}")
                except Exception as e:
                    if self.debug:
                        print(f"[DEBUG] Failed to get commands for {service}: {e}")
            pbar.close()

        if not commands_to_run:
            print(
                f"{Fore.RED}No AWS CLI commands were discovered. "
                "Unable to brute-force permissions. Run with --debug to check "
                f"the AWS CLI help output.{Fore.RESET}"
            )
            return []

        discovery_commands = [
            args for args in commands_to_run
            if self._has_no_required_input(args[2], args[3])
        ]
        discovery_set = set(discovery_commands)
        remaining_commands = [args for args in commands_to_run if args not in discovery_set]
        nested_discovery_commands = [
            args for args in remaining_commands if args[3].startswith("list-")
        ]
        nested_discovery_set = set(nested_discovery_commands)
        remaining_commands = [
            args for args in remaining_commands if args not in nested_discovery_set
        ]
        for phase, commands in (
            ("Discovering resource IDs", discovery_commands),
            ("Discovering nested resource IDs", nested_discovery_commands),
            ("Running ID-based probes", remaining_commands),
        ):
            with ThreadPoolExecutor(max_workers=self.num_threads) as executor:
                futures = [executor.submit(self.run_command, *args) for args in commands]
                pbar = tqdm(total=len(futures), desc=phase)
                for future in as_completed(futures):
                    pbar.update(1)
                pbar.close()

        print("\n[+] Permission enumeration completed.")
        if self.discovery_stats["real_id_probes"]:
            print(
                f"{Fore.BLUE}Response-derived IDs confirmed "
                f"{self.discovery_stats['real_id_confirmed']} read probe(s) "
                f"in {self.discovery_stats['real_id_probes']} bounded attempt(s)."
            )
        if self.historical_values_used:
            print(
                f"{Fore.BLUE}Used {len(self.historical_values_used)} validated resource "
                "identifier(s) recovered from CloudTrail instead of dummy IDs."
            )
        if self.probe_stats["timeouts"]:
            print(
                f"{Fore.YELLOW}{self.probe_stats['timeouts']} read-only probe(s) timed out; "
                "rerun with fewer --threads or --debug to diagnose them."
            )
        if self.probe_stats["os_errors"]:
            print(
                f"{Fore.YELLOW}{self.probe_stats['os_errors']} probe(s) could not start; "
                "rerun with --debug to see the local OS errors."
            )
        if self.probe_stats["credential_errors"]:
            print(
                f"{Fore.RED}Credentials became unusable during live probes; remaining probes "
                "were stopped. Refresh the selected profile/session and rerun."
            )
        return self.found_permissions
