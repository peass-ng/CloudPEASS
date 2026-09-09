import time
from types import SimpleNamespace

import jwt
import pytest

from CloudPEASS.http import ReadOnlyHttpClient
from CloudPEASS.cloudpeass import CloudPEASS
from azure.arm import AzureARMEnumerator, scope_kind
from azure.azcli import is_safe_read_command, parse_help_entries, required_options
from azure.entraid import EntraIDPEASS
from AzurePEAS import AzurePEASS
from sensitive_permissions.azure import sensitive_combinations, very_sensitive_combinations


class FakeResponse:
    def __init__(self, status_code=200, data=None, headers=None, text=""):
        self.status_code = status_code
        self._data = data if data is not None else {}
        self.headers = headers or {}
        self.text = text

    def json(self):
        return self._data


class FakeSession:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        return self.responses.pop(0)


def make_token(**claims):
    defaults = {
        "aud": "https://graph.microsoft.com/",
        "exp": int(time.time()) + 3600,
        "oid": "11111111-1111-1111-1111-111111111111",
    }
    defaults.update(claims)
    return jwt.encode(defaults, "test", algorithm="HS256")


def test_read_only_http_refuses_mutation_and_foreign_hosts():
    client = ReadOnlyHttpClient(allowed_hosts={"management.azure.com"})
    with pytest.raises(ValueError, match="refuses HTTP method POST"):
        client.request("POST", "https://management.azure.com/subscriptions")
    with pytest.raises(ValueError, match="unexpected host"):
        client.get("https://attacker.invalid/nextLink")


def test_read_only_http_retries_throttling_with_retry_after():
    session = FakeSession(
        [
            FakeResponse(429, headers={"Retry-After": "0"}),
            FakeResponse(200, {"value": []}),
        ]
    )
    sleeps = []
    client = ReadOnlyHttpClient(
        allowed_hosts={"management.azure.com"},
        session=session,
        sleep=sleeps.append,
    )
    response = client.get("https://management.azure.com/subscriptions")
    assert response.status_code == 200
    assert len(session.calls) == 2
    assert sleeps == [0.0]


def test_read_only_http_understands_azure_millisecond_retry_header():
    response = FakeResponse(429, headers={"x-ms-retry-after-ms": "250"})
    assert ReadOnlyHttpClient._retry_delay(response, 4) == 0.25


def test_arm_permission_blocks_preserve_wildcard_exclusions():
    allowed, excluded = AzureARMEnumerator.permissions_from_blocks(
        [
            {
                "actions": ["*"],
                "notActions": ["Microsoft.Authorization/*/Delete"],
                "dataActions": ["Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"],
                "notDataActions": ["Microsoft.Storage/*/write"],
            }
        ]
    )
    assert "*" in allowed
    assert "Microsoft.Authorization/*/Delete" in excluded
    assert "Microsoft.Storage/*/write" in excluded
    assert scope_kind("/providers/Microsoft.Management/managementGroups/root") == "management_group"


def test_sovereign_token_selects_matching_api_hosts():
    arm_token = make_token(aud="https://management.usgovcloudapi.net/")
    arm = AzureARMEnumerator(arm_token)
    assert arm.endpoint == "https://management.usgovcloudapi.net"
    assert arm.http.allowed_hosts == {"management.usgovcloudapi.net"}

    graph_token = make_token(aud="https://graph.microsoft.us/")
    entra = EntraIDPEASS(graph_token, 1)
    assert entra.graph == "https://graph.microsoft.us"
    assert entra.http.allowed_hosts == {"graph.microsoft.us"}

    app_id_audience = make_token(
        aud="00000003-0000-0000-c000-000000000000",
        iss="https://login.microsoftonline.us/tenant/v2.0",
    )
    assert EntraIDPEASS(app_id_audience, 1).graph == "https://graph.microsoft.us"


def test_azure_help_parser_handles_wrapping_crlf_and_annotations():
    help_text = (
        "Subgroups:\r\n"
        "    vm [Preview] : Manage VMs.\r\n"
        "    keyvault     : Manage vaults.\r\n"
        "\r\nCommands:\r\n"
        "    list          : List items.\r\n"
        "    delete        : Delete items.\r\n"
    ).splitlines(True)
    assert parse_help_entries(help_text, "Subgroups") == ["vm", "keyvault"]
    assert parse_help_entries(help_text, "Commands") == ["list", "delete"]


def test_azure_help_required_arguments_and_safety_allowlist():
    lines = [
        "Required Arguments\n",
        "    --resource-group -g [Required] : Group.\n",
        "    --name -n               : Name. Required: true.\n",
        "Global Arguments\n",
        "    --output -o : Output.\n",
    ]
    assert required_options(lines) == ["--resource-group", "--name"]
    assert is_safe_read_command(("vm", "list"))
    assert is_safe_read_command(("keyvault", "secret", "show"))
    assert not is_safe_read_command(("vm", "run-command", "show"))
    assert not is_safe_read_command(("vm", "delete"))
    assert not is_safe_read_command(("aks", "get-credentials", "run"))


def test_entra_token_claims_are_zero_permission_fallback():
    token = make_token(
        scp="User.Read Mail.Read",
        roles=["Directory.Read.All"],
        wids=[],
    )
    entra = EntraIDPEASS(token, 2)
    resources = entra.get_token_permissions()
    assert len(resources) == 1
    assert resources[0].permissions == ["Directory.Read.All", "Mail.Read", "User.Read"]
    assert not entra.is_application


def test_entra_application_detection_and_app_role_permissions_are_lists():
    token = make_token(idtyp="app", appid="22222222-2222-2222-2222-222222222222", roles=["User.Read.All"])
    entra = EntraIDPEASS(token, 1)
    entra._get_app_role_value = lambda resource_id, role_id: "User.Read.All"
    resources = entra._app_role_resources(
        [{"id": "assignment", "resourceId": "resource", "appRoleId": "role"}]
    )
    assert entra.is_application
    assert resources[0].permissions == ["User.Read.All"]


def test_entra_malformed_scalar_role_claim_is_one_permission():
    token = make_token(idtyp="app", roles="Directory.Read.All", wids="role-id")
    entra = EntraIDPEASS(token, 1)
    entra._role_resource = lambda item, assignment_type: item["roleDefinitionId"]
    resources = entra.get_token_permissions()
    assert resources[0].permissions == ["Directory.Read.All"]
    assert resources[1] == "role-id"


def test_conditional_arm_assignment_is_labeled_and_preserved():
    class FakeArm:
        def permissions_for_role(self, role_id):
            from azure.arm import PermissionResult

            return PermissionResult(["Microsoft.Storage/storageAccounts/read"], [], 200)

        def get_role_definition(self, role_id):
            return {"properties": {"roleName": "Conditional Reader"}}

    peas = AzurePEASS.__new__(AzurePEASS)
    peas.arm = FakeArm()
    resource = peas._role_assignment_resource(
        {
            "properties": {
                "roleDefinitionId": "/providers/Microsoft.Authorization/roleDefinitions/role",
                "scope": "/subscriptions/00000000-0000-0000-0000-000000000000",
                "condition": "@Resource[Type] StringEquals 'example'",
                "conditionVersion": "2.0",
            }
        }
    )
    assert resource.name == "Conditional Reader (conditional assignment)"
    assert resource.extra_fields["conditionVersion"] == "2.0"
    assert resource.permissions == ["Microsoft.Storage/storageAccounts/read"]


def test_teams_graph_fallback_runs_when_skype_chat_is_unavailable(monkeypatch):
    peas = AzurePEASS.__new__(AzurePEASS)
    peas.no_ask = True
    peas.graph_base = "https://graph.microsoft.com"
    seen = []

    monkeypatch.setattr(
        "AzurePEAS.requests.post",
        lambda *args, **kwargs: SimpleNamespace(status_code=403, json=lambda: {}),
    )

    def graph_get(url, headers, label):
        seen.append(url)
        return {"value": []}

    peas._graph_get_json = graph_get
    peas.enumerate_teams_conversations("skype-token", "graph-token")
    assert seen == ["https://graph.microsoft.com/v1.0/me/joinedTeams"]


def test_sharepoint_folder_walk_honors_max_depth():
    peas = AzurePEASS.__new__(AzurePEASS)
    peas.graph_base = "https://graph.microsoft.com"
    seen = []

    def graph_get(url, headers, label):
        seen.append(url)
        item_id = f"folder-{len(seen)}"
        return {"value": [{"id": item_id, "name": item_id, "folder": {}}]}

    peas._graph_get_json = graph_get
    peas.sharepoint_list_documents("site", "token", max_depth=2)
    assert len(seen) == 2


def test_graph_pagination_loop_is_bounded():
    peas = AzurePEASS.__new__(AzurePEASS)
    calls = []

    def graph_get(url, headers, label):
        calls.append(url)
        return {"value": [{"id": "one"}], "@odata.nextLink": url}

    peas._graph_get_json = graph_get
    assert peas.fetch_paginated_data("https://graph.microsoft.com/v1.0/items", "token") == [
        {"id": "one"}
    ]
    assert len(calls) == 1


def test_single_foci_app_id_is_not_iterated_as_characters():
    peas = AzurePEASS.__new__(AzurePEASS)
    seen = []

    def acquire(app_id, scopes):
        seen.append(app_id)
        return {"access_token": "token"}

    peas.get_accesstoken_from_foci = acquire
    assert peas.get_tokens_from_foci(["scope"], app_ids="client-id") == "token"
    assert seen == ["client-id"]


def test_azure_sensitive_permission_matching_is_case_insensitive():
    peas = CloudPEASS(
        [["Microsoft.Authorization/roleDefinitions/Write"]],
        [],
        "Azure",
        1,
    )
    result = peas.analyze_sensitive_combinations(
        {"microsoft.authorization/roledefinitions/write"}
    )
    assert result["very_sensitive_perms"] == {
        "microsoft.authorization/roledefinitions/write"
    }


def test_azure_final_risk_precedence_keeps_all_four_tiers_distinct():
    peas = CloudPEASS(
        very_sensitive_combinations,
        sensitive_combinations,
        "Azure",
        1,
    )
    result = peas.analyze_group(
        {
            "*",
            "*/read",
            "Microsoft.Network/virtualNetworks/read",
            "Microsoft.Network/virtualNetworks/write",
            "Microsoft.Search/searchServices/listQueryKeys/action",
        },
        [],
    )["permissions_cat"]

    assert "*" in result["critical"]
    assert "Microsoft.Search/searchServices/listQueryKeys/action" in result["high"]
    assert "*/read" in result["medium"]
    assert "Microsoft.Network/virtualNetworks/write" in result["medium"]
    assert "Microsoft.Network/virtualNetworks/read" in result["low"]


def test_every_configured_azure_attack_combination_reaches_its_declared_tier():
    peas = CloudPEASS(
        very_sensitive_combinations,
        sensitive_combinations,
        "Azure",
        1,
    )

    for expected, combinations in (
        ("critical", very_sensitive_combinations),
        ("high", sensitive_combinations),
    ):
        for combination in combinations:
            categories = peas.analyze_group(set(combination), [])["permissions_cat"]
            for permission in combination:
                assert permission in categories[expected], (expected, combination)


def test_compute_application_access_requires_workspace_read_combination():
    combination = [
        "Microsoft.MachineLearningServices/workspaces/read",
        "Microsoft.MachineLearningServices/workspaces/computes/applicationaccess/action",
    ]
    assert combination in sensitive_combinations

    peas = CloudPEASS(
        very_sensitive_combinations,
        sensitive_combinations,
        "Azure",
        1,
    )
    action_only = peas.analyze_group({combination[1]}, [])["permissions_cat"]
    assert combination[1] in action_only["medium"]
    assert combination[1] not in action_only["high"]

    complete = peas.analyze_group(set(combination), [])["permissions_cat"]
    assert set(combination).issubset(complete["high"])


def test_search_elevated_read_requires_document_read_combination():
    elevated = (
        "Microsoft.Search/searchServices/indexes/contentSecurity/"
        "elevatedOperations/read"
    )
    documents = "Microsoft.Search/searchServices/indexes/documents/read"
    combination = [documents, elevated]
    assert combination in sensitive_combinations

    peas = CloudPEASS(
        very_sensitive_combinations,
        sensitive_combinations,
        "Azure",
        1,
    )
    elevated_only = peas.analyze_group({elevated}, [])["permissions_cat"]
    assert elevated in elevated_only["medium"]
    assert elevated not in elevated_only["high"]

    documents_only = peas.analyze_group({documents}, [])["permissions_cat"]
    assert documents in documents_only["low"]
    assert documents not in documents_only["high"]

    pair = peas.analyze_group(set(combination), [])["permissions_cat"]
    assert set(pair["high"]) == set(combination)


def test_search_skillset_write_is_a_validated_high_singleton():
    permission = "Microsoft.Search/searchServices/skillsets/write"
    assert [permission] in sensitive_combinations

    peas = CloudPEASS(
        very_sensitive_combinations,
        sensitive_combinations,
        "Azure",
        1,
    )
    categories = peas.analyze_group({permission}, [])["permissions_cat"]
    assert categories["high"] == [permission]
    assert not categories["critical"]


def test_environment_secret_expansion_requires_all_three_permissions():
    combination = [
        "Microsoft.MachineLearningServices/workspaces/environments/read",
        "Microsoft.MachineLearningServices/workspaces/metadata/secrets/read",
        "Microsoft.MachineLearningServices/workspaces/environments/readSecrets/action",
    ]
    assert combination in sensitive_combinations

    peas = CloudPEASS(
        very_sensitive_combinations,
        sensitive_combinations,
        "Azure",
        1,
    )
    for omitted in combination:
        incomplete = set(combination) - {omitted}
        categories = peas.analyze_group(incomplete, [])["permissions_cat"]
        assert not (incomplete & set(categories["high"]))

    complete = peas.analyze_group(set(combination), [])["permissions_cat"]
    assert set(combination).issubset(complete["high"])


def test_foundry_connection_secret_requires_read_and_list_secrets():
    combination = [
        "Microsoft.CognitiveServices/accounts/AIServices/connections/read",
        "Microsoft.CognitiveServices/accounts/AIServices/connections/listSecrets/action",
    ]
    assert combination in sensitive_combinations

    peas = CloudPEASS(
        very_sensitive_combinations,
        sensitive_combinations,
        "Azure",
        1,
    )
    for permission in combination:
        incomplete = peas.analyze_group({permission}, [])["permissions_cat"]
        assert permission not in incomplete["high"]
        assert permission not in incomplete["critical"]

    complete = peas.analyze_group(set(combination), [])["permissions_cat"]
    assert set(combination).issubset(complete["high"])


def test_live_validated_ai_response_reads_are_high():
    permissions = (
        "Microsoft.CognitiveServices/accounts/OpenAI/responses/read",
        "Microsoft.CognitiveServices/accounts/AIServices/agents/read",
        "Microsoft.CognitiveServices/accounts/SpeechServices/speechrest/transcriptions/files/read",
    )
    peas = CloudPEASS(
        very_sensitive_combinations,
        sensitive_combinations,
        "Azure",
        1,
    )

    for permission in permissions:
        assert [permission] in sensitive_combinations
        categories = peas.analyze_group({permission}, [])["permissions_cat"]
        assert permission in categories["high"]
        assert permission not in categories["critical"]


def test_live_validated_inference_account_keys_are_high():
    permission = "Microsoft.InferenceService/inferenceAccounts/listKeys/action"
    assert [permission] in sensitive_combinations

    peas = CloudPEASS(
        very_sensitive_combinations,
        sensitive_combinations,
        "Azure",
        1,
    )
    categories = peas.analyze_group({permission}, [])["permissions_cat"]
    assert permission in categories["high"]
    assert permission not in categories["critical"]


def test_live_validated_grafana_admin_token_minting_is_high():
    permission = "Microsoft.Dashboard/grafana/ActAsGrafanaAdmin/action"
    assert [permission] in sensitive_combinations

    peas = CloudPEASS(
        very_sensitive_combinations,
        sensitive_combinations,
        "Azure",
        1,
    )
    categories = peas.analyze_group({permission}, [])["permissions_cat"]
    assert permission in categories["high"]
    assert permission not in categories["critical"]


def test_live_validated_video_indexer_tokens_are_high_not_critical():
    permissions = (
        "Microsoft.VideoIndexer/accounts/generateAccessToken/action",
        "Microsoft.VideoIndexer/accounts/generateRestrictedViewerAccessToken/action",
    )
    peas = CloudPEASS(
        very_sensitive_combinations,
        sensitive_combinations,
        "Azure",
        1,
    )

    for permission in permissions:
        assert [permission] in sensitive_combinations
        categories = peas.analyze_group({permission}, [])["permissions_cat"]
        assert permission in categories["high"]
        assert permission not in categories["critical"]


def test_speech_job_read_only_becomes_high_with_file_read():
    job_read = (
        "Microsoft.CognitiveServices/accounts/SpeechServices/"
        "speechrest/transcriptions/read"
    )
    file_read = (
        "Microsoft.CognitiveServices/accounts/SpeechServices/"
        "speechrest/transcriptions/files/read"
    )
    combination = [job_read, file_read]
    assert combination in sensitive_combinations

    peas = CloudPEASS(
        very_sensitive_combinations,
        sensitive_combinations,
        "Azure",
        1,
    )
    job_only = peas.analyze_group({job_read}, [])["permissions_cat"]
    assert job_read not in job_only["high"]
    assert job_read not in job_only["critical"]

    complete = peas.analyze_group(set(combination), [])["permissions_cat"]
    assert set(combination).issubset(complete["high"])


def test_azure_multi_permission_attacks_are_not_critical_when_incomplete():
    peas = CloudPEASS(
        very_sensitive_combinations,
        sensitive_combinations,
        "Azure",
        1,
    )
    incomplete = {
        "Microsoft.KeyVault/vaults/deploy/action",
        "Microsoft.Automation/automationAccounts/runbooks/draft/write",
        "Microsoft.App/containerApps/getAuthToken/action",
        "Policy.ReadWrite.ConditionalAccess",
    }

    categories = peas.analyze_group(incomplete, [])["permissions_cat"]

    assert not categories["critical"]


def test_data_factory_identity_theft_requires_pipeline_write_and_run():
    peas = CloudPEASS(
        very_sensitive_combinations,
        sensitive_combinations,
        "Azure",
        1,
    )
    pipeline_write = "Microsoft.DataFactory/factories/pipelines/write"
    pipeline_run = "Microsoft.DataFactory/factories/pipelines/createRun/action"

    complete = peas.analyze_group({pipeline_write, pipeline_run}, [])["permissions_cat"]
    write_only = peas.analyze_group({pipeline_write}, [])["permissions_cat"]
    run_only = peas.analyze_group({pipeline_run}, [])["permissions_cat"]

    assert {pipeline_write, pipeline_run} <= set(complete["critical"])
    assert pipeline_write not in write_only["critical"]
    assert pipeline_run not in run_only["critical"]
    assert pipeline_run in run_only["high"]


def test_acr_schedule_run_does_not_require_source_upload_or_imply_identity_reuse():
    peas = CloudPEASS(
        very_sensitive_combinations,
        sensitive_combinations,
        "Azure",
        1,
    )
    source_upload = "Microsoft.ContainerRegistry/registries/listBuildSourceUploadUrl/action"
    schedule_run = "Microsoft.ContainerRegistry/registries/scheduleRun/action"

    categories = peas.analyze_group({source_upload, schedule_run}, [])["permissions_cat"]

    assert not categories["critical"]
    assert schedule_run in categories["high"]
