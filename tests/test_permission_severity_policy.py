import pytest

from CloudPEASS.permission_risk_classifier import classify_all, classify_permission


@pytest.mark.parametrize("provider,permission,expected", [
    ("aws", "iam:PassRole", "critical"),
    ("aws", "eks:UpdateAccessEntry", "critical"),
    ("aws", "lambda:CreateMicrovmShellAuthToken", "critical"),
    ("aws", "secretsmanager:GetSecretValue", "high"),
    ("aws", "acm:ExportCertificate", "high"),
    ("aws", "shield:DisableApplicationLayerAutomaticResponse", "medium"),
    ("aws", "elasticmapreduce:OpenEditorInConsole", "medium"),
    ("gcp", "iam.serviceAccounts.getAccessToken", "critical"),
    ("gcp", "iam.serviceAccounts.actAs", "critical"),
    ("gcp", "osconfig.osPolicyAssignments.update", "critical"),
    ("gcp", "secretmanager.versions.access", "high"),
    ("gcp", "secretmanager.versions.add", "high"),
    ("gcp", "secretmanager.versions.destroy", "medium"),
    ("gcp", "developerconnect.users.fetchAccessToken", "medium"),
    ("azure", "Microsoft.DocumentDB/mongoClusters/write", "critical"),
    ("azure", "Microsoft.ContainerService/managedClusters/runCommand/action", "critical"),
    ("azure", "Microsoft.KeyVault/vaults/secrets/getSecret/action", "high"),
    ("azure", "Microsoft.Storage/storageAccounts/managementPolicies/write", "medium"),
    ("azure", "Group.Read.All", "low"),
    ("azure", "Microsoft.Resources/deployments/read", "high"),
    ("azure", "Microsoft.Resources/subscriptions/resourcegroups/deployments/read", "high"),

])
def test_documented_severity_policy(provider, permission, expected):
    assert classify_permission(provider, permission, unknown_default="medium") == expected


def test_disruption_is_not_promoted_by_a_complete_legacy_chain():
    permissions = [
        "Microsoft.StreamAnalytics/streamingjobs/Stop/action",
        "Microsoft.StreamAnalytics/streamingjobs/outputs/Write",
        "Microsoft.StreamAnalytics/streamingjobs/Start/action",
    ]
    result = classify_all("azure", permissions, "medium")
    assert permissions[0] in result["medium"]
    assert permissions[1] in result["high"]


def test_passrole_prerequisite_requires_a_complete_chain():
    permission = "scheduler:CreateSchedule"
    assert classify_permission("aws", permission, unknown_default="medium") == "medium"
    complete = [permission, "iam:PassRole"]
    assert set(classify_all("aws", complete, "medium")["critical"]) == set(complete)
