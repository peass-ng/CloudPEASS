"""Distinguish IAM grants from condition keys, SDK namespaces and API names."""
import pytest
from CloudPEASS.permission_risk_classifier import classify_all, classify_permission


@pytest.mark.parametrize('identifier', [
    'connect:MonitorCapabilities', 'iam:PassedToService', 'redshift:AllowWrites',
    'dynamodb:TransactGetItems', 'dynamodb:TransactWriteItems',
    'sso-admin:CreateTrustedTokenIssuer', 'sesv2:PutEmailIdentityPolicy',
    'budgets:DeleteBudget', 'budgets:DeleteNotification',
])
def test_non_permission_tokens_cannot_be_reported_as_sensitive_grants(identifier):
    assert classify_permission('aws', identifier, unknown_default='high') == 'low'
    result = classify_all('aws', [identifier, '*'])
    assert identifier in result['low']


@pytest.mark.parametrize('provider,permission', [
    ('aws', 'glue:GetConnections'), ('aws', 'glue:GetWorkflow'),
    ('aws', 'workmailmessageflow:GetRawMessageContent'),
    ('aws', 'directconnect:DescribeRouterConfiguration'),
    ('aws', 'redshift-data:GetStatementResult'),
    ('gcp', 'aiplatform.ragCorpora.query'), ('gcp', 'ces.conversations.get'),
    ('gcp', 'clouddeploy.releases.list'), ('gcp', 'appengine.versions.getFileContents'),
    ('azure', 'Microsoft.Web/sourcecontrols/read'),
    ('azure', 'Microsoft.OperationalInsights/workspaces/query/read'),
    ('azure', 'Microsoft.Automation/automationAccounts/runbooks/content/read'),
])
def test_content_reads_are_not_mistaken_for_discovery(provider, permission):
    assert classify_permission(provider, permission, unknown_default='medium') == 'high'


def test_real_budget_deletion_authorization_stays_medium():
    assert classify_permission('aws', 'budgets:ModifyBudget') == 'medium'


def test_existing_runtime_command_execution_is_critical():
    assert classify_permission('aws', 'bedrock-agentcore:InvokeAgentRuntimeCommand') == 'critical'


def test_authorization_write_wildcard_includes_self_assignment():
    assert classify_permission('azure', 'Microsoft.Authorization/*/write') == 'critical'
    assert classify_permission('azure', 'Microsoft.Authorization/policyDefinitions/write') != 'critical'


@pytest.mark.parametrize('identifier', [
    'container.nodePools.create', 'container.nodePools.update',
    'alloydb.clusters.restore', 'resourcemanager.projects.createLien',
    'resourcemanager.projects.deleteLien', 'netapp.backups.createCrossProjectBackup',
])
def test_gcp_operation_aliases_do_not_grant_permissions(identifier):
    assert classify_permission('gcp', identifier, unknown_default='high') == 'low'
    assert identifier in classify_all('gcp', [identifier, '*'])['low']


@pytest.mark.parametrize('provider,permission', [
    ('aws', 's3tables:GetTableData'),
    ('aws', 'invoicing:GetProcurementPortalPreference'),
    ('gcp', 'logging.logEntries.list'), ('gcp', 'logging.privateLogEntries.list'),
    ('gcp', 'appengine.memcache.get'), ('gcp', 'cloudsupport.techCases.get'),
    ('gcp', 'contactcenterinsights.conversations.list'),
    ('gcp', 'contactcenterinsights.datasetConversations.list'),
    ('azure', 'Microsoft.Search/searchServices/indexes/documents/read'),
    ('azure', 'Microsoft.ContainerRegistry/registries/repositories/content/read'),
    ('azure', 'Microsoft.Automation/automationAccounts/jobs/output/read'),
])
def test_protected_content_reads_are_high(provider, permission):
    assert classify_permission(provider, permission) == 'high'


@pytest.mark.parametrize('permission,severity', [
    ('cloudfunctions.functions.generateUploadUrl', 'medium'),
    ('cloudkms.cryptoKeyVersions.useToEncrypt', 'medium'),
    ('container.roleBindings.create', 'medium'),
    ('container.clusterRoleBindings.update', 'medium'),
    ('serviceusage.services.use', 'low'), ('mcp.tools.call', 'low'),
    ('resourcemanager.projects.updateLiens', 'medium'),
])
def test_helpers_retain_api_authorization_boundaries(permission, severity):
    assert classify_permission('gcp', permission) == severity
    assert permission in classify_all('gcp', [permission, '*'])[severity]


@pytest.mark.parametrize('provider,identifier', [
    ('aws', 'sso:GetRoleCredentials'),
    ('gcp', 'v1.IAM.SignBlob'), ('gcp', 'v2.Jobs.SetIamPolicy'),
    ('gcp', 'projects.serviceAccounts.signJwt'),
    ('gcp', 'datastore.databases.setIamPolicy'),
    ('gcp', 'file.instances.setIamPolicy'),
    ('gcp', 'managedkafka.clusters.setIamPolicy'),
    ('gcp', 'networkconnectivity.hubs.use'),
    ('gcp', 'iam.serviceaccounts.actAs'),
    ('azure', 'microsoft.com/en-us/rest/api/appservice/web-apps/update'),
])
def test_api_names_negative_examples_and_urls_are_not_grants(provider, identifier):
    assert classify_permission(provider, identifier, unknown_default='high') == 'low'
    assert identifier in classify_all(provider, [identifier, '*'])['low']


@pytest.mark.parametrize('permission', [
    'microsoft.directory/bitlockerKeys/key/read',
    'microsoft.directory/deviceLocalCredentials/password/read',
    'microsoft.directory/groups/members/update',
    'microsoft.directory/groups/owners/update',
])
def test_entra_stored_secrets_and_conditional_membership_are_high(permission):
    assert classify_permission('azure', permission) == 'high'


@pytest.mark.parametrize('permission', [
    'wafv2:DisassociateWebACL', 'appsync:DisassociateWebACL',
    'network-firewall:DeleteFirewall',
])
def test_security_filter_disruption_stays_medium(permission):
    assert classify_permission('aws', permission) == 'medium'
    assert permission in classify_all('aws', [permission, '*'])['medium']
