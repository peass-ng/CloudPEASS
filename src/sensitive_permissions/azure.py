

very_sensitive_combinations = [
    # Microsoft Graph application/delegated permissions exposed in token claims.
    ["AppRoleAssignment.ReadWrite.All"],
    ["Application.ReadWrite.All"],
    ["DelegatedPermissionGrant.ReadWrite.All"],
    ["RoleManagement.ReadWrite.Directory"],
    ["Policy.Read.All", "Policy.ReadWrite.ConditionalAccess"],
    ["Application.Read.All", "Policy.ReadWrite.ConditionalAccess"],
    ["PrivilegedAccess.ReadWrite.AzureAD"],
    ["PrivilegedAccess.ReadWrite.AzureResources"],
    ["UserAuthenticationMethod.ReadWrite.All"],
    ["microsoft.directory/applications/credentials/update"],
    ["microsoft.directory/applications.myOrganization/credentials/update"],
    ["microsoft.directory/applications/owners/update"],
    ["microsoft.directory/servicePrincipals/credentials/update"],
    ["microsoft.directory/servicePrincipals/synchronizationCredentials/manage"],
    ["microsoft.directory/servicePrincipals/owners/update"],
    ["microsoft.directory/servicePrincipals/getPasswordSingleSignOnCredentials", "microsoft.directory/servicePrincipals/managePasswordSingleSignOnCredentials"],
    ["microsoft.directory/groups/owners/update"],
    ["microsoft.directory/groups/members/update"],
    ["microsoft.directory/users/password/update"],
    ["microsoft.directory/deviceLocalCredentials/password/read"],
    ["microsoft.directory/bitlockerKeys/key/read"],


    ["Microsoft.Authorization/roleAssignments/write"],
    ["Microsoft.Authorization/elevateAccess/action"],

    ["Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials/write"],
    
    
    ["Microsoft.Web/sites/publish/Action"],
    ["Microsoft.Web/sites/slots/publish/Action"],
    # Live validated independently on production and a deployment slot: the
    # exact action replaced the main SiteContainer image/startup arguments and
    # the corresponding public endpoint served the injected canary.
    ["Microsoft.Web/sites/sitecontainers/write"],
    ["Microsoft.Web/sites/slots/sitecontainers/write"],
    # Live validated independently on production and a deployment slot: each
    # exact action redirected deployment to an attacker-controlled public Git
    # repository and the corresponding endpoint served the injected canary.
    ["Microsoft.Web/sites/sourcecontrols/write"],
    ["Microsoft.Web/sites/slots/sourcecontrols/write"],

    ["Microsoft.Automation/automationAccounts/runbooks/draft/write", "Microsoft.Automation/automationAccounts/runbooks/draft/content/write", "Microsoft.Automation/automationAccounts/runbooks/draft/testJob/write"],
    ["Microsoft.Automation/automationAccounts/runbooks/draft/write", "Microsoft.Automation/automationAccounts/runbooks/draft/content/write", "Microsoft.Automation/automationAccounts/runbooks/publish/action", "Microsoft.Automation/automationAccounts/jobs/write"],
    ["Microsoft.Automation/automationAccounts/sourceControls/write", "Microsoft.Automation/automationAccounts/jobs/write"],

    # Live validated: pipeline replacement plus execution can make Data Factory
    # send its managed-identity bearer token to an attacker-controlled WebActivity.
    ["Microsoft.DataFactory/factories/pipelines/write", "Microsoft.DataFactory/factories/pipelines/createRun/action"],

    # Either exact singleton can replace the Synapse workspace Entra admin.
    # Live validation then authenticated to the dedicated SQL endpoint as
    # sysadmin and created a persistent SQL login that survived admin removal.
    ["Microsoft.Synapse/workspaces/administrators/write"],
    ["Microsoft.Synapse/workspaces/sqlAdministrators/write"],

    # Live exact-role validation replaced an OnSuccess deployment script and
    # exfiltrated a Key Vault secret as its pre-attached UAMI. The write action
    # alone was denied even when the identity was already attached. Retained
    # support containers additionally require containerGroups/delete.
    [
        "Microsoft.Resources/deploymentScripts/write",
        "Microsoft.ManagedIdentity/userAssignedIdentities/assign/action",
        "Microsoft.ContainerInstance/containerGroups/read",
        "Microsoft.ContainerInstance/containerGroups/write",
        "Microsoft.Storage/storageAccounts/read",
        "Microsoft.Storage/storageAccounts/write",
        "Microsoft.Storage/storageAccounts/listKeys/action",
    ],

    ["Microsoft.ContainerRegistry/registries/listCredentials/action"],
    ["Microsoft.ContainerRegistry/registries/regenerateCredential/action"],
    ["Microsoft.ContainerRegistry/registries/generateCredentials/action"],
    ["Microsoft.ContainerInstance/containerGroups/containers/exec/action"],
    ["Microsoft.Web/sites/functions/masterkey/read"],
    ["Microsoft.Web/sites/functions/token/read"],
    ["Microsoft.Web/sites/slots/publishxml/action"],
    ["Microsoft.Web/sites/slots/config/list/action"],
    ["Microsoft.App/jobs/start/action"],
    ["Microsoft.App/jobs/listSecrets/action"],
    ["Microsoft.App/managedEnvironments/daprComponents/listSecrets/action"],
    ["Microsoft.App/sessionPools/fetchMCPServerCredentials/action"],
    ["Microsoft.Devices/provisioningServices/listkeys/action"],
    ["Microsoft.Devices/provisioningServices/keys/listkeys/action"],
    ["Microsoft.App/containerApps/getAuthToken/action", "Microsoft.App/containerApps/exec/action"],
    ["Microsoft.App/containerApps/getAuthToken/action", "Microsoft.App/containerApps/debug/action"],


    ["Microsoft.DocumentDB/databaseAccounts/sqlRoleDefinitions/write", "Microsoft.DocumentDB/databaseAccounts/sqlRoleAssignments/write"],
    ["Microsoft.DocumentDB/databaseAccounts/mongodbRoleDefinitions/write", "Microsoft.DocumentDB/databaseAccounts/mongodbUserDefinitions/write"],

    ["Microsoft.DocumentDB/databaseAccounts/listKeys/action"],
    ["Microsoft.DocumentDB/databaseAccounts/listConnectionStrings/action"],
    ["Microsoft.DocumentDB/mongoClusters/write"],

    ["Microsoft.Web/sites/host/listkeys/action"],
    ["Microsoft.Web/sites/slots/host/listkeys/action"],
    ["Microsoft.Web/sites/config/list/action"],
    ["Microsoft.Web/sites/config/list/action", "Microsoft.Web/sites/config/write"],
    ["Microsoft.Web/sites/publishxml/action"],
    ["Microsoft.Web/sites/config/write", "Microsoft.Web/sites/config/list/action"],

    ["Microsoft.Logic/workflows/write"],
    ["Microsoft.Web/sites/basicPublishingCredentialsPolicies/read", "Microsoft.Web/sites/write", "Microsoft.Web/sites/config/list/action"],

    ["Microsoft.DBforMySQL/flexibleServers/write"],
    ["Microsoft.DBforMySQL/flexibleServers/write", "Microsoft.DBforMySQL/flexibleServers/backups/read"],
    ["Microsoft.DBforMySQL/flexibleServers/administrators/write"],

    ["Microsoft.DBforPostgreSQL/flexibleServers/write"],
    ["Microsoft.DBforPostgreSQL/flexibleServers/write", "Microsoft.DBforPostgreSQL/flexibleServers/backups/read"],
    ["Microsoft.DBforPostgreSQL/flexibleServers/administrators/write"],

    ["Microsoft.ServiceBus/namespaces/authorizationrules/listKeys/action"],
    ["Microsoft.ServiceBus/namespaces/authorizationrules/regenerateKeys/action"],
    ["Microsoft.ServiceBus/namespaces/*/authorizationRules/ListKeys/action"],
    ["Microsoft.ServiceBus/namespaces/*/authorizationRules/regenerateKeys/action"],
    ["Microsoft.ServiceBus/namespaces/queues/authorizationRules/listKeys/action"],
    ["Microsoft.ServiceBus/namespaces/queues/authorizationRules/regenerateKeys/action"],
    ["Microsoft.ServiceBus/namespaces/topics/authorizationRules/listKeys/action"],
    ["Microsoft.ServiceBus/namespaces/topics/authorizationRules/regenerateKeys/action"],

    ["Microsoft.Web/staticSites/listSecrets/action"],

    ["Microsoft.MachineLearningServices/workspaces/listKeys/action"],
    ["Microsoft.MachineLearningServices/workspaces/listStorageAccountKeys/action"],
    ["Microsoft.MachineLearningServices/workspaces/connections/listsecrets/action"],
    ["Microsoft.MachineLearningServices/workspaces/datastores/listsecrets/action"],
    ["Microsoft.CognitiveServices/accounts/connections/listsecrets/action"],
    ["Microsoft.CognitiveServices/accounts/projects/connections/listsecrets/action"],
    ["Microsoft.ApiManagement/service/namedValues/listValue/action"],
    ["Microsoft.ApiManagement/service/backends/read"],
    ["Microsoft.ApiManagement/service/authorizationServers/listSecrets/action"],
    ["Microsoft.ApiManagement/service/openidConnectProviders/listSecrets/action"],
    ["Microsoft.ApiManagement/service/identityProviders/listSecrets/action"],
    ["Microsoft.ApiManagement/service/tenant/listSecrets/action"],
    ["Microsoft.ApiManagement/service/gateways/generateToken/action"],

    ["Microsoft.Storage/storageAccounts/listkeys/action"],
    ["Microsoft.Storage/storageAccounts/regenerateKey/action"],
    ["Microsoft.Storage/storageAccounts/fileServices/takeOwnership/action"],
    ["Microsoft.Storage/storageAccounts/fileServices/fileshares/files/modifypermissions/action"],
    ["Microsoft.Storage/storageAccounts/fileServices/fileshares/files/actassuperuser/action"],
    ["Microsoft.Storage/storageAccounts/localusers/write"],
    ["Microsoft.Storage/storageAccounts/localusers/regeneratePassword/action"],

    ["Microsoft.ApiManagement/service/users/token/action"],
    ["Microsoft.AppConfiguration/configurationStores/ListKeys/action"],
    ["Microsoft.AppConfiguration/configurationStores/RegenerateKey/action"],
    ["Microsoft.Automation/automationAccounts/listKeys/action"],
    ["Microsoft.Batch/batchAccounts/listkeys/action"],
    ["Microsoft.Batch/batchAccounts/regeneratekeys/action"],
    ["Microsoft.Cache/redis/listKeys/action"],
    ["Microsoft.Cache/redisEnterprise/databases/listKeys/action"],
    ["Microsoft.Cache/redisEnterprise/databases/regenerateKey/action"],
    ["Microsoft.CognitiveServices/accounts/listKeys/action"],
    ["Microsoft.CognitiveServices/accounts/regenerateKey/action"],
    ["Microsoft.DataFactory/datafactories/gateways/listauthkeys/action"],
    ["Microsoft.DataFactory/factories/integrationruntimes/listauthkeys/action"],
    ["Microsoft.EventHub/namespaces/authorizationRules/listkeys/action"],
    ["Microsoft.EventHub/namespaces/authorizationRules/regenerateKeys/action"],
    ["Microsoft.EventHub/namespaces/eventhubs/authorizationRules/listkeys/action"],
    ["Microsoft.EventHub/namespaces/eventhubs/authorizationRules/regenerateKeys/action"],
    ["Microsoft.EventHub/namespaces/disasterRecoveryConfigs/authorizationRules/listkeys/action"],
    ["Microsoft.ServiceBus/namespaces/disasterRecoveryConfigs/authorizationRules/listkeys/action"],
    ["Microsoft.FluidRelay/fluidRelayServers/listKeys/action"],
    ["Microsoft.FluidRelay/fluidRelayServers/regenerateKey/action"],
    ["Microsoft.Quantum/Workspaces/listKeys/action"],
    ["Microsoft.Quantum/Workspaces/regenerateKey/action"],
    ["Microsoft.Devices/IotHubs/listkeys/action"],
    ["Microsoft.Devices/IotHubs/iotHubKeys/listkeys/action"],
    ["Microsoft.KeyVault/vaults/accessPolicies/write"],
    ["Microsoft.KeyVault/vaults/deploy/action", "Microsoft.Resources/deployments/write"],
    ["Microsoft.Search/searchServices/listAdminKeys/action"],
    ["Microsoft.Search/searchServices/regenerateAdminKey/action"],
    ["Microsoft.Storage/storageAccounts/listAccountSas/action"],
    ["Microsoft.Storage/storageAccounts/listServiceSas/action"],
    ["Microsoft.NotificationHubs/Namespaces/authorizationRules/listkeys/action"],
    ["Microsoft.NotificationHubs/Namespaces/authorizationRules/regenerateKeys/action"],
    ["Microsoft.NotificationHubs/Namespaces/NotificationHubs/authorizationRules/listkeys/action"],
    ["Microsoft.NotificationHubs/Namespaces/NotificationHubs/authorizationRules/regenerateKeys/action"],
    ["Microsoft.App/containerApps/listSecrets/action"],

    ["Microsoft.ContainerService/managedClusters/listClusterAdminCredential/action"],
    ["Microsoft.HybridContainerService/provisionedClusters/listClusterAdminCredential/action"],

    ["Microsoft.Compute/virtualMachines/runCommands/write"],
    ["Microsoft.Compute/virtualMachineScaleSets/virtualMachines/runCommands/write"],
    ["Microsoft.HybridCompute/machines/runcommands/write"],

    ["Microsoft.Sql/servers/write"],
    ["Microsoft.Sql/servers/administrators/write"],
    ["Microsoft.Sql/servers/azureADOnlyAuthentications/write"],
    ["Microsoft.Sql/servers/databases/dataMaskingPolicies/write"],
    
    ["Microsoft.DesktopVirtualization/hostPools/retrieveRegistrationToken/action"],

    ["Microsoft.Compute/virtualMachines/extensions/write"],
    ["Microsoft.Compute/virtualMachines/runCommand/action"],
    ["Microsoft.Compute/virtualMachines/loginAsAdmin/action"],

    ["Microsoft.KeyVault/vaults/secrets/getSecret/action"],

]

sensitive_combinations = [
    ["AuditLog.Read.All"],
    ["Directory.Read.All"],
    ["Directory.ReadWrite.All"],
    ["Group.ReadWrite.All"],
    ["Mail.Read"],
    ["Mail.ReadWrite"],
    ["RoleManagement.Read.Directory"],
    ["User.Read.All"],
    ["User.ReadWrite.All"],
    ["microsoft.directory/applications/allProperties/update"],
    ["microsoft.directory/groups/dynamicMembershipRule/update"],
    ["microsoft.directory/devices/registeredOwners/update"],
    ["microsoft.directory/devices/registeredUsers/update"],
    ["Microsoft.Authorization/roleDefinitions/Write"],
    ["Microsoft.ManagedIdentity/userAssignedIdentities/assign/action"],
    ["Microsoft.Automation/automationAccounts/schedules/write", "Microsoft.Automation/automationAccounts/jobSchedules/write"],
    ["Microsoft.Automation/automationAccounts/sourceControls/write"],
    # Live validated with exact roles. Job streams exposed output, error,
    # warning, and verbose canaries; variable reads exposed an unencrypted
    # secret-like value while correctly keeping the encrypted value hidden.
    ["Microsoft.Automation/automationAccounts/jobs/streams/read"],
    ["Microsoft.Automation/automationAccounts/variables/read"],
    # Live validated against a published canary runbook. Azure checks the
    # undocumented webhooks/action operation when minting the one-time URI,
    # but rejects that exact operation in custom roles. The supported
    # webhooks/* wildcard plus runbooks/read generated the URI, created the
    # webhook, and let an anonymous POST execute the selected runbook.
    [
        "Microsoft.Automation/automationAccounts/webhooks/*",
        "Microsoft.Automation/automationAccounts/runbooks/read",
    ],
    # Live validated with an exact role: the action minted an AML endpoint
    # bearer token that invoked a deployed scoring service after an
    # unauthenticated request was rejected.
    ["Microsoft.MachineLearningServices/workspaces/onlineEndpoints/token/action"],
    # Live validated with an exact role: serverless endpoint keys were
    # returned without resource read and authenticated a model-inference call.
    ["Microsoft.MachineLearningServices/workspaces/serverlessEndpoints/listKeys/action"],
    # Live validated with an exact role after key authentication was enabled:
    # both account keys were returned without resource read, and one key
    # authenticated a protected Semantic Reranker request.
    ["Microsoft.InferenceService/inferenceAccounts/listKeys/action"],
    # Live validated with the exact singleton DataAction and no ARM read:
    # after service accounts were enabled on the selected workspace, the
    # caller minted a Grafana Admin token.  The token remained usable after
    # the issuer's Azure role assignment and application were removed.
    ["Microsoft.Dashboard/grafana/ActAsGrafanaAdmin/action"],
    # Live validated with separate exact roles. The ordinary action minted an
    # account Contributor token that listed, downloaded, and deleted private
    # media. The restricted-viewer action exposed the private media list and
    # processed insights while correctly denying the original source file.
    ["Microsoft.VideoIndexer/accounts/generateAccessToken/action"],
    ["Microsoft.VideoIndexer/accounts/generateRestrictedViewerAccessToken/action"],
    # Live validated with the exact singleton DataAction and no ARM read. The
    # response was the newly active API_JWT_SECRET, and an HS256 JWT signed
    # with it authenticated to the bot's management-scenarios endpoint.
    ["Microsoft.HealthBot/healthBots/Admin/Secrets/GenerateApiKey/Action"],
    # Live validated on a compute instance explicitly assigned to the caller:
    # workspace read plus application access opened a Jupyter terminal and
    # executed a canary while computes/read remained denied. The action alone
    # and all tested unassigned-instance variants were rejected.
    [
        "Microsoft.MachineLearningServices/workspaces/read",
        "Microsoft.MachineLearningServices/workspaces/computes/applicationaccess/action",
    ],
    # Live validated against an immutable V1 environment definition. All
    # three permissions were required to expand an AzureMlSecret reference;
    # the recovered ACR admin password authenticated to the registry.
    [
        "Microsoft.MachineLearningServices/workspaces/environments/read",
        "Microsoft.MachineLearningServices/workspaces/metadata/secrets/read",
        "Microsoft.MachineLearningServices/workspaces/environments/readSecrets/action",
    ],
    # Live validated against an account-level connection inherited by a
    # Foundry project. listSecrets alone stayed denied, but adding the narrow
    # connection read DataAction returned a Storage account key that downloaded
    # a private blob. Knowing the account, project, and connection names avoids
    # any ARM resource-read requirement.
    [
        "Microsoft.CognitiveServices/accounts/AIServices/connections/read",
        "Microsoft.CognitiveServices/accounts/AIServices/connections/listSecrets/action",
    ],
    # Live validated across separate principals. OpenAI responses/read returned
    # a stored response created with the account key. On a Foundry project the
    # advertised AIServices/responses/read action stayed denied, while the
    # exact agents/read action listed and returned the response, including the
    # victim prompt metadata and output.
    ["Microsoft.CognitiveServices/accounts/OpenAI/responses/read"],
    ["Microsoft.CognitiveServices/accounts/AIServices/agents/read"],
    # Live validated against a completed Speech batch transcription. files/read
    # alone returned signed download URLs when the job UUID was known. Pairing
    # it with transcriptions/read also disclosed the UUID through the job list,
    # enabling end-to-end transcript discovery and recovery.
    ["Microsoft.CognitiveServices/accounts/SpeechServices/speechrest/transcriptions/files/read"],
    [
        "Microsoft.CognitiveServices/accounts/SpeechServices/speechrest/transcriptions/read",
        "Microsoft.CognitiveServices/accounts/SpeechServices/speechrest/transcriptions/files/read",
    ],
    ["Microsoft.ContainerRegistry/registries/tasks/write"],
    ["Microsoft.ContainerRegistry/registries/taskruns/write"],
    ["Microsoft.ContainerRegistry/registries/scheduleRun/action"],
    ["Microsoft.ContainerRegistry/registries/importImage/action"],
    ["Microsoft.ContainerRegistry/registries/tasks/listDetails/action"],
    ["Microsoft.ContainerRegistry/registries/taskruns/listDetails/action"],
    # Live validated with an exact DataAction: code submitted under a known
    # session identifier read a retained file created by a different caller.
    ["Microsoft.App/sessionPools/executions/action"],
    # Live validated independently: the direct-process action returned the
    # victim environment, and the shell action returned victim file/env data.
    ["Microsoft.App/sandboxGroups/sandboxes/executeCommand/action"],
    ["Microsoft.App/sandboxGroups/sandboxes/executeShellCommand/action"],
    # Live exact-DataAction validation recovered a victim-owned file from an
    # existing sandbox without ARM read or sandbox-list permissions.
    ["Microsoft.App/sandboxGroups/sandboxes/files/read"],
    # Live exact-DataAction validation returned every cleartext value in a
    # victim ACA Sandbox secret. The separate secrets/read action returned
    # metadata only and is intentionally not promoted with it.
    ["Microsoft.App/sandboxGroups/secrets/peek/action"],
    # Live validated with exact roles. Agent listSecrets returned the
    # platform-generated OAuth private key, while connector listSecrets
    # returned cleartext custom-header API credentials hidden by ordinary GET.
    ["Microsoft.App/agents/listSecrets/action"],
    ["Microsoft.App/agents/dataconnectors/listSecrets/action"],
    ["Microsoft.App/containerApps/getAuthToken/action"],
    ["Microsoft.App/jobs/write"],
    ["Microsoft.Web/staticSites/createInvitation/action"],
    ["Microsoft.Web/sites/functions/keys/write"],
    ["Microsoft.Web/sites/slots/functions/keys/write"],
    ["Microsoft.Web/sites/functions/listkeys/action"],
    ["Microsoft.Web/sites/slots/functions/listkeys/action"],
    ["Microsoft.Web/sites/functions/listsecrets/action"],
    # Live exact-role validation started pre-existing triggered and continuous
    # WebJobs; their execution logs contained the expected canaries. Existing
    # job code and the App Service identity determine impact, so these are High.
    ["Microsoft.Web/sites/triggeredwebjobs/run/action"],
    ["Microsoft.Web/sites/slots/triggeredwebjobs/run/action"],
    ["Microsoft.Web/sites/continuouswebjobs/start/action"],
    ["Microsoft.Web/sites/host/functionKeys/write"],
    ["Microsoft.Web/sites/slots/host/functionKeys/write"],
    # Live validated independently against production and a deployment slot:
    # each exact action set an attacker-chosen Event Grid extension system key
    # that invoked the matching webhook and produced the expected side effect.
    ["Microsoft.Web/sites/host/systemkeys/write"],
    ["Microsoft.Web/sites/slots/host/systemkeys/write"],
    ["Microsoft.Web/sites/hybridConnectionNamespaces/relays/listKeys/action"],
    ["Microsoft.ContainerService/managedClusters/listClusterUserCredential/action"],
    ["Microsoft.Kubernetes/connectedClusters/listClusterUserCredential/action"],
    ["Microsoft.Kubernetes/connectedClusters/listClusterUserCredentials/action"],
    ["Microsoft.HybridContainerService/provisionedClusters/listClusterUserCredential/action"],
    ["Microsoft.Compute/virtualMachines/login/action"],
    ["Microsoft.Compute/galleries/applications/versions/write"],
    # Exact singleton tests disclosed a declared output/plain environment
    # value through resource read and stdout through the separate logs route.
    # secureValue remained redacted in the resource representation.
    ["Microsoft.Resources/deploymentScripts/read"],
    ["Microsoft.Resources/deploymentScripts/logs/read"],
    ["Microsoft.Logic/workflows/triggers/listCallbackUrl/action"],
    ["Microsoft.Logic/workflows/versions/triggers/listCallbackUrl/action"],
    ["Microsoft.Logic/workflows/triggers/run/action"],
    # Live exact-role validation against the still-supported legacy route
    # started an existing managed-identity workflow and wrote a private blob.
    # Modern API versions reject only this route as deprecated.
    ["Microsoft.Logic/workflows/run/action"],
    ["Microsoft.Logic/workflows/triggers/histories/resubmit/action"],
    # Besides signed input/output links, an exact singleton live test showed
    # that this read action authorizes listExpressionTraces and returns plain
    # evaluated expressions. Secure Inputs made that trace return
    # ContentSecured. The separately advertised listExpressionTraces/action
    # did not authorize the route by itself and therefore stays Medium.
    ["Microsoft.Logic/workflows/runs/actions/read"],
    # Live exact-role Webhook test disclosed custom request/response headers
    # and a signed callback URI that was independently replayable.
    ["Microsoft.Logic/workflows/runs/actions/requestHistories/read"],
    # Exact singleton access to the legacy child API returned both active
    # 43-character workflow signing secrets without workflow read or callback
    # URL permissions. Controlled rotations changed the matching platform SAS
    # signature and invalidated the prior primary-signed callback.
    ["Microsoft.Logic/workflows/accessKeys/list/action"],
    ["Microsoft.DataFactory/factories/pipelines/createRun/action"],
    ["Microsoft.EventGrid/eventSubscriptions/getFullUrl/action"],
    ["Microsoft.EventGrid/topics/eventSubscriptions/getFullUrl/action"],
    ["Microsoft.EventGrid/systemTopics/eventSubscriptions/getFullUrl/action"],
    ["Microsoft.EventGrid/domains/eventSubscriptions/getFullUrl/action"],
    ["Microsoft.EventGrid/domains/topics/eventSubscriptions/getFullUrl/action"],
    # Exact receive-only DataAction recovered the full seeded CloudEvent and
    # its delivery lock token while ARM namespace read remained denied.
    ["Microsoft.EventGrid/events/receive/action"],
    ["Microsoft.ContainerRegistry/registries/runs/listLogSasUrl/action"],
    ["Microsoft.Compute/disks/beginGetAccess/action"],
    ["Microsoft.Compute/snapshots/beginGetAccess/action"],
    ["Microsoft.Compute/restorePointCollections/restorePoints/diskRestorePoints/beginGetAccess/action"],
    ["Microsoft.DocumentDB/databaseAccounts/readonlykeys/action"],
    ["Microsoft.DocumentDB/databaseAccounts/readonlykeys/read"],
    # Live validated against an ACL-enabled Azure AI Search index. Ordinary
    # documents/read returned only the caller-authorized document, while the
    # exact pair plus x-ms-enable-elevated-read returned a document protected
    # for an unrelated user. The elevated operation alone could not query.
    [
        "Microsoft.Search/searchServices/indexes/documents/read",
        "Microsoft.Search/searchServices/indexes/contentSecurity/elevatedOperations/read",
    ],
    # Live validated with the exact singleton and no Search read permission:
    # replacing a known skillset caused its untouched scheduled indexer to
    # send the Search managed-identity token to an unrelated HTTPS endpoint.
    # The captured token then read a separately Entra-protected canary API.
    ["Microsoft.Search/searchServices/skillsets/write"],
    ["Microsoft.Search/searchServices/createQueryKey/action"],
    ["Microsoft.Search/searchServices/listQueryKeys/action"],
    ["Microsoft.EventGrid/topics/listKeys/action"],
    ["Microsoft.EventGrid/topics/regenerateKey/action"],
    ["Microsoft.EventGrid/domains/listKeys/action"],
    ["Microsoft.EventGrid/domains/regenerateKey/action"],
    ["Microsoft.EventGrid/namespaces/listKeys/action"],
    ["Microsoft.EventGrid/namespaces/regenerateKey/action"],
    ["Microsoft.EventGrid/namespaces/topics/listKeys/action"],
    ["Microsoft.EventGrid/namespaces/topics/regenerateKey/action"],
    ["Microsoft.EventGrid/partnerNamespaces/listKeys/action"],
    ["Microsoft.EventGrid/partnerNamespaces/regenerateKey/action"],
    ["Microsoft.OperationalInsights/workspaces/listKeys/action"],
    ["Microsoft.OperationalInsights/workspaces/regenerateSharedKey/action"],
    ["Microsoft.OperationalInsights/workspaces/sharedKeys/action"],
    ["Microsoft.OperationalInsights/workspaces/sharedKeys/read"],
    ["Microsoft.Communication/CommunicationServices/ListKeys/action"],
    ["Microsoft.Communication/CommunicationServices/RegenerateKey/action"],
    ["Microsoft.Relay/namespaces/authorizationRules/listkeys/action"],
    ["Microsoft.Relay/namespaces/authorizationRules/regenerateKeys/action"],
    ["Microsoft.Relay/namespaces/HybridConnections/authorizationRules/listkeys/action"],
    ["Microsoft.Relay/namespaces/HybridConnections/authorizationRules/regeneratekeys/action"],
    ["Microsoft.Relay/namespaces/WcfRelays/authorizationRules/listkeys/action"],
    ["Microsoft.Relay/namespaces/WcfRelays/authorizationRules/regeneratekeys/action"],
    ["Microsoft.SignalRService/SignalR/listkeys/action"],
    ["Microsoft.SignalRService/SignalR/regeneratekey/action"],
    ["Microsoft.SignalRService/WebPubSub/listkeys/action"],
    ["Microsoft.SignalRService/WebPubSub/regeneratekey/action"],
    ["Microsoft.Maps/accounts/listKeys/action"],
    ["Microsoft.Maps/accounts/regenerateKey/action"],
    ["Microsoft.Purview/accounts/listkeys/action"],
    ["Microsoft.BotService/botServices/channels/listchannelwithkeys/action"],
    ["Microsoft.ApiManagement/service/subscriptions/listSecrets/action"],
    ["Microsoft.ApiManagement/service/apiKeys/listSecrets/action"],
    ["Microsoft.ApiManagement/service/workspaces/toolServers/listSecrets/action"],
    ["Microsoft.ApiManagement/service/portalConfigs/listDelegationSecrets/action"],
    ["Microsoft.ApiManagement/service/portalConfigs/listMediaContentSecrets/action"],
    ["Microsoft.ApiManagement/service/portalSettings/listSecrets/action"],
    ["Microsoft.Logic/integrationAccounts/listCallbackUrl/action"],
    ["Microsoft.Insights/actionGroups/read"],
    ["Microsoft.Insights/webtests/read"],
    ["Microsoft.Insights/Components/ApiKeys/Action"],
    ["Microsoft.Insights/generateLiveToken/read"],
    ["Microsoft.HealthBot/healthBots/listSecrets/action"],
    ["Microsoft.NotificationHubs/Namespaces/NotificationHubs/pnsCredentials/action"],
    ["Microsoft.ContainerRegistry/registries/webhooks/getCallbackConfig/action"],
    ["Microsoft.ApiManagement/service/policies/read"],
    ["Microsoft.ApiManagement/service/apis/policies/read"],
    ["Microsoft.ApiManagement/service/apis/operations/policies/read"],
    ["Microsoft.ApiManagement/service/products/policies/read"],
    ["Microsoft.Web/sites/config/snapshots/listsecrets/action"],
    ["Microsoft.Web/sites/slots/config/snapshots/listsecrets/action"],
    ["Microsoft.Network/vpnServerConfigurations/listAllRadiusServersSecrets/action"],
    ["Microsoft.Network/virtualNetworkGateways/listAllRadiusServersSecrets/action"],
    ["Microsoft.Network/connections/sharedkey/action"],
    ["Microsoft.Network/connections/sharedKey/read"],
    ["Microsoft.AppConfiguration/configurationStores/ListKeyValue/action"],
    ["Microsoft.AppConfiguration/configurationStores/keyValues/read"],
    ["Microsoft.Logic/integrationAccounts/agreements/listContentCallbackUrl/action"],
    ["Microsoft.Logic/integrationAccounts/assemblies/listContentCallbackUrl/action"],
    ["Microsoft.Logic/integrationAccounts/maps/listContentCallbackUrl/action"],
    ["Microsoft.Logic/integrationAccounts/partners/listContentCallbackUrl/action"],
    ["Microsoft.Logic/integrationAccounts/schemas/listContentCallbackUrl/action"],
    ["Microsoft.Logic/workflows/listCallbackUrl/action"],
    ["Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"],
    ["Microsoft.Storage/storageAccounts/fileServices/fileshares/files/read"],
    ["Microsoft.Storage/storageAccounts/queueServices/queues/messages/read"],
    ["Microsoft.Storage/storageAccounts/tableServices/tables/entities/read"]
]
