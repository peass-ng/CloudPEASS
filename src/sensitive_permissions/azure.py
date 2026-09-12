

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
    # Live exact-role validation changed only config/web.appCommandLine on a
    # Linux app. The platform recycled from a benign Node server into an
    # attacker-selected dormant program while site/config reads and a sibling
    # config write remained denied. This is direct workload execution.
    ["Microsoft.Web/sites/config/write"],
    # The slot-specific operation was validated independently: only the target
    # slot recycled into the attacker-selected program; production and a
    # sibling slot remained outside the exact role's scope.
    ["Microsoft.Web/sites/slots/config/write"],
    # Live exact-role validation restored an attacker-controlled App Service
    # backup from a private Blob SAS into one production app. The caller could
    # not read the site/config or restore a sibling. The restored code ran as
    # the target's preserved system identity and returned a Key Vault canary.
    # The similarly named sites/restore/write alias only reached 404/405 legacy
    # routes and is deliberately not promoted.
    ["Microsoft.Web/sites/restoreFromBackupBlob/action"],
    # Live exact-role validation installed an attacker-supplied NuGet package
    # through the otherwise bodyless site-extension route. Its install.cmd
    # wrote attacker ASPX into wwwroot; that code ran as the app's preserved
    # system identity and returned a Key Vault-only canary.
    ["Microsoft.Web/sites/siteextensions/write"],
    # Live exact-role validation invoked the OneDeploy extension with an
    # attacker-controlled private-Blob ZIP. The replacement application ran
    # as the target's preserved identity and returned the protected canary.
    ["Microsoft.Web/sites/extensions/write"],
    # Live exact-role validation replaced one known Function's files and HTTP
    # binding. No site/function read or trigger-sync permission was present;
    # the next request ran the injected code as the Function managed identity
    # and returned a protected ARM canary.
    ["Microsoft.Web/sites/functions/write"],
    # Live minimum-role validation against the Azure Files share backing a
    # Function App: file write alone could not issue an Entra FileREST request,
    # and backup intent alone lacked write. The exact pair blindly replaced
    # index.js; the next key-protected request ran it as the Function managed
    # identity and returned the ARM-only canary without a restart.
    [
        "Microsoft.Storage/storageAccounts/fileServices/fileshares/files/write",
        "Microsoft.Storage/storageAccounts/fileServices/writeFileBackupSemantics/action",
    ],

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
    ["Microsoft.Web/sites/publishxml/action"],

    ["Microsoft.Logic/workflows/write"],
    ["Microsoft.Web/sites/basicPublishingCredentialsPolicies/read", "Microsoft.Web/sites/write", "Microsoft.Web/sites/config/list/action"],

    ["Microsoft.DBforMySQL/flexibleServers/write"],
    ["Microsoft.DBforMySQL/flexibleServers/write", "Microsoft.DBforMySQL/flexibleServers/backups/read"],
    ["Microsoft.DBforMySQL/flexibleServers/administrators/write"],

    ["Microsoft.DBforPostgreSQL/flexibleServers/write"],
    ["Microsoft.DBforPostgreSQL/flexibleServers/write", "Microsoft.DBforPostgreSQL/flexibleServers/backups/read"],
    ["Microsoft.DBforPostgreSQL/flexibleServers/administrators/write"],

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
    ["Microsoft.EventHub/namespaces/disasterRecoveryConfigs/authorizationRules/listkeys/action"],
    ["Microsoft.ServiceBus/namespaces/disasterRecoveryConfigs/authorizationRules/listkeys/action"],
    ["Microsoft.FluidRelay/fluidRelayServers/listKeys/action"],
    ["Microsoft.FluidRelay/fluidRelayServers/regenerateKey/action"],
    ["Microsoft.Quantum/Workspaces/listKeys/action"],
    ["Microsoft.Quantum/Workspaces/regenerateKey/action"],
    ["Microsoft.Devices/IotHubs/listkeys/action"],
    ["Microsoft.Devices/IotHubs/iotHubKeys/listkeys/action"],
    ["Microsoft.KeyVault/vaults/accessPolicies/write"],
    ["Microsoft.Kusto/clusters/databases/principalAssignments/write"],
    ["Microsoft.Kusto/clusters/principalAssignments/write"],
    ["Microsoft.KeyVault/vaults/deploy/action", "Microsoft.Resources/deployments/write"],
    # Live exact-role validation: templateSpecs/versions/write alone (scoped to one
    # spec, no RG read, no Microsoft.Authorization) overwrote a template-spec version;
    # the next authorized deployment consuming it created an attacker role assignment
    # under the deployer's identity (supply-chain privesc).
    ["Microsoft.Resources/templateSpecs/versions/write"],
    ["Microsoft.Search/searchServices/listAdminKeys/action"],
    ["Microsoft.Search/searchServices/regenerateAdminKey/action"],
    ["Microsoft.Storage/storageAccounts/listAccountSas/action"],
    ["Microsoft.Storage/storageAccounts/listServiceSas/action"],
    # Live exact-role validation on an HNS account: runAsSuperUser alone
    # changed POSIX permissions and read the protected blob canary.
    ["Microsoft.Storage/storageAccounts/blobServices/containers/blobs/runAsSuperUser/action"],
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
    # Exact target-scoped API connection write redirected the next unchanged
    # Logic workflow output to an attacker-selected Blob sink without read or
    # workflow permissions. Impact requires a future privileged consumer.
    ["Microsoft.Web/connections/write"],
    # Exact access-policy write on a V2 API connection authorized an otherwise
    # forbidden Workflow Standard identity to use the connection's unreadable
    # credentials after its attacker-controlled runtime refreshed.
    ["Microsoft.Web/connections/accessPolicies/Write"],
    # An exact map-scoped write blindly replaced an XSLT used by an unchanged
    # Logic workflow. Its next protected input disclosed the selected secret
    # field despite denied map/workflow reads and denied sibling writes.
    ["Microsoft.Logic/integrationAccounts/maps/write"],
    # A blind Dapr component update supplied a replacement state-store
    # destination and credentials. A later unchanged managed-identity workload
    # wrote its Key Vault-only canary there without component read/listSecrets.
    ["Microsoft.App/managedEnvironments/daprComponents/write"],
    # Exact ARM Action and data-plane DataAction tests independently poisoned
    # a write-only secret consumed by a privileged scheduled workload. Impact
    # depends on an unversioned downstream consumer, so these are High.
    ["Microsoft.KeyVault/vaults/secrets/write"],
    ["Microsoft.KeyVault/vaults/secrets/setSecret/action"],
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
    # Live exact-role validation at one job-schedule child proved that this
    # singleton can blindly attach a known published, identity-bearing runbook
    # to an existing enabled schedule with attacker-selected parameters. The
    # next platform-owned tick exfiltrated the runbook MI's protected canary;
    # schedule/runbook/job reads and direct job start remained denied.
    ["Microsoft.Automation/automationAccounts/jobSchedules/write"],
    # Exact module-scoped write replaced a classic dependency without module,
    # runbook, job, account, or source-Blob read. The next unchanged scheduled
    # runbook loaded it and exfiltrated its MI-only ARM canary. This remains
    # workload-conditional High because a compatible future consumer is needed.
    ["Microsoft.Automation/automationAccounts/modules/write"],
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
    # Live validated on an F0 Healthcare Agent with the exact singleton
    # DataAction and no ARM read. The export returned a CSV containing both
    # sides of a seeded synthetic patient-like Direct Line conversation.
    ["Microsoft.HealthBot/healthBots/Admin/ConversationLogs/Export/Action"],
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
    # Live validated on an ABAC-enabled registry. content/write alone received
    # push but ACR rejected the manifest replacement because pull was also
    # required. The exact read+write pair retagged an existing attacker image
    # as a mutable tag; a later legitimate Container App revision restart
    # pulled it and exposed a managed-identity-only ARM canary. Metadata write,
    # registry ARM read, and listCredentials were not required.
    [
        "Microsoft.ContainerRegistry/registries/repositories/content/read",
        "Microsoft.ContainerRegistry/registries/repositories/content/write",
    ],
    # Live validated with an exact DataAction: code submitted under a known
    # session identifier read a retained file created by a different caller.
    ["Microsoft.App/sessionPools/executions/action"],
    # Live validated independently: a content-read-only principal recovered a
    # retained file by known pool, session identifier, and filename. It needed
    # neither ARM/resource read nor the sibling file-metadata read action.
    ["Microsoft.App/sessionPools/files/content/read"],
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
    # Live validated with an exact singleton role: activating an inactive
    # retained revision made its previously unavailable endpoint execute and
    # return the seeded canary. The retained revision's code, identity, secret
    # references, and network context determine impact, so this is High rather
    # than an arbitrary-code Critical primitive.
    ["Microsoft.App/containerApps/revisions/activate/action"],
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
    # Live exact-role validation blindly replaced a known sink linked service
    # with an attacker-keyed private Storage destination. The next unchanged
    # pipeline run copied its protected canary to that destination; linked-
    # service/pipeline reads, createRun, and a sibling write remained denied.
    ["Microsoft.DataFactory/factories/linkedservices/write"],
    # Live exact-role validation at one dataset resource blindly replaced its
    # known sink linked-service/path. The next unchanged owner-started pipeline
    # copied a private source canary only to the attacker-readable sink, while
    # dataset/pipeline reads, createRun, sibling write, and source Blob read
    # remained denied. This is workload-conditional High, not Critical.
    ["Microsoft.DataFactory/factories/datasets/write"],
    # Live exact-role validation blindly replaced a factory global URL
    # parameter. The next unchanged owner-started pipeline sent its protected
    # managed-identity ARM result to the attacker receiver; parameter/pipeline
    # reads, createRun, and a sibling factory write stayed denied.
    ["Microsoft.DataFactory/factories/globalParameters/write"],
    # An enabled schedule trigger rejects mutation. Live minimum-role testing
    # proved that Stop + Write changed only the known trigger's pipeline URL
    # parameter, Start was separately enforced, and the next scheduled run
    # sent a protected factory-MI result to the attacker receiver.
    [
        "Microsoft.DataFactory/factories/triggers/stop/action",
        "Microsoft.DataFactory/factories/triggers/write",
        "Microsoft.DataFactory/factories/triggers/start/action",
    ],
    # Live exact-role validation recovered a plaintext secret-like pipeline
    # parameter from a known completed run. Parameters declared SecureString
    # remained redacted in this representation.
    ["Microsoft.DataFactory/factories/pipelineruns/read"],
    # Querying historical runs requires both the action that starts the query
    # and the separately enforced result-read operation. The exact pair
    # recovered the same plaintext parameter without factory or pipeline read.
    [
        "Microsoft.DataFactory/factories/querypipelineruns/action",
        "Microsoft.DataFactory/factories/querypipelineruns/read",
    ],
    # Live exact DataAction tests recovered plaintext command lines,
    # environment values, and SAS-like metadata from inert jobs and schedules.
    # The two resource families remained independently scoped.
    ["Microsoft.Batch/batchAccounts/jobs/read"],
    ["Microsoft.Batch/batchAccounts/jobSchedules/read"],
    # Live minimum-role validation against a stopped Stream Analytics job:
    # Sample/action started collection but its Location URL returned 403 until
    # the separately enforced OperationResults/read permission was present.
    # The exact pair returned a signed download URL containing the private
    # Blob-input canary; each role was scoped to one input and a sibling input
    # remained denied.
    [
        "Microsoft.StreamAnalytics/streamingjobs/inputs/Sample/action",
        "Microsoft.StreamAnalytics/streamingjobs/inputs/OperationResults/read",
    ],
    # Live minimum-role validation against an active Stream Analytics job:
    # output write alone reached the service but could not mutate an active
    # job. Stop + output write redirected its existing Blob sink to an
    # attacker-keyed private account, and Start resumed the unchanged query.
    # The next private input event appeared only at the replacement sink.
    [
        "Microsoft.StreamAnalytics/streamingjobs/Stop/action",
        "Microsoft.StreamAnalytics/streamingjobs/outputs/Write",
        "Microsoft.StreamAnalytics/streamingjobs/Start/action",
    ],
    # Live minimum-role validation against an existing Azure SQL Elastic Job:
    # step write alone was linked-authorized against both the stored credential
    # and target group. Exact read on those two linked resources (the credential
    # response exposed only its username) allowed a blind T-SQL replacement.
    # The separately enforced executions/write operation then started that
    # version via PUT /executions/{uuid}; it copied a protected database canary
    # using the stored SQL credential. Every singleton and a sibling job stayed
    # denied, so this is a workload-conditional High chain rather than Critical.
    [
        "Microsoft.Sql/servers/jobAgents/jobs/steps/write",
        "Microsoft.Sql/servers/jobAgents/credentials/read",
        "Microsoft.Sql/servers/jobAgents/targetGroups/read",
        "Microsoft.Sql/servers/jobAgents/jobs/executions/write",
    ],
    # Live minimum-role validation: the action passed ARM alone but Databricks
    # bootstrap stayed 403. Adding only workspace read placed the user in the
    # workspace admins group and enabled the admin-only SCIM user list.
    [
        "Microsoft.Databricks/workspaces/assignWorkspaceAdmin/action",
        "Microsoft.Databricks/workspaces/read",
    ],
    ["Microsoft.EventGrid/eventSubscriptions/getFullUrl/action"],
    ["Microsoft.EventGrid/topics/eventSubscriptions/getFullUrl/action"],
    ["Microsoft.EventGrid/systemTopics/eventSubscriptions/getFullUrl/action"],
    ["Microsoft.EventGrid/domains/eventSubscriptions/getFullUrl/action"],
    ["Microsoft.EventGrid/domains/topics/eventSubscriptions/getFullUrl/action"],
    # Live exact-role validation overwrote an existing custom-topic event
    # subscription so future events were delivered to an attacker-controlled
    # HTTPS webhook. No-role and sibling-topic writes were denied. Redirecting
    # to another Azure Storage queue additionally required the destination
    # account's Microsoft.Storage/storageAccounts/write permission.
    ["Microsoft.EventGrid/eventSubscriptions/write"],
    # The namespace-topic alias was independently live validated. An exact
    # event-subscription-scoped role replaced an existing push destination
    # with an attacker Logic webhook. The next private CloudEvent arrived
    # only at the replacement consumer; GET and a sibling-topic write stayed
    # denied. This is not inferred from the classic generic alias above.
    ["Microsoft.EventGrid/namespaces/topics/eventSubscriptions/write"],
    # Live exact-role validation replaced the receiver of an existing Action
    # Group with an attacker-controlled HTTPS webhook. The caller could not
    # read the group or write its sibling; a pre-existing Activity Log alert
    # subsequently delivered its synthetic description and resource metadata
    # to the replacement endpoint. Impact requires an active alert/receiver
    # consumer, so this is conditional High rather than Critical.
    ["Microsoft.Insights/ActionGroups/Write"],
    # Live minimum-role validation changed an existing Storage metric alert
    # from an inert threshold to a matching one. Azure linked-authorized both
    # the monitored resource and Action Group, so the write required these two
    # exact reads at their respective scopes. The next evaluation invoked an
    # unchanged Logic playbook whose MI disclosed the ARM-protected canary.
    [
        "Microsoft.Insights/metricAlerts/write",
        "Microsoft.Storage/storageAccounts/read",
        "Microsoft.Insights/actionGroups/read",
    ],
    # Exact receive-only DataAction recovered the full seeded CloudEvent and
    # its delivery lock token while ARM namespace read remained denied.
    ["Microsoft.EventGrid/events/receive/action"],
    # Exact send-only DataAction published two CloudEvents to a namespace
    # topic without ARM namespace/topic read. A queue subscriber recovered
    # both canaries; the same valid principal was denied on a sibling topic.
    ["Microsoft.EventGrid/events/send/action"],
    # Exact topic-space roles were sufficient without ARM resource read. An
    # HTTP-to-MQTT publisher delivered the exact canary to an Entra-authenticated
    # MQTT v5 subscriber; both principals were denied on a sibling topic space.
    ["Microsoft.EventGrid/topicSpaces/publish/action"],
    ["Microsoft.EventGrid/topicSpaces/subscribe/action"],
    # The generic action returned static delivery attributes marked isSecret
    # verbatim while ordinary resource GET redacted them as Hidden. The
    # advertised topics/eventSubscriptions alias did not authorize this route.
    ["Microsoft.EventGrid/eventSubscriptions/getDeliveryAttributes/action"],
    # Exact IoT Hub roles proved device/module credential theft or creation,
    # desired-state command injection, cloud-to-device delivery, direct method
    # invocation, targeted job execution, and full registry export/import.
    # Device keys also minted a configured Storage file-upload SAS.
    # Separately, exact hub write replaced a DeviceMessages route with an
    # attacker-supplied Storage connection string. Future telemetry appeared
    # in that container while the former destination received nothing new;
    # no Storage RBAC or linked authorization was required.
    ["Microsoft.Devices/IotHubs/write"],
    ["Microsoft.Devices/IotHubs/devices/read"],
    ["Microsoft.Devices/IotHubs/devices/write"],
    ["Microsoft.Devices/IotHubs/twins/read"],
    ["Microsoft.Devices/IotHubs/twins/write"],
    ["Microsoft.Devices/IotHubs/cloudToDeviceMessages/send/action"],
    ["Microsoft.Devices/IotHubs/directMethods/invoke/action"],
    ["Microsoft.Devices/IotHubs/jobs/read"],
    ["Microsoft.Devices/IotHubs/jobs/write"],
    ["Microsoft.Devices/IotHubs/exportDevices/action"],
    ["Microsoft.Devices/IotHubs/importDevices/action"],
    # DPS attestation detail disclosed individual/group symmetric keys. The
    # write actions created attacker-keyed enrollment paths. Every path
    # provisioned a device into the linked hub and published a live canary.
    ["Microsoft.Devices/provisioningServices/attestationmechanism/details/action"],
    ["Microsoft.Devices/provisioningServices/enrollments/write"],
    ["Microsoft.Devices/provisioningServices/enrollmentGroups/write"],
    # Exact entity-scoped DataActions injected or recovered seeded messages;
    # sibling entities and the opposite operation remained denied. Service
    # Bus receive could also permanently complete the received message.
    ["Microsoft.EventHub/namespaces/messages/receive/action"],
    ["Microsoft.EventHub/namespaces/messages/send/action"],
    # Live capture redirection required the event-hub write plus both linked
    # Storage permissions. Namespace write was irrelevant, and either Storage
    # permission by itself failed. The combination archived future events to
    # an attacker-readable container; it did not backfill retained events.
    [
        "Microsoft.EventHub/namespaces/eventhubs/write",
        "Microsoft.Storage/storageAccounts/blobServices/containers/write",
        "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write",
    ],
    ["Microsoft.ServiceBus/namespaces/messages/receive/action"],
    ["Microsoft.ServiceBus/namespaces/messages/send/action"],
    # Live exact DataAction validation injected a base64-encoded command into
    # one known Storage Queue. The caller could not peek the target, access the
    # account, or add to a sibling queue. An existing unchanged queue-triggered
    # Function consumed it and used its managed identity to disclose an ARM-
    # protected canary. A wrong command was consumed without disclosure.
    ["Microsoft.Storage/storageAccounts/queueServices/queues/messages/add/action"],
    # Independently live validated at one known Table entity. Both the broad
    # write and narrower update-only action changed an unreadable TargetUri;
    # the next unchanged Function invocation followed it with its managed
    # identity and disclosed the ARM-only canary. Entity read, account read,
    # and sibling-table updates remained denied.
    ["Microsoft.Storage/storageAccounts/tableServices/tables/entities/write"],
    ["Microsoft.Storage/storageAccounts/tableServices/tables/entities/update/action"],
    # Shared-access rules may be Listen-, Send-, or Manage-scoped, so their
    # credentials are High but not inherently subscription/tenant takeover.
    ["Microsoft.EventHub/namespaces/authorizationRules/listkeys/action"],
    ["Microsoft.EventHub/namespaces/authorizationRules/regenerateKeys/action"],
    ["Microsoft.EventHub/namespaces/eventhubs/authorizationRules/listkeys/action"],
    ["Microsoft.EventHub/namespaces/eventhubs/authorizationRules/regenerateKeys/action"],
    ["Microsoft.ServiceBus/namespaces/authorizationrules/listKeys/action"],
    ["Microsoft.ServiceBus/namespaces/authorizationrules/regenerateKeys/action"],
    ["Microsoft.ServiceBus/namespaces/*/authorizationRules/ListKeys/action"],
    ["Microsoft.ServiceBus/namespaces/*/authorizationRules/regenerateKeys/action"],
    ["Microsoft.ServiceBus/namespaces/queues/authorizationRules/listKeys/action"],
    ["Microsoft.ServiceBus/namespaces/queues/authorizationRules/regenerateKeys/action"],
    ["Microsoft.ServiceBus/namespaces/topics/authorizationRules/listKeys/action"],
    ["Microsoft.ServiceBus/namespaces/topics/authorizationRules/regenerateKeys/action"],
    # Creating a rule does not return its generated key. These exact minimum
    # pairs created Manage rules and exercised their scoped SAS credentials.
    [
        "Microsoft.EventHub/namespaces/eventhubs/authorizationRules/write",
        "Microsoft.EventHub/namespaces/eventhubs/authorizationRules/listkeys/action",
    ],
    [
        "Microsoft.ServiceBus/namespaces/queues/authorizationRules/write",
        "Microsoft.ServiceBus/namespaces/queues/authorizationRules/listKeys/action",
    ],
    # Live exact-role validation showed both operations are required. Topic
    # subscription write alone passed primary authorization but failed linked
    # authorization on the destination queue; queue write alone could not
    # alter the subscription. Together they forwarded both retained and future
    # topic messages into an attacker-readable queue.
    [
        "Microsoft.ServiceBus/namespaces/topics/subscriptions/write",
        "Microsoft.ServiceBus/namespaces/queues/write",
    ],
    ["Microsoft.ContainerRegistry/registries/runs/listLogSasUrl/action"],
    ["Microsoft.Compute/disks/beginGetAccess/action"],
    ["Microsoft.Compute/snapshots/beginGetAccess/action"],
    ["Microsoft.Compute/restorePointCollections/restorePoints/diskRestorePoints/beginGetAccess/action"],
    ["Microsoft.DocumentDB/databaseAccounts/readonlykeys/action"],
    ["Microsoft.DocumentDB/databaseAccounts/readonlykeys/read"],
    # Live exact-role validation recovered seeded secret-like graph data.
    # Query did not need twin read, while twin and relationship reads each
    # disclosed their own protected properties and remained instance-scoped.
    ["Microsoft.DigitalTwins/query/action"],
    ["Microsoft.DigitalTwins/digitaltwins/read"],
    # Live cross-service validation poisoned a selector later trusted by an
    # Automation managed identity, exposing its Key Vault-readable canary.
    ["Microsoft.DigitalTwins/digitaltwins/write"],
    ["Microsoft.DigitalTwins/digitaltwins/relationships/read"],
    # Live exact-role validation changed and reset the SGX trust policy on an
    # unsigned Azure Attestation provider. Signed providers additionally
    # require a trusted policy-signing key, so the impact is High, not Critical.
    ["Microsoft.Attestation/attestationProviders/attestation/write"],
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
    # Live exact-role validation showed each singleton can redirect data that
    # the Search managed identity can read into an independently readable
    # index, without Search-object reads or direct access to the source Blob.
    # dataSources/write needs a later existing indexer run; indexers/write both
    # auto-runs a new indexer and authorizes its Search data-plane run/reset.
    ["Microsoft.Search/searchServices/dataSources/write"],
    ["Microsoft.Search/searchServices/indexers/write"],
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
    # Live exact-role validation used only this singleton to create ACS
    # identities and mint chat/VoIP tokens for a pre-existing identity. The
    # resulting victim token created a thread and sent/read an attributed
    # canary; no-role, Read-only, and sibling-resource controls were denied.
    ["Microsoft.Communication/CommunicationServices/Write"],
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
    # SignalR returned temporary signing material that established an
    # arbitrary-user hub client. The send actions delivered exact canaries to
    # known live connections on both real-time services.
    ["Microsoft.SignalRService/SignalR/auth/accessKey/action"],
    ["Microsoft.SignalRService/SignalR/clientConnection/send/action"],
    ["Microsoft.SignalRService/WebPubSub/clientConnection/send/action"],
    # A blind exact hub update redirected future authenticated user events,
    # including their bodies and identity/connection metadata, to an
    # attacker-controlled HTTPS handler without hub or parent read access.
    ["Microsoft.SignalRService/WebPubSub/hubs/write"],
    # Live exact-role validation: a principal holding ONLY experiments/start/action
    # (no experiment read, no permission on the target) started a pre-configured
    # Chaos experiment whose system-assigned identity was Key Vault Contributor.
    # The DenyAccess fault ran under that identity and flipped the target vault's
    # firewall Allow->Deny (no-role start was 403). This is availability/disruption
    # (DoS) via a more-privileged experiment identity, not attacker-chosen privesc,
    # so it is Medium and conditional on an existing configured experiment/target.
    ["Microsoft.Chaos/experiments/start/action"],
    # Web PubSub token generation alone could not connect; adding only the
    # handshake permission produced a usable resource-and-hub-bound JWT.
    [
        "Microsoft.SignalRService/WebPubSub/clientConnection/generateToken/action",
        "Microsoft.SignalRService/WebPubSub/clientConnection/write",
    ],
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
    # Live exact-role validation for both the Action and DataAction catalog
    # forms poisoned a secret selector consumed by a privileged Automation MI.
    ["Microsoft.AppConfiguration/configurationStores/keyValues/write"],
    ["Microsoft.Logic/integrationAccounts/agreements/listContentCallbackUrl/action"],
    ["Microsoft.Logic/integrationAccounts/assemblies/listContentCallbackUrl/action"],
    ["Microsoft.Logic/integrationAccounts/maps/listContentCallbackUrl/action"],
    ["Microsoft.Logic/integrationAccounts/partners/listContentCallbackUrl/action"],
    ["Microsoft.Logic/integrationAccounts/schemas/listContentCallbackUrl/action"],
    ["Microsoft.Logic/workflows/listCallbackUrl/action"],
    ["Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"],
    # Live exact-role validation scoped this DataAction to one private JSON
    # control blob. The caller could not read that blob, overwrite its sibling,
    # or access Data Factory. Its replacement was nevertheless consumed by an
    # existing schedule and redirected an MSI-authenticated Web activity to an
    # owned receiver. The captured factory-identity ARM token then read a
    # protected canary. This is High and workload-conditional, not Critical.
    ["Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write"],
    ["Microsoft.Storage/storageAccounts/fileServices/fileshares/files/read"],
    ["Microsoft.Storage/storageAccounts/queueServices/queues/messages/read"],
    ["Microsoft.Storage/storageAccounts/tableServices/tables/entities/read"],
    # Live minimum-role validation against an operational Azure Blob backup:
    # restore/action passed the primary vault authorization check but Azure
    # rejected the linked storage account until this exact read was granted at
    # the account scope. The pair completed a point-in-time restore and
    # recreated a deleted canary byte-for-byte. It does not itself grant Blob
    # data reads, but it can roll back account contents and re-expose deleted
    # data to workloads or principals that already consume the account.
    [
        "Microsoft.DataProtection/backupVaults/backupInstances/restore/action",
        "Microsoft.Storage/storageAccounts/read",
    ],
    # API version 2025-07-05 added service-specific user delegation keys for
    # Files, Queues, and Tables. In live tests all four actions minted keys, but
    # every action-only SAS was denied; adding the exact service read produced
    # the canary. Azure Files also enforces backup-semantics intent.
    [
        "Microsoft.Storage/storageAccounts/blobServices/generateUserDelegationKey/action",
        "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
    ],
    [
        "Microsoft.Storage/storageAccounts/fileServices/generateUserDelegationKey/action",
        "Microsoft.Storage/storageAccounts/fileServices/fileshares/files/read",
        "Microsoft.Storage/storageAccounts/fileServices/readFileBackupSemantics/action",
    ],
    [
        "Microsoft.Storage/storageAccounts/queueServices/generateUserDelegationKey/action",
        "Microsoft.Storage/storageAccounts/queueServices/queues/messages/read",
    ],
    [
        "Microsoft.Storage/storageAccounts/tableServices/generateUserDelegationKey/action",
        "Microsoft.Storage/storageAccounts/tableServices/tables/entities/read",
    ],
]
