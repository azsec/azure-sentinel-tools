<#
    .SYNOPSIS
        This script is used to create a scheduled analytics rule in Microsoft Sentinel.
    .DESCRIPTION
        This script is used to create a scheduled analytics rule with custom entity mapping and incident grouping configuration in Microsoft Sentinel.
    .NOTES
        This script is written with Azure PowerShell (Az) module.

        File Name     : Get-AzSentinelIncidentComments.ps1
        Version       : 1.0.0.0
        Author        : AzSec (https://azsec.azurewebsites.net/)
        Prerequisite  : Az
        API Version   : 2021-03-01-preview

    .PARAMETER WorkspaceRg
        The resource group name of the Log Analytics workspace Azure Sentinel connects to
    .PARAMETER WorkspaceName
        The name of the Log Analytics workspace Azure Sentinel connects to
    .PARAMETER RuleDisplayName
        The display name of the alert rule
    .PARAMETER RuleDescription
        The description of the alert rule
    .PARAMETER Query
        The analytics query rule
    .PARAMETER IsEnabled
        Flag to indicate whether the rule is enabled
    .PARAMETER Tactics
        The tactic(s) of the alert rules
    .PARAMETER Severity
        The severity of the alert rules
    .PARAMETER SuppressionEnabled
        Flag to indicate whether suppression is enabled
    .PARAMETER SuppressionDuration
        The duration of the suppression if enabled
    .PARAMETER QueryFrequency
        The query frequency e.g. PT5H
    .PARAMETER QueryPeriod
        The query period
    .PARAMETER TriggerOperator
        The operator of the trigger
    .PARAMETER TriggerThreshold
        The threshold of the trigger
    .PARAMETER EntityMappings
        The entity mapping of the alert rule
    .PARAMETER CustomDetails
        The custom detail of the alert rule
    .PARAMETER AlertDisplayNameFormat
        The custom format of the alert
    .PARAMETER IncidentCreation
        Flag to indicate whether to create incidents from alerts triggered by this rule.
    .PARAMETER GroupIncidentEnabled
        Flag to indicate whether to group incident
    .PARAMETER ReopenClosedIncident
        Flag to indicate whether to reopen closed incident
    .PARAMETER LookbackDuration
        Limit the group to alerts created within the selected time frame
    .PARAMETER MatchingMethod
        The matching method of incident grouping configuration
    .PARAMETER GroupByEntities
        The entities to group
    .PARAMETER GroupByAlertDetails
        The field in the alert to group
    .PARAMETER GroupByCustomDetails
        The field in the custom detail to grou
    
    .EXAMPLE
        .\New-AzSentinelAlertRule.ps1 -WorkspaceRg "azsec-corporate-rg" `
                                      -WorkspaceName "azsec-shared-workspace" `
                                      -RuleDisplayName "AzSec - Monitor Az Key Vault Operation" `
                                      -RuleDescription "This is the sample rule to monitor KV" `
                                      -Query 'let TargetKeyVaults = dynamic (["shared-corporate-kv","azsec-kv"]); AzureDiagnostics | where ResourceProvider =~ "MICROSOFT.KEYVAULT" | where Resource in~ (TargetKeyVaults) | project TimeGenerated, OperationName, KeyVaultName = Resource, ResourceGroup, CallerIPAddress, _ResourceId' `
                                      -IsEnabled "True" `
                                      -Tactics "Reconnaissance", "Discovery" `
                                      -Severity "Medium" `
                                      -SuppressionEnabled "True" `
                                      -SuppressionDuration "PT5H" `
                                      -QueryFrequency "PT5H" `
                                      -QueryPeriod "PT5H" `
                                      -TriggerOperator "GreaterThan" `
                                      -TriggerThreshold "0" `
                                      -EntityMappings '[{"entityType":"AzureResource","fieldMappings":["ResourceId","_ResourceId"]},{"entityType":"IP","fieldMappings":["Address","CallerIPAddress"]}]' `
                                      -CustomDetails @{OperationName = "OperationName"; KeyVaultName = "KeyVaultName"} `
                                      -AlertDisplayNameFormat "{{OperationName}} from {{CallerIPAddress}} on {{KeyVaultName}} Key Vault" `
                                      -IncidentCreation "True" `
                                      -GroupIncidentEnabled "True" `
                                      -ReopenClosedIncident "True" `
                                      -LookbackDuration "PT5H" `
                                      -MatchingMethod "Selected" `
                                      -GroupByEntities "AzureResource", "IP" `
                                      -GroupByAlertDetails "DisplayName", "Severity" `
                                      -GroupByCustomDetails "OperationName", "KeyVaultName" 

#>
Param(
    [Parameter(Mandatory = $true,
               HelpMessage = "The resource group name of the Log Analytics workspace Azure Sentinel connects to",
               Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string]
    $WorkspaceRg,

    [Parameter(Mandatory = $true,
               HelpMessage = "The name of the Log Analytics workspace Azure Sentinel connects to",
               Position = 1)]
    [ValidateNotNullOrEmpty()]
    [string]
    $WorkspaceName,

    [Parameter(Mandatory = $true,
               HelpMessage = "The display name of the alert rule",
               Position = 2)]
    [ValidateNotNullOrEmpty()]
    [string]
    $RuleDisplayName,

    [Parameter(Mandatory = $true,
               HelpMessage = "The description of the alert rule",
               Position = 3)]
    [ValidateNotNullOrEmpty()]
    [string]
    $RuleDescription,

    [Parameter(Mandatory = $true,
               HelpMessage = "The analytics query rule",
               Position = 4)]
    [ValidateNotNullOrEmpty()]
    [string]
    $Query,

    [Parameter(Mandatory = $true,
               HelpMessage = "Flag to indicate whether the rule is enabled",
               Position = 5)]
    [ValidateSet("True", "False")]
    [string]
    $IsEnabled,

    [Parameter(Mandatory = $true,
               HelpMessage = "The tactic(s) of the alert rules",
               Position = 6)]
    [ValidateSet("Execution", 
                 "Persistence",
                 "Reconnaissance",
                 "ResourceDevelopment",
                 "InitialAccess",
                 "PrivilegeEscalation",
                 "DefenseEvasion",
                 "CredentialAccess",
                 "Discovery",
                 "LateralMovement",
                 "Collection",
                 "CommandAndControl",
                 "Exfiltration",
                 "Impact")]
    [string[]]
    $Tactics,

    [Parameter(Mandatory = $true,
               HelpMessage = "The severity of the alert rules",
               Position = 7)]
    [ValidateSet("Informational", 
                 "High",
                 "Medium",
                 "Low")]
    [string]
    $Severity,

    [Parameter(Mandatory = $true,
               HelpMessage = "Flag to indicate whether suppression is enabled",
               Position = 8)]
    [ValidateSet("True", "False")]
    [string]
    $SuppressionEnabled,

    [Parameter(Mandatory = $false,
               HelpMessage = "The duration of the suppression if enabled",
               Position = 9)]
    [ValidateNotNullOrEmpty()]
    [string]
    $SuppressionDuration,

    [Parameter(Mandatory = $true,
               HelpMessage = "The query frequency",
               Position = 10)]
    [ValidateNotNullOrEmpty()]
    [string]
    $QueryFrequency,

    [Parameter(Mandatory = $true,
               HelpMessage = "The query period",
               Position = 11)]
    [ValidateNotNullOrEmpty()]
    [string]
    $QueryPeriod,

    [Parameter(Mandatory = $true,
               HelpMessage = "The operator of the trigger",
               Position = 12)]
    [ValidateSet("GreaterThan", 
                 "LessThan",
                 "Equal",
                 "NotEqual")]
    [string]
    $TriggerOperator,

    [Parameter(Mandatory = $true,
               HelpMessage = "The threshold of the trigger",
               Position = 13)]
    [ValidateNotNullOrEmpty()]
    [string]
    $TriggerThreshold,

    [Parameter(Mandatory = $false,
               HelpMessage = "The entity mapping of the alert rule",
               Position = 14)]
    [ValidateNotNullOrEmpty()]
    [string]
    $EntityMappings,

    [Parameter(Mandatory = $false,
               HelpMessage = "The custom detail of the alert rule",
               Position = 15)]
    [ValidateNotNullOrEmpty()]
    [Hashtable]
    $CustomDetails,

    [Parameter(Mandatory = $false,
               HelpMessage = "The custom format of the alert",
               Position = 16)]
    [ValidateNotNullOrEmpty()]
    [string]
    $AlertDisplayNameFormat,

    [Parameter(Mandatory = $false,
               HelpMessage = "Flag to indicate whether to create incidents from alerts triggered by this rule",
               Position = 17)]
    [ValidateSet("True", "False")]
    [string]
    $IncidentCreation,

    [Parameter(Mandatory = $true,
               HelpMessage = "Flag to indicate whether to group incident",
               Position = 18)]
    [ValidateSet("True", "False")]
    [string]
    $GroupIncidentEnabled,

    [Parameter(Mandatory = $false,
               HelpMessage = "Flag to indicate whether to reopen closed incident",
               Position = 19)]
    [ValidateSet("True", "False")]
    [string]
    $ReopenClosedIncident,

    [Parameter(Mandatory = $false,
               HelpMessage = "Limit the group to alerts created within the selected time frame",
               Position = 20)]
    [ValidateNotNullOrEmpty()]
    [string]
    $LookbackDuration,

    [Parameter(Mandatory = $false,
               HelpMessage = "The matching method of incident grouping configuration",
               Position = 21)]
    [ValidateNotNullOrEmpty()]
    [string]
    $MatchingMethod,

    [Parameter(Mandatory = $false,
               HelpMessage = "The entities to group",
               Position = 22)]
    [ValidateNotNullOrEmpty()]
    [string[]]
    $GroupByEntities,

    [Parameter(Mandatory = $false,
               HelpMessage = "The field in the alert to group",
               Position = 23)]
    [ValidateNotNullOrEmpty()]
    [string[]]
    $GroupByAlertDetails,

    [Parameter(Mandatory = $false,
               HelpMessage = "The field in the custom detail to group",
               Position = 24)]
    [ValidateNotNullOrEmpty()]
    [string[]]
    $GroupByCustomDetails
    
)

$workspaceId = (Get-AzOperationalInsightsWorkspace -Name $WorkspaceName `
                                                   -ResourceGroupName $WorkspaceRg).ResourceId
if (!$workspaceId) {
    throw  "[!] Workspace cannot be found. Please try again"
}
else {
    Write-Host -ForegroundColor Green "[-] Your Azure Sentinel is connected to workspace: $WorkspaceName"
}

$entities = $EntityMappings | ConvertFrom-Json
$entityMappingsObj = @()

foreach ($entity in $entities) {
    $entityObject = @{
        entityType    = $entity.entityType
        fieldMappings = @(
            @{
                identifier = $entity.fieldMappings[0]
                columnName = $entity.fieldMappings[1]
            }
        )
    }
    $entityMappingsObj += $entityObject
}

$entityMappingsObj

$alertRuleId = (New-Guid).Guid
$alert = [ordered]@{
    ruleId     = $alertRuleId
    kind       = "Scheduled"
    properties = @{
        displayName           = $RuleDisplayName
        enabled               = $IsEnabled
        description           = $RuleDescription
        tactics               = @(
            $Tactics
        )
        suppressionEnabled    = $SuppressionEnabled
        suppressionDuration   = $SuppressionDuration
        query                 = $Query
        severity              = $Severity
        queryFrequency        = $QueryFrequency
        queryPeriod           = $QueryPeriod
        triggerOperator       = $TriggerOperator
        triggerThreshold      = $TriggerThreshold
        entityMappings        = $entityMappingsObj
        customDetails         = $CustomDetails
        alertDetailsOverride  = @{
            alertDisplayNameFormat   = $AlertDisplayNameFormat
            alertDescriptionFormat   = $AlertDisplayNameFormat
        }
        incidentConfiguration = @{
            createIncident        = "true"
            groupingConfiguration = @{
                enabled              = $GroupIncidentEnabled
                reopenClosedIncident = $ReopenClosedIncident
                lookbackDuration     = $LookbackDuration
                matchingMethod       = $MatchingMethod
                groupByEntities      = @(
                    $GroupByEntities
                )
                groupByAlertDetails  = @(
                    $GroupByAlertDetails
                )
                groupByCustomDetails = @(
                    $GroupByCustomDetails
                )
            }
        }
    }
}

<# Sample accepted request body in JSON format
{
  "ruleId": "8e2ce858-2b9e-4583-8a61-81810b55d923",
  "kind": "Scheduled",
  "properties": {
    "query": "let TargetKeyVaults = dynamic ([\"shared-corporate-kv\",\"azsec-kv\"]); AzureDiagnostics | where ResourceProvider =~ \"MICROSOFT.KEYVAULT\" | where Resource in~ (TargetKeyVaults) | project TimeGenerated, OperationName, KeyVaultName = Resource, ResourceGroup, CallerIPAddress, _ResourceId",
    "triggerThreshold": "0",
    "customDetails": {
      "KeyVaultName": "KeyVaultName",
      "OperationName": "OperationName"
    },
    "suppressionDuration": "PT5H",
    "suppressionEnabled": "True",
    "queryPeriod": "PT5H",
    "triggerOperator": "GreaterThan",
    "displayName": "AzSecAAA - Monitor Az Key Vault Operation",
    "queryFrequency": "PT5H",
    "alertDetailsOverride": {
      "alertDescriptionFormat": "{{OperationName}} from {{CallerIPAddress}} on {{KeyVaultName}} Key Vault",
      "alertDisplayNameFormat": "{{OperationName}} from {{CallerIPAddress}} on {KeyVaultName}} Key Vault"
    },
    "description": "This is the sample rule to monitor KV",
    "severity": "Medium",
    "entityMappings": [
      {
        "fieldMappings": [
          {
            "identifier": "ResourceId",
            "columnName": "_ResourceId"
          }
        ],
        "entityType": "AzureResource"
      },
      {
        "fieldMappings": [
          {
            "identifier": "Address",
            "columnName": "CallerIPAddress"
          }
        ],
        "entityType": "IP"
      }
    ],
    "enabled": "True",
    "tactics": [
      "Reconnaissance",
      "Discovery"
    ],
    "incidentConfiguration": {
      "groupingConfiguration": {
        "lookbackDuration": "PT5H",
        "matchingMethod": "Selected",
        "groupByCustomDetails": [
          "OperationName",
          "KeyVaultName"
        ],
        "groupByEntities": [
          "AzureResource",
          "IP"
        ],
        "groupByAlertDetails": [
          "DisplayName",
          "Severity"
        ],
        "reopenClosedIncident": "True",
        "enabled": "True"
      },
      "createIncident": "true"
    }
  }
}
#>

# Get Azure Access Token for https://management.azure.com endpoint
$accessToken = Get-AzAccessToken -ResourceTypeName "ResourceManager"
$authHeader = @{
    'Content-Type'  = 'application/json'
    'Authorization' = 'Bearer ' + $accessToken.Token
}
$requestBody = $alert | ConvertTo-Json -Depth 5

$uri = "https://management.azure.com" + $workspaceId `
                                      + "/providers/Microsoft.SecurityInsights/alertRules/" `
                                      + $alertRuleId `
                                      + "?api-version=2021-03-01-preview"

$response = Invoke-RestMethod -Uri $uri `
                              -Method PUT `
                              -Headers $authHeader `
                              -Body $requestBody

$response.properties | ConvertTo-Json -Depth 5
