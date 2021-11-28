<#
    .SYNOPSIS
        This script is used to get a full Microsoft Sentinel Alert rule including custom entities and incident grouping configuration.
    .DESCRIPTION
        This script is used to get a full Microsoft Sentinel Alert rule including custom entities and incident grouping configuration.
    .NOTES
        This script is written with Azure PowerShell (Az) module.

        File Name     : Get-AzSentinelAlertRuleById.ps1
        Version       : 1.0.0.0
        Author        : AzSec (https://azsec.azurewebsites.net/)
        Prerequisite  : Az
    
    .EXAMPLE
        .\Get-AzSentinelAlertRuleById.ps1 -WorkspaceRg "azsec-corporate-rg" `
                                          -WorkspaceName "azsec-shared-workspace" `
                                          -AlertRuleId "XXXXX-XXXXXX-XXXXXX-XXXXXX"
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
               HelpMessage = "The Id (Name) of the alert rule",
               Position = 2)]
    [ValidateNotNullOrEmpty()]
    [string]
    $AlertRuleId
)

$workspaceId = (Get-AzOperationalInsightsWorkspace -Name $WorkspaceName `
                                                   -ResourceGroupName $WorkspaceRg).ResourceId
if (!$workspaceId) {
    throw  "[!] Workspace cannot be found. Please try again"
}
else {
    Write-Host -ForegroundColor Green "[-] Your Azure Sentinel is connected to workspace: $WorkspaceName"
}

# Get Azure Access Token for https://management.azure.com endpoint
$accessToken = Get-AzAccessToken -ResourceTypeName "ResourceManager"
$authHeader = @{
    'Content-Type'  = 'application/json'
    'Authorization' = 'Bearer ' + $accessToken.Token
}

$uri = "https://management.azure.com" + $workspaceId `
                                      + "/providers/Microsoft.SecurityInsights/alertRules/" `
                                      + $AlertRuleId `
                                      + "?api-version=2021-03-01-preview"

$response = Invoke-RestMethod -Uri $uri `
                              -Method GET `
                              -Headers $authHeader

$response.properties | ConvertTo-Json -Depth 5