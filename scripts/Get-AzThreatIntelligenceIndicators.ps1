<#
    .SYNOPSIS
        This script is used to get all custom Threat Intelligence (TI) Indicators in your Azure Sentinel.
    .DESCRIPTION
        SecOps analyst may require a report containing all indicators in Azure Sentinel or use to import to 3rd TI party.
    .NOTES
        This script is written with Azure PowerShell (Az) module.

        File Name     : Get-AzThreatIntelligenceIndicators.ps1
        Version       : 1.0.0.0
        Author        : AzSec (https://azsec.azurewebsites.net/)
        Prerequisite  : Az
    .EXAMPLE
        .\Get-AzThreatIntelligenceIndicators.ps1 -WorkspaceRg azsec-corporate-rg `
                                                 -WorkspaceName azsec-shared-workspace `
#>

Param(
    [Parameter(Mandatory = $true,
              HelpMessage = "Resource group name of the Log Analytics workspace Azure Sentinel connects to",
              Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string]
    $WorkspaceRg,

    [Parameter(Mandatory = $true,
               HelpMessage = "Name of the Log Analytics workspace Azure Sentinel connects to",
               Position = 1)]
    [ValidateNotNullOrEmpty()]
    [string]
    $WorkspaceName
)

$workspaceId = (Get-AzOperationalInsightsWorkspace -Name $WorkspaceName `
                                                   -ResourceGroupName $WorkspaceRg).ResourceId
if (!$workspaceId) {
    Write-Host -ForegroundColor Red "[!] Workspace cannot be found. Please try again"
}
else {
    Write-Host -ForegroundColor Green "[-] Your Azure Sentinel is connected to workspace: $WorkspaceName"
}

$accessToken = Get-AzAccessToken -ResourceTypeName "ResourceManager"
$authHeader = @{
    'Content-Type'  = 'application/json'
    'Authorization' = 'Bearer ' + $accessToken.Token
}

$uri = "https://management.azure.com" + $workspaceId `
                                      + "/providers/Microsoft.SecurityInsights/ThreatIntelligence/main/indicators" `
                                      + "?api-version=2021-04-01"

$response = Invoke-RestMethod -Uri $uri `
                              -Method Get `
                              -Headers $authHeader
$indicators = $response.value
$indicators