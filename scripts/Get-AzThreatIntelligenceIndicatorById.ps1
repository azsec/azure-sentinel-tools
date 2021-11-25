<#
    .SYNOPSIS
        This script is used to get a custom Threat Intelligence (TI) Indicators by Name in your Azure Sentinel.
    .DESCRIPTION
        This script is used to get a custom Threat Intelligence (TI) Indicators by Name in your Azure Sentinel.
    .NOTES
        This script is written with Azure PowerShell (Az) module.

        File Name     : Get-AzThreatIntelligenceIndicatorById.ps1
        Version       : 1.0.0.0
        Author        : AzSec (https://azsec.azurewebsites.net/)
        Prerequisite  : Az
    .EXAMPLE
        .\Get-AzThreatIntelligenceIndicatorById.ps1 -WorkspaceRg "azsec-corporate-rg" `
                                                    -WorkspaceName "azsec-shared-workspace" `
                                                    -IndicatorName "6a36e7f1-20ee-39f2-958d-90a6994188d"
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
    $WorkspaceName,

    [Parameter(Mandatory = $true,
               HelpMessage = "Name (GUID) of the Indicator",
               Position = 1)]
    [ValidateNotNullOrEmpty()]
    [string]
    $IndicatorName
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
                                      + "/providers/Microsoft.SecurityInsights/ThreatIntelligence/" `
                                      + $IndicatorName `
                                      + "?api-version=2021-04-01"

$response = Invoke-RestMethod -Uri $uri `
                              -Method Get `
                              -Headers $authHeader
$response