<#
    .SYNOPSIS
        This script is used to delete a specific incident generated from ASC
    .DESCRIPTION
        This script is used to delete a specific incident generated from ASC.
        This is for testing purpose. You shouldn't delete a security incident in a production environment. 
        You can mark an incident as a False Positive case.
    .NOTES
        This script is written with Azure PowerShell (Az) module.

        File Name     : Delete-AzureSentinelIncident.ps1
        Version       : 1.1.0.0
        Author        : AzSec (https://azsec.azurewebsites.net/)
        Prerequisite  : Az
        Reference     : https://azsec.azurewebsites.net/2020/01/03/delete-an-azure-sentinel-incident/

    
        [11/26/2021] Updated script to use latest stable API
    .EXAMPLE
        .\Delete-AzureSentinelIncident.ps1  -WorkspaceRg azsec-corporate-rg `
                                            -WorkspaceName azsec-shared-workspace `
                                            -IncidentId XXXXXXX
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
              HelpMessage = "ID of the incident",
              Position = 2)]
    [ValidateNotNullOrEmpty()]
    [string]
    $IncidentId
)

$workspaceId = (Get-AzOperationalInsightsWorkspace -Name $WorkspaceName `
                                                   -ResourceGroupName $WorkspaceRg).ResourceId
if (!$workspaceId) {
    throw "[!] Workspace cannot be found. Please try again"
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
                                      + "/providers/Microsoft.SecurityInsights/incidents/" `
                                      + $IncidentId `
                                      + "/?api-version=2021-04-01"

Invoke-RestMethod -Uri $uri -Method DELETE -Headers $authHeader
