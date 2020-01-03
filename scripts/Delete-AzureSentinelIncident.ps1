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
        Version       : 1.0.0.0
        Author        : AzSec (https://azsec.azurewebsites.net/)
        Prerequisite  : Az
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
    Write-Host -ForegroundColor Red "[!] Workspace cannot be found. Please try again"
}
else {
    Write-Host -ForegroundColor Green "[-] Your Azure Sentinel is connected to workspace: $WorkspaceName"
}

function Get-AzureAccessToken {
    $context = Get-AzContext
    $profile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
    $profileClient = New-Object -TypeName Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient -ArgumentList ($profile)
    $token = $profileClient.AcquireAccessToken($context.Subscription.TenantId)
    $authHeader = @{
        'Content-Type'  = 'application/json'
        'Authorization' = 'Bearer ' + $token.AccessToken
    }

    return $authHeader
}

$authHeader = Get-AzureAccessToken
$uri = "https://management.azure.com" + $workspaceId + "/providers/Microsoft.SecurityInsights/cases/" + $IncidentId + "/?api-version=2019-01-01-preview"
Invoke-RestMethod -Uri $uri -Method DELETE -Headers $authHeader
