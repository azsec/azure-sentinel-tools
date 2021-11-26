<#
    .SYNOPSIS
        This script is used to get all comments in an Azure Sentinel incident.
    .DESCRIPTION
        This script is used to get all comments in an Azure Sentinel incident.
    .NOTES
        This script is written with Azure PowerShell (Az) module.

        File Name     : Get-AzSentinelIncidentComments.ps1
        Version       : 1.1.0.0
        Author        : AzSec (https://azsec.azurewebsites.net/)
        Prerequisite  : Az
        Reference     : https://azsec.azurewebsites.net/2020/01/27/get-all-comments-in-an-azure-sentinel-incident-programtically/
    .EXAMPLE
        .\Get-AzSentinelIncidentComments    -WorkspaceRg azsec-corporate-rg `
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

# Get Azure Access Token for https://management.azure.com endpoint
$accessToken = Get-AzAccessToken -ResourceTypeName "ResourceManager"
$authHeader = @{
    'Content-Type'  = 'application/json'
    'Authorization' = 'Bearer ' + $accessToken.Token
}

#
$uri = "https://management.azure.com" + $workspaceId `
                                      + "/providers/Microsoft.SecurityInsights/incidents/" `
                                      + $IncidentId `
                                      + "/comments" `
                                      + "?api-version=2021-04-01"


$response = Invoke-RestMethod -Uri $uri `
                              -Method Get `
                              -Headers $authHeader


$response.value | ConvertTo-Json
$comments = $response.value
foreach ($comment in $comments) {
    Write-Host -ForegroundColor Green "[-] User Info:" $comment.properties.userInfo.name
    Write-Host -ForegroundColor Yellow "`t [-] Comment Time Created (UTC):" $comment.properties.createdTimeUtc
    Write-Host -ForegroundColor Yellow "`t [-] Comment:" $comment.properties.message
}
