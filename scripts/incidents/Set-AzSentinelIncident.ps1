<#
    .SYNOPSIS
        This script is used to update an existing Azure Sentinel incident.
    .DESCRIPTION
        This script is used to to update an existing Azure Sentinel incident.
        You may want to assign and label an incident programtically without going to Azure Portal.
    .NOTES
        This script is written with Azure PowerShell (Az) module.

        File Name     : Set-AzSentinelIncident.ps1
        Version       : 1.1.0.0
        Author        : AzSec (https://azsec.azurewebsites.net/)
        Prerequisite  : Az
        Reference     : https://azsec.azurewebsites.net/2020/01/21/update-azure-sentinel-incident-programatically/


        [11/26/2021] Updated script to use latest stable API.
    .EXAMPLE
        .\Set-AzureSentinelIncident.ps1  -WorkspaceRg azsec-corporate-rg `
                                         -WorkspaceName azsec-shared-workspace `
                                         -IncidentId XXXXXXX
                                         -Assignee "linda.chung@azsec.net"
                                         -Label "brute-force", "detection", "asc"
                                         -Severity "High"
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
    $IncidentId,

    [Parameter(Mandatory = $true,
               HelpMessage = "User Principal name of assignee e.g linda.chung@azsec.net",
               Position = 3)]
    [ValidateNotNullOrEmpty()]
    [string]
    $Assignee,

    [Parameter(Mandatory = $true,
               HelpMessage = "Label/Tagging of an incident",
               Position = 4)]
    [ValidateNotNullOrEmpty()]
    [string[]]
    $Label,

    [Parameter(Mandatory = $true,
              HelpMessage = "Severity of an incident",
              Position = 5)]
    [ValidateSet("Informational", "Critical", "High", "Medium", "Low")]
    [string]
    $Severity

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

$response = Invoke-RestMethod -Uri $uri `
                             -Method Get `
                             -Headers $authHeader
$response | ConvertTo-Json
$response.name = $IncidentId
$response.properties.labels = $Label   
$objectId = (Get-AzAdUser -UserPrincipalName $Assignee).Id
$response.properties.owner.objectId = $objectId
$response.properties.severity = $Severity
$reguestBody = $response | ConvertTo-Json

$updateUri = "https://management.azure.com" + $workspaceId `
                                            + "/providers/Microsoft.SecurityInsights/2021-04-01/" `
                                            + $IncidentId `
                                            + "?api-version=2021-04-01"
$r = Invoke-RestMethod -Uri $updateUri `
                       -Method PUT `
                       -Headers $authHeader `
                       -Body $reguestBody
$r
