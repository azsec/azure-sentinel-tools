<#
    .SYNOPSIS
        This script is used to create a custom Azure Sentinel incident.
    .DESCRIPTION
        This script is used to create a custom Azure Sentinel incident that you may need in order to test your own SOAR solution.
    .NOTES
        This script is written with Azure PowerShell (Az) module.

        File Name     : New-AzSentinelIncident.ps1
        Version       : 1.1.0.0
        Author        : AzSec (https://azsec.azurewebsites.net/)
        Prerequisite  : Az
        Reference     : https://azsec.azurewebsites.net/2020/01/06/create-a-fully-customized-azure-sentinel-incident/
        
        [11/26/2021] Updated script to use latest stable API. Supported custom parameters.
        
    .EXAMPLE
        .\New-AzSentinelIncident.ps1 -WorkspaceRg azsec-corporate-rg `
                                     -WorkspaceName azsec-shared-workspace `
                                     -IncidentTile "New Incident" `
                                     -IncidentDescription "Test Incident" `
                                     -IncidentSeverity "Informational" `
                                     -IncidentStatus "active" `
                                     -IncidentOwner "5487dc0c-7765-421c-ad9a-60b81e6f0a83" `
                                     -LabelName "SSH" `
                                     -FirstActivityTime "2021-11-27T00:00:00Z" `
                                     -LastActivityTime "2021-11-27T00:00:00Z" `
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
               HelpMessage = "The title of the incident",
               Position = 2)]
    [ValidateNotNullOrEmpty()]
    [string]
    $IncidentTile,

    [Parameter(Mandatory = $true,
               HelpMessage = "The description of the incident",
               Position = 3)]
    [ValidateNotNullOrEmpty()]
    [string]
    $IncidentDescription,

    [Parameter(Mandatory = $true,
               HelpMessage = "The title of the incident",
               Position = 4)]
    [ValidateSet("High",
                 "Medium",
                 "Low",
                 "Informational")]
    [string]
    $IncidentSeverity,

    [Parameter(Mandatory = $true,
               HelpMessage = "The title of the incident",
               Position = 5)]
    [ValidateSet("New",
                 "Active",
                 "Closed")]
    [string]
    $IncidentStatus,

    [Parameter(Mandatory = $true,
               HelpMessage = "The owner of the incident",
               Position = 6)]
    [ValidateNotNullOrEmpty()]
    [string]
    $IncidentOwnerObjectId,

    [Parameter(Mandatory = $true,
               HelpMessage = "The label of the incident",
               Position = 7)]
    [ValidateNotNullOrEmpty()]
    [string]
    $LabelName,


    [Parameter(Mandatory = $true,
               HelpMessage = "The date time (UTC) of the first activity of the incident",
               Position = 8)]
    [ValidateNotNullOrEmpty()]
    [string]
    $FirstActivityTime,

    [Parameter(Mandatory = $true,
               HelpMessage = "The date time (UTC) of the last activity of the incident",
               Position = 9)]
    [ValidateNotNullOrEmpty()]
    [string]
    $LastActivityTime
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

# The name of Incident is a global unique ID (GUID)
$incidentName = (New-Guid).Guid
$incident = [ordered]@{
    name = $incidentName
    properties = @{
        title = $IncidentTile
        description = $IncidentDescription
        owner = @{
            objectId = $IncidentOwner
        }
        labels = @(
            @{
                labelName = $LabelName
                labelType = "User"
            }
        )
        status = $IncidentStatus
        severity = $IncidentSeverity
        firstActivityTimeUtc = $FirstActivityTime
        lastActivityTimeUtc = $LastActivityTime
    }
}

# Sample Request Body
##########################################################
# {
#     "name": "e5f4ec2c-53ec-4fe8-9590-64bc0a78dd97",
#     "properties": {
#         "owner": {
#             "objectId": null
#         },
#         "labels": [
#             {
#                 "labelName": "SSH",
#                 "labelType": "User"
#             }
#         ],
#         "title": "New Incident",
#         "description": "Test Incident",
#         "status": "active",
#         "severity": "Informational",
#         "firstActivityTimeUtc": "2021-11-27T00:00:00Z",
#         "lastActivityTimeUtc": "2021-11-27T00:00:00Z"
#     }
# }
############################################################

$requestBody = $incident | ConvertTo-Json -Depth 3
$uri = "https://management.azure.com" + $workspaceId `
                                      + "/providers/Microsoft.SecurityInsights/incidents/" `
                                      + $incidentName `
                                      + "?api-version=2021-04-01"


$response = Invoke-RestMethod -Uri $uri `
                              -Method PUT `
                              -Headers $authHeader `
                              -Body $requestBody

$response.properties

