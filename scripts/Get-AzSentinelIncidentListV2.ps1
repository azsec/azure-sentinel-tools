<#
    .SYNOPSIS
        This script is used to extract all Azure Sentinel incidents using a new Azure Sentinel Incident API 2020-01-01
    .DESCRIPTION
        The script is used to extract all Azure Sentinel incidents.The script extracts the following info:
            - Incident ID: this is very important because it shall be used when you need to get specific incident. Name can be similar but this ID is unique.
            - Title: name of that incident
            - Incident number: it is incremental number when an incident is created.
            - Incident severity: severity of an incident (Low, Medium, High, Critical)
            - Status: status of an incident (New, In Progress, Closed)
            - Classification: it is a classification (False Positive, True Positive)
            - Classification Comment: it is formerly Close Reason.
            - Incident label: it is like a tag.
            - Close Reason: a close status (False Positive, True Positive)
            - Owner email: email of the assignee. This field is retrieved from AAD user profile.
            - Assigned To: name of the person who is assigned to work on an incident
            - Time Generated: alert time generated, incident time generated
            - Total comment: it is the total number of comments in each incident.
    .NOTES
        This script is written with Azure PowerShell (Az) module.

        File Name     : Get-AzSentinelIncidentListV2.ps1
        Version       : 1.0.0.4
        Author        : AzSec (https://azsec.azurewebsites.net/)
        Prerequisite  : Az
        Reference     : https://azsec.azurewebsites.net/2020/03/18/quick-look-at-new-azure-sentinel-incident-api/
    .EXAMPLE
        .\Get-AzSentinelIncidentListV2.ps1 -WorkspaceRg azsec-corporate-rg `
                                         -WorkspaceName azsec-shared-workspace `
                                         -FileName 'AzSentinelIncident' `
                                         -Path 'C:\Audit' 
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
              HelpMessage = "File name of the audit report",
              Position = 2)]
    [ValidateNotNullOrEmpty()]
    [string]
    $FileName,

    [Parameter(Mandatory = $true,
              HelpMessage = "Location where the audit report is stored",
              Position = 3)]
    [ValidateNotNullOrEmpty()]
    [string]
    $Path
)



$date = Get-Date -UFormat "%Y_%m_%d_%H%M%S"

$workspaceId = (Get-AzOperationalInsightsWorkspace -Name $WorkspaceName `
                                                   -ResourceGroupName $WorkspaceRg).ResourceId
if (!$workspaceId) {
    Write-Host -ForegroundColor Red "[!] Workspace cannot be found. Please try again"
}
else {
    Write-Host -ForegroundColor Green "[-] Your Azure Sentinel is connected to workspace: $WorkspaceName"
}

class azSentinelIncidentCsv{
    [Object]$IncidentUniqueId
    [Object]$IncidentTile
    [Object]$IncidentNumber
    [Object]$Description
    [Object]$Severity
    [Object]$Status
    [Object]$Label
    [Object]$Classification
    [Object]$ClassificationComment
    [Object]$AssignedTo
    [Object]$OwnerEmail
    [Object]$CreatedTimeUTC
    [Object]$FirstActivityTimeUTC
    [Object]$LastActivityTimeUTC
    [Object]$LastModifiedTimeUTC
    [Object]$FirstActivityTimeGenerated
    [Object]$LastActivityTimeGenerated
    [Object]$AlertProductName
    [Object]$CommentCount
    [Object]$AlertCount
}

$azSentinelIncidentCsvReport = @()
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
$uri = "https://management.azure.com" + $workspaceId + "/providers/Microsoft.SecurityInsights/incidents/?api-version=2020-01-01"
$response = Invoke-RestMethod -Uri $uri -Method GET -Headers $authHeader
$icds = $response.value

while($response.nextLink)
{
    $nextLink = $response.nextLink
    $response = (Invoke-RestMethod -Uri $nextLink -Method GET -Headers $authHeader)
    $icds += $response.value
}

foreach ($icd in $icds) {
    $icdObj = [azSentinelIncidentCsv]::new()
    # Incident Unique ID is important if you want to get specific incident by ID
    $icdObj.IncidentUniqueId = $icd.id.Split('/')[12]
    $icdObj.IncidentTile = $icd.properties.title
    $icdObj.IncidentNumber = $icd.properties.incidentNumber
    $icdObj.Description =  $icd.properties.description
    $icdObj.Severity = $icd.properties.severity
    $icdObj.Status = $icd.properties.status
    $icdObj.Label = $icd.properties.labels.labelName | Out-String
    $icdObj.Classification = $icd.properties.classification
    $icdObj.ClassificationComment = $icd.properties.classificationComment
    $icdObj.AssignedTo = $icd.properties.owner.assignedTo
    $icdObj.OwnerEmail = $icd.properties.owner.email
    $icdObj.CreatedTimeUTC = $icd.properties.createdTimeUtc
    $icdObj.FirstActivityTimeUTC = $icd.properties.firstActivityTimeUTC
    $icdObj.LastActivityTimeUTC = $icd.properties.lastActivityTimeUTC
    $icdObj.LastModifiedTimeUTC = $icd.properties.lastModifiedTimeUTC
    $icdObj.FirstActivityTimeGenerated = $icd.properties.firstActivityTimeGenerated
    $icdObj.LastActivityTimeGenerated = $icd.properties.lastActivityTimeGenerated
    $icdObj.AlertProductName = $icd.properties.additionalData.alertProductNames | Out-string
    $icdObj.CommentCount = $icd.properties.additionalData.commentsCount
    $icdObj.AlertCount = $icd.properties.additionalData.alertsCount
    $azSentinelIncidentCsvReport += $icdObj
}

$azSentinelIncidentCsvReport | Export-Csv -Path "$Path\$($FileName)_$($date).csv" -NoTypeInformation -Encoding UTF8
Write-Host -ForegroundColor Green "[-] YOUR AZURE SENTINEL INCIDENT REPORT IS IN: " $Path\$($FileName)_$($date).csv
