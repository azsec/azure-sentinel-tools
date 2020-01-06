<#
    .SYNOPSIS
        This script is used to create a custom Azure Sentinel incident.
    .DESCRIPTION
        This script is used to create a custom Azure Sentinel incident that you may need in order to test your own SOAR solution.
    .NOTES
        This script is written with Azure PowerShell (Az) module.

        File Name     : New-AzSentinelIncident.ps1
        Version       : 1.0.0.0
        Author        : AzSec (https://azsec.azurewebsites.net/)
        Prerequisite  : Az
    .EXAMPLE
        .\New-AzSentinelIncident.ps1 -WorkspaceRg azsec-corporate-rg `
                                     -WorkspaceName azsec-shared-workspace `
                                     -IncidentConfigPath C:\AzSentinel\Incident01.json
#>

<#
Sample request body
{
    "properties": {
        "startTimeUtc": "2020-06-01T00:00:00Z",
        "createdTimeUtc": "2020-06-01T00:00:00Z",
        "endTimeUtc": "2020-06-01T00:00:00Z",
        "title": "Your virtual machine is still safe",
        "description": "..then why am I seeing this incident?",
        "owner": {
            "objectId": "b8c7b934-b040-4156-a089-fb344add2d6c",
            "email": "andy@azsec.net",
            "name": "Andy"
        },
        "severity": "High",
        "closeReson": "",
        "status": "New",
        "caseNumber": 1331000000,
        "labels": [
            "sample-incident",
            "test"
        ],
        "relatedAlertIds": [
            "921214ee-beaa-43b5-ab40-0b8b8280511e"
        ]
    },
    "name": "66bd8bac-681a-4caa-8a29-96145e4137fe"
}

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
        HelpMessage = "Incident configuration file ",
        Position = 2)]
    [ValidateNotNullOrEmpty()]
    [string]
    $IncidentConfigPath
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

function Get-IncidentConfig {
    Param(
        [Parameter(Mandatory = $true,
            HelpMessage = "Incident configuration file ",
            Position = 2)]
        [ValidateNotNullOrEmpty()]
        [string]
        $IncidentConfigPath
    )
    $incidentId = (New-Guid).Guid
    $incidentConfig = Get-Content -Path $IncidentConfigPath | ConvertFrom-Json
    $incidentConfig | Add-Member -Type NoteProperty -Name "name" -Value $incidentId -Force
    $incidentConfig | ConvertTo-Json | Set-Content $IncidentConfigPath
    return $incidentConfig
}

$authHeader = Get-AzureAccessToken
$incidentConfig = Get-IncidentConfig -IncidentConfigPath $IncidentConfigPath
$uri = "https://management.azure.com" + $workspaceId + "/providers/Microsoft.SecurityInsights/cases/$($incidentConfig.name)?api-version=2019-01-01-preview"
$uri
$requestBody = $incidentConfig | ConvertTo-Json
$requestBody

$response = Invoke-RestMethod -Uri $uri `
                              -Method PUT `
                              -Headers $authHeader `
                              -Body $requestBody

$response

