<#
    .SYNOPSIS
        This script is used to update multiple Azure Sentinel incidents by Alert Display Name
    .DESCRIPTION
        This script is used to update multiple Azure Sentinel incidents by Alert Display Name
        You may want to assign and label multiple Azure Sentinel incidents programtically without going to Azure Portal.
    .NOTES
        This script is written with Azure PowerShell (Az) module.

        File Name     : Update-MultipleAzIncident.ps1
        Version       : 1.0.0.0
        Author        : AzSec (https://azsec.azurewebsites.net/)
        Prerequisite  : Az
        Reference     : https://azsec.azurewebsites.net/2020/01/21/update-azure-sentinel-incident-programatically/
    .EXAMPLE
        .\Update-MultipleAzSentinelIncidents.ps1  -WorkspaceRg azsec-corporate-rg `
                                                  -WorkspaceName azsec-shared-workspace `
                                                  -AlertDisplayName "Suspicious authentication activity"
                                                  -Assignee "linda.chung@azsec.net"
                                                  -Label "authentication", "detection", "asc"
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
    $WorkspaceName,Id

    [Parameter(Mandatory = $true,
               HelpMessage = "Alert Display Name to filter",
               Position = 2)]
    [ValidateNotNullOrEmpty()]
    [string]
    $AlertDisplayName,

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
    Write-Host -ForegroundColor Red "[!] Workspace cannot be found. Please try again"
}
else {
    Write-Host -ForegroundColor Green "[-] Your Azure Sentinel is connected to workspace: $WorkspaceName"
}

function New-AuthHeader {
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


$authHeader = New-AuthHeader
$uri = "https://management.azure.com" + $workspaceId `
                                      + "/providers/Microsoft.SecurityInsights/cases/" `
                                      + "/?api-version=2019-01-01-preview"

$response = Invoke-RestMethod -Uri $uri `
                              -Method Get `
                              -Headers $authHeader

$icds = $response.value | Where-Object {$_.properties.title -eq $AlertDisplayName }

foreach ($icd in $icds) {
    $icd.properties.labels = $Label
    $objectId = (Get-AzAdUser -UserPrincipalName $Assignee).Id
    $icd.properties.owner.objectId = $objectId
    $icd.properties.severity = $Severity
    $reguestBody = $icd | ConvertTo-Json
    
    $updateUri = "https://management.azure.com" + $workspaceId `
                                                + "/providers/Microsoft.SecurityInsights/cases/" `
                                                + $icd.name `
                                                + "?api-version=2019-01-01-preview"
    $r = Invoke-RestMethod -Uri $updateUri `
                           -Method PUT `
                           -Headers $authHeader `
                           -Body $reguestBody
    $r   
}
