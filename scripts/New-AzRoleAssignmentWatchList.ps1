<#
    .SYNOPSIS
        This script is used to create a new Azure Sentinel Watchlist to monitor Azure Role Assignment.
    .DESCRIPTION
        This script is used to create a new Azure Sentinel Watchlist to monitor Azure Role Assignment. 
        It also exports Azure Role Assignments in your Azure Cloud environment.
    .NOTES
        This script is written with Azure PowerShell Az module.

        File Name     : New-AzRoleAssignmentWatchList.ps1
        Version       : 1.0.0.0
        Author        : AzSec (https://azsec.azurewebsites.net/)
        Prerequisite  : Az 
    
    .EXAMPLE
        New-AzRoleAssignmentWatchList.ps1 -WorkspaceRg azsec-corporate-rg `
                                          -WorkspaceName azsec-shared-workspace `
                                          -WatchListAlias 'role_assignment' `
                                          -Path 'C:\Workspace'
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
        HelpMessage = "The name of your Role Assignment Watchlist",
        Position = 2)]
    [ValidateNotNullOrEmpty()]
    [string]
    $WatchListAlias,

    [Parameter(Mandatory = $true,
              HelpMessage = "Location where the audit report is stored",
              Position = 3)]
    [ValidateNotNullOrEmpty()]
    [string]
    $Path
)

$date = Get-Date -UFormat "%Y_%m_%d_%H%M%S"
$filePath = "$Path\$($WatchListAlias)_$($date).csv"

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
    $authProfile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
    $profileClient = New-Object -TypeName Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient -ArgumentList ($authProfile)
    $token = $profileClient.AcquireAccessToken($context.Subscription.TenantId)
    $authHeader = @{
        'Content-Type'  = 'application/json'
        'Authorization' = 'Bearer ' + $token.AccessToken
    }

    return $authHeader
}

class roleAssignmentObj {
    [Object]$SubscriptionId
    [Object]$SubscriptionName
    [Object]$RoleAssignmentId
    [Object]$Scope
    [Object]$RoleDefinitionName
    [Object]$RoleDefinitionId
    [Object]$ObjectId
    [Object]$ObjectType
    [Object]$DisplayName
    [Object]$SignInName
}

$roleAssignmentCsvReport = @()
$subscriptions = Get-AzSubscription | Where-Object {$_.State -eq "Enabled" }
$roleAssignments = Get-AzRoleAssignment 
foreach ($subscription in $subscriptions) {
    Set-AzContext -SubscriptionId $subscription.Id
    Write-Host -ForegroundColor Green "[-] Start retrieving Role Assignment in subscription:" $subscription.Name
    $roleAssignments = Get-AzRoleAssignment 
    foreach ($roleAssignment in $roleAssignments) {
        $roleAssignmentObj = [roleAssignmentObj]::new()
        $roleAssignmentObj.SubscriptionId = $subscription.Id
        $roleAssignmentObj.SubscriptionName = $subscription.Name
        $roleAssignmentObj.RoleAssignmentId = $roleAssignment.RoleAssignmentId
        $roleAssignmentObj.Scope = $roleAssignment.Scope
        $roleAssignmentObj.RoleDefinitionName = $roleAssignment.RoleDefinitionName
        $roleAssignmentObj.RoleDefinitionId = $roleAssignment.RoleDefinitionId
        $roleAssignmentObj.ObjectId = $roleAssignment.ObjectId
        $roleAssignmentObj.ObjectType = $roleAssignment.ObjectType
        $roleAssignmentObj.DisplayName = $roleAssignment.DisplayName
        $roleAssignmentObj.SignInName = $roleAssignment.SignInName
        $roleAssignmentCsvReport += $roleAssignmentObj
    }
}

$roleAssignmentContent = $roleAssignmentCsvReport | ConvertTo-Csv -NoTypeInformation `
                                                  | Foreach-Object { $_ -replace "`"", "" } `
                                                  | Out-String

$watchListConfig = @{}
$properties = @{
    "displayName" = "$WatchListAlias";
    "provider" = "Microsoft";
    "numberOfLinesToSkip" = "0";
    "itemsSearchKey" = "RoleDefinitionName";
    "rawContent" = "$roleAssignmentContent";
    "contentType" = "text/csv";
    "source" = "Local file";
}
$watchListConfig.Add("properties",$properties)
$requestBody = $watchListConfig | ConvertTo-Json -Depth 10

$authHeader = Get-AzureAccessToken
$uri = "https://management.azure.com" + $workspaceId `
                                      + "/providers/Microsoft.SecurityInsights/watchlists/" `
                                      + "$($WatchListAlias)?api-version=2021-03-01-preview"

$response = Invoke-RestMethod -Uri $uri -Method PUT -Headers $authHeader -Body $requestBody
$response

$roleAssignmentCsvReport | Export-Csv -Path $filePath -NoTypeInformation -Encoding UTF8
Write-Host -ForegroundColor Green "[-] Your Role Assignment Report is: " $filePath