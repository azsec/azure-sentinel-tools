<#
    .SYNOPSIS
        This script is used to create a new Azure Sentinel Watchlist to monitor Azure Role Assignment.
    .DESCRIPTION
        This script is used to create a new Azure Sentinel Watchlist to monitor Azure Role Assignment. 
        It also exports Azure Role Assignments in your Azure Cloud environment.
    .NOTES
        This script is written with Azure PowerShell Az module.

        File Name     : New-AzRoleAssignmentWatchList.ps1
        Version       : 1.1.0.0
        Author        : AzSec (https://azsec.azurewebsites.net/)
        Prerequisite  : Az
        Reference     : https://azsec.azurewebsites.net/2021/07/13/create-an-azure-role-assignment-watchlist-in-azure-sentinel/

        [11/26/2021] Updated script to use latest stable API.
    
    .EXAMPLE
        New-AzRoleAssignmentWatchList.ps1 -TargetSubscriptionId 'XXXX-XX-XX'
                                          -WorkspaceRg azsec-corporate-rg `
                                          -WorkspaceName azsec-shared-workspace `
                                          -WatchListAlias 'role_assignment' `
                                          -Path 'C:\Workspace'
#>

Param(
    [Parameter(Mandatory = $true,
               HelpMessage = "The ID of the subscription of the target Azure Sentinel",
               Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string]
    $TargetSubscriptionId,

    [Parameter(Mandatory = $true,
               HelpMessage = "Resource group name of the Log Analytics workspace Azure Sentinel connects to",
               Position = 1)]
    [ValidateNotNullOrEmpty()]
    [string]
    $WorkspaceRg,

    [Parameter(Mandatory = $true,
               HelpMessage = "Name of the Log Analytics workspace Azure Sentinel connects to",
               Position = 2)]
    [ValidateNotNullOrEmpty()]
    [string]
    $WorkspaceName,

    [Parameter(Mandatory = $true,
               HelpMessage = "The name of your Role Assignment Watchlist",
               Position = 3)]
    [ValidateNotNullOrEmpty()]
    [string]
    $WatchListAlias,

    [Parameter(Mandatory = $true,
               HelpMessage = "Location where the audit report is stored",
               Position = 4)]
    [ValidateNotNullOrEmpty()]
    [string]
    $Path
)

$date = Get-Date -UFormat "%Y_%m_%d_%H%M%S"
$filePath = "$Path\$($WatchListAlias)_$($date).csv"

$context = Set-AzContext -SubscriptionId $TargetSubscriptionId
if ($context) {
    Write-Host -ForegroundColor Green "[-] Logged into the target subscription succesfully"
    $workspaceId = (Get-AzOperationalInsightsWorkspace -Name $WorkspaceName `
                                                       -ResourceGroupName $WorkspaceRg).ResourceId
    if (!$workspaceId) {
        throw "[!] Workspace cannot be found. Please try again"
    }
    else {
        Write-Host -ForegroundColor Green "[-] Your Azure Sentinel is connected to workspace: $WorkspaceName"
    }
}
else {
    throw "Target can't be found"
}

# Get Azure Access Token for https://management.azure.com endpoint
$accessToken = Get-AzAccessToken -ResourceTypeName "ResourceManager"
$authHeader = @{
    'Content-Type'  = 'application/json'
    'Authorization' = 'Bearer ' + $accessToken.Token
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
$subscriptions = Get-AzSubscription | Where-Object { $_.State -eq "Enabled" }
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
    "displayName"         = "$WatchListAlias";
    "provider"            = "Microsoft";
    "numberOfLinesToSkip" = "0";
    "itemsSearchKey"      = "RoleDefinitionName";
    "contentType"         = "text/csv";
    "rawContent"          = "$roleAssignmentContent";
    "source"              = "Local file";
}

<# If you want to use file in your location computer use the following code:

$path = "C:\Workspace\azsec_role_assignment_2021_07_12_213000.csv"
$watchListConfig = @{}
$properties = @{
    "displayName"         = "$WatchListAlias";
    "provider"            = "Microsoft";
    "numberOfLinesToSkip" = "0";
    "itemsSearchKey"      = "RoleDefinitionName";
    "source"              = "$path";
}
#>

$watchListConfig.Add("properties", $properties)
$requestBody = $watchListConfig | ConvertTo-Json -Depth 10

$uri = "https://management.azure.com" + $workspaceId `
                                      + "/providers/Microsoft.SecurityInsights/watchlists/" `
                                      + "$($WatchListAlias)" `
                                      + "?api-version=2021-04-01"

$response = Invoke-RestMethod -Uri $uri -Method PUT -Headers $authHeader -Body $requestBody
$response

$roleAssignmentCsvReport | Export-Csv -Path $filePath -NoTypeInformation -Encoding UTF8
Write-Host -ForegroundColor Green "[-] Your Role Assignment Report is: " $filePath
