<#
    .SYNOPSIS
        This script is used to connect Azure Security Center to Azure Sentinel. 
    .DESCRIPTION
        The script is used to connect Azure Security Center from different subscriptions to a single Azure Sentinel for centralized security operation.
    .NOTES
        This script is written with Azure PowerShell (Az) module.

        File Name     : Connect-AzureSecurityCenter.ps1
        Version       : 1.0.0.0
        Author        : AzSec (https://azsec.azurewebsites.net/)
        Prerequisite  : Az
        Reference     : https://azsec.azurewebsites.net/2019/12/14/connect-azure-security-center-to-azure-sentinel-programatically/
    .PARAMETER WorkspaceRg
        The resource group name of the Log Analytics workspace Azure Sentinel connects to
    .PARAMETER WorkspaceName
        The name of the Log Analytics workspace Azure Sentinel connects to
    .PARAMETER SubscriptionList
        Location path of the subscription list file containing a list of subscriptions.
        Sample format:
        2dd8cb59-ed12-XXXX-a2bc-356c212fbafc
        e90d1736-d456-XXXX-a53b-b4790eef8a35

    .EXAMPLE
        .\Connect-AzureSecurityCenter.ps1 -WorkspaceRg azsec-corporate-rg `
                                          -WorkspaceName azsec-shared-workspace `
                                          -SubscriptionList .\subscription.txt
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
               HelpMessage = "Location path of the subscription list",
               Position = 2)]
    [ValidateNotNullOrEmpty()]
    [string]
    $SubscriptionList
)


$workspaceId = (Get-AzOperationalInsightsWorkspace -Name $WorkspaceName `
                                                   -ResourceGroupName $WorkspaceRg).ResourceId
if (!$workspaceId) {
    throw "[!] Workspace cannot be found. Please try again"
}
else {
    Write-Host -ForegroundColor Green "[-] Your Azure Sentinel is connected to workspace: $WorkspaceName"
}

function Get-SubscriptionList {
    Param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $SubscriptionList
    )
    
    $list = Get-Content -Path $SubscriptionList
    return $list
}

# Get Azure Access Token for https://management.azure.com endpoint
$accessToken = Get-AzAccessToken -ResourceTypeName "ResourceManager"
$authHeader = @{
    'Content-Type'  = 'application/json'
    'Authorization' = 'Bearer ' + $accessToken.Token
}

function Test-AzureSecurityCenterTier {
    Param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $SubscriptionId
    )
    Write-Host -ForegroundColor Green "[-] Found a subscription Id: $SubscriptionId"
    Set-AzContext -SubscriptionId $SubscriptionId
    $ascTier = Get-AzSecurityPricing
    if ($ascTier.PricingTier -contains "Standard") {
        Write-Host -ForegroundColor Green "[-] Your ASC is ready to be connected to Azure Sentinel"
        return $true
    }
    else {
        Write-Host -ForegroundColor Red "[!] Your ASC is not Standard tier. Please enable Standard tier first!"
    }
}

function New-ConnectorConfiguration {

    Param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $SubscriptionId
    )
        $connnectorCfg = [PSCustomObject]@{
            name = $SubscriptionId
            etag = (New-Guid).Guid
            kind = "AzureSecurityCenter"
            properties = @{
                SubscriptionId = $SubscriptionId
                dataTypes = @{
                    alerts = @{
                        state = "Enabled"
                    }
                }
            }
        }
    return $connnectorCfg
}

$subscriptionsIds = Get-SubscriptionList -SubscriptionList $SubscriptionList
foreach ($subscriptionId in $subscriptionsIds) {
    $status = Test-AzureSecurityCenterTier -SubscriptionId $subscriptionId
    $connectorName = $subscriptionId
    if ($status -eq $true) {
        Write-Host -ForegroundColor Green "[-] Connecting ASC to Azure Sentinel is going to be started"
        $requestBody = New-ConnectorConfiguration -SubscriptionId $subscriptionId | ConvertTo-Json -Depth 4
        $uri = "https://management.azure.com" + $workspaceId `
                                              + "/providers/Microsoft.SecurityInsights/dataConnectors/" `
                                              + $connectorName `
                                              + "?api-version=2020-01-01"
        $response = Invoke-WebRequest -Uri $uri -Method Put -Headers $authHeader -Body $requestBody -UseBasicParsing
        if ($response.StatusCode -eq "200") {
            Write-Host -ForegroundColor Yellow "[-] Succesfully connected ASC in subscription: $subscriptionId to Azure Sentinel"
        }
        else {
            Write-Host -ForegroundColor Red "[!] Failed to connect to Azure Sentinel"
        }
    }
}
