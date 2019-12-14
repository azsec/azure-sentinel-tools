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
    Write-Host -ForegroundColor Red "[!] Workspace cannot be found. Please try again"
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
    $authHeader = Get-AzureAccessToken
    $connectorName = $subscriptionId
    if ($status -eq $true) {
        Write-Host -ForegroundColor Green "[-] Connecting ASC to Azure Sentinel is going to be started"
        $requestBody = New-ConnectorConfiguration -SubscriptionId $subscriptionId | ConvertTo-Json -Depth 4
        $uri = "https://management.azure.com" + $workspaceId + "/providers/Microsoft.SecurityInsights/dataConnectors/" + $connectorName + "?api-version=2019-01-01-preview"
        $response = Invoke-WebRequest -Uri $uri -Method Put -Headers $authHeader -Body $requestBody
        if ($response.StatusCode -eq "200") {
            Write-Host -ForegroundColor Yellow "[-] Succesfully connected ASC in subscription: $subscriptionId to Azure Sentinel"
        }
        else {
            Write-Host -ForegroundColor Red "[!] Failed to connect to Azure Sentinel"
        }
    }
}
