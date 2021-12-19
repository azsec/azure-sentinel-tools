<#
    .SYNOPSIS
        This script is used to migrate alert rules to another Azure Sentinel in the same Azure tenant.
    
    .DESCRIPTION
        This script is used to migrate alert rules to another Azure Sentinel in the same Azure tenant.
    .NOTES
        This script is written with Azure PowerShell (Az) module.

        File Name     : Move-AzSentinelAlertRulesV2.ps1
        Version       : 1.0.0.0
        Author        : AzSec (https://azsec.azurewebsites.net/)
        Prerequisite  : Az
        Reference     : https://azsec.azurewebsites.net/2021/11/27/migrate-alert-rules-to-another-azure-sentinel-in-the-same-tenant/

    This script uses API version 2021-03-01-preiew (https://azsec.azurewebsites.net/2021/11/28/create-an-alert-with-custom-entity-mapping-using-microsoft-sentinel-rest-api/)

    .PARAMETER SrcWorkspaceResourceId
        The resource id of the source Log analytics workspace where Azure Sentinel is connected to
    .PARAMETER DstWorkspaceResourceId
        The resource id of the destination Log analytics workspace where Azure Sentinel is connected to
    .EXAMPLE
        .\Move-AzSentinelAlertRulesV2.ps1  -SrcWorkspaceResourceId  "{resource_id}" `
                                           -DstWorkspaceResourceId "{resource_id}"
#>


Param(
    [Parameter(Mandatory = $true,
               HelpMessage = "The resource id of the source Log analytics workspace where Azure Sentinel is connected to",
               Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string]
    $SrcWorkspaceResourceId,

    [Parameter(Mandatory = $true,
               HelpMessage = "The resource id of the destination Log analytics workspace where Azure Sentinel is connected to",
               Position = 1)]
    [ValidateNotNullOrEmpty()]
    [string]
    $DstWorkspaceResourceId
)

$srcSubscriptionId = $SrcWorkspaceResourceId.Split('/')[2]
$srcResourceGroupName = $SrcWorkspaceResourceId.Split('/')[4]
$srcWorkspaceName = $SrcWorkspaceResourceId.Split('/')[8]

$dstSubscriptionId = $DstWorkspaceResourceId.Split('/')[2]
$dstResourceGroupName = $DstWorkspaceResourceId.Split('/')[4]
$dstWorkspaceName = $DstWorkspaceResourceId.Split('/')[8]

function Get-ScheduledAnalyticsRule {
    Write-Host -ForegroundColor Green "[-] Set Subscription Context before retrieving alert rules...."
    $context = Set-AzContext -SubscriptionId $srcSubscriptionId
    if ($context) {
        $srcWorkspace = Get-AzOperationalInsightsWorkspace -Name $srcWorkspaceName -ResourceGroupName $srcResourceGroupName
        
        # Get Azure Access Token to use with API
        $accessToken = Get-AzAccessToken -ResourceTypeName "ResourceManager"
        $authHeader = @{
            'Content-Type'  = 'application/json'
            'Authorization' = 'Bearer ' + $accessToken.Token
        }
                
        if ($srcWorkspace) {
            Write-Host -ForegroundColor Green "[-] Found the workspace named: " $srcWorkspace.Name
            Write-Host -ForegroundColor Green "[-] Start retrieving alert rules...."

            $uri = "https://management.azure.com" + $($srcWorkspace.ResourceId) `
                                                  + "/providers/Microsoft.SecurityInsights/alertRules" `
                                                  + "?api-version=2021-03-01-preview"

            $response = Invoke-RestMethod -Uri $uri `
                                          -Method GET `
                                          -Headers $authHeader
            $alertRules = $response.value

            return $alertRules
        }
        else {
            throw "[!] The source Log Analytics Workspace cound not be found"
        }
    }
    else {
        throw "[!] Subcription id $srcSubscriptionId could not be found. Please try again!"
    }
}

# This script supports custom schedule analytics rule.
# Anomaly, fusion, nrt (near real time) and MicrosoftSecurityIncidentCreation are NOT supported.
$alertRules = Get-ScheduledAnalyticsRule | Where-Object {$_.kind -eq "Scheduled" }

# Switch to destination subscription if not the same
if ($dstSubscriptionId -ne $srcSubscriptionId) {
    Write-Host -ForegroundColor Green "[-] Set destined subscription context before retrieving alert rules...."
    Set-AzContext -SubscriptionId $dstSubscriptionId
}

$dstWorkspace = Get-AzOperationalInsightsWorkspace -Name $dstWorkspaceName -ResourceGroupName $dstResourceGroupName

$accessToken = Get-AzAccessToken -ResourceTypeName "ResourceManager"
$authHeader = @{
    'Content-Type'  = 'application/json'
    'Authorization' = 'Bearer ' + $accessToken.Token
}
if ($dstWorkspace) {
    Write-Host -ForegroundColor Green "[-] Found the destined workspace named: " $dstWorkspace.Name
    foreach ($alertRule in $alertRules) {

        # Convert to the right data type to avoid conversion
        [string]$ruleDisplayName = $alertRule.properties.displayName
        [int]$triggerThreshold = $alertRule.properties.triggerThreshold
        [bool]$suppressionEnabled = $alertRule.properties.suppressionEnabled
        [string]$query = $alertRule.properties.query

        Write-Host -ForegroundColor Green "Found a rule named: $ruleDisplayName"

        $alertRuleId = (New-Guid).Guid
        # Create an alert rule object
        $alert = [ordered]@{
            ruleId     = $alertRuleId
            kind       = "Scheduled"
            properties = @{
                displayName           = $ruleDisplayName
                enabled               = $alertRule.properties.enabled
                description           = $alertRule.properties.description
                tactics               = $alertRule.properties.tactics
                suppressionEnabled    = $suppressionEnabled
                suppressionDuration   = $alertRule.properties.suppressionDuration
                query                 = $query
                severity              = $alertRule.properties.severity
                queryFrequency        = $alertRule.properties.queryFrequency
                queryPeriod           = $alertRule.properties.queryPeriod
                triggerOperator       = $alertRule.properties.triggerOperator
                triggerThreshold      = $triggerThreshold
                entityMappings        = $alertRule.properties.entityMappings
                customDetails         = $alertRule.properties.customDetails
                alertDetailsOverride  = $alertRule.properties.alertDetailsOverride
                incidentConfiguration = $alertRule.properties.incidentConfiguration
            }
        }    

        $requestBody = $alert | ConvertTo-Json -Depth 5

        Write-Host -ForegroundColor Yellow "`t[-] Start migrating rules named: $ruleDisplayName"  

        $uri = "https://management.azure.com" + $($dstWorkspace.ResourceId) `
                                            + "/providers/Microsoft.SecurityInsights/alertRules/" `
                                            + $alertRuleId `
                                            + "?api-version=2021-03-01-preview"

        try {
            $response = Invoke-RestMethod -Uri $uri `
                                        -Method PUT `
                                        -Headers $authHeader `
                                        -Body $requestBody 
            Write-Host -ForegroundColor Green "`t[-] Succesfully migrated rule named: $ruleDisplayName"

        } catch {
            Write-Host -ForegroundColor Red "`t[!] StatusCode:" $_.Exception.Response.StatusCode.value__ 
            Write-Host -ForegroundColor Red "`t[!] StatusDescription:" $_.Exception.Response.StatusDescription
            Write-Host -ForegroundColor Red "`t[!] Failed to migrate rule named: $ruleDisplayName"
        }                                 
    }
}
else {
    throw "[!] Destination Workspace could not be found. Please try again!"
}