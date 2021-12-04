<#
    .SYNOPSIS
        This script is used to migrate alert rules to another Azure Sentinel in the same Azure tenant.
    
    .DESCRIPTION
        This script is used to migrate alert rules to another Azure Sentinel in the same Azure tenant.
    .NOTES
        This script is written with Azure PowerShell (Az) module.

        File Name     : Move-AzSentinelAlertRules.ps1
        Version       : 1.1.0.0
        Author        : AzSec (https://azsec.azurewebsites.net/)
        Prerequisite  : Az
        Reference     : https://azsec.azurewebsites.net/2021/11/27/migrate-alert-rules-to-another-azure-sentinel-in-the-same-tenant/

    [12/04/2021] Use this script to migrate an alert rule with custom entity mapping, custom details and incident grouping configuration
    (https://github.com/azsec/azure-sentinel-tools/blob/master/scripts/migration/Move-AzSentinelAlertRulesV2.ps1)
    
    This script uses API version 2020-01-01 which doesn't support getting full alert rule object. 
    There are several unsupported fields from this API version such as custom details, entity mappings and new incident grouping configuration.
    Use this script to quickly copy alert rule to another Sentinel to test. You will need to manually update incident grouping configuration and custom mapping.
    Stay tuned for another script to fully copy.

    .PARAMETER SrcWorkspaceResourceId
        The resource id of the source Log analytics workspace where Azure Sentinel is connected to
    .PARAMETER DstWorkspaceResourceId
        The resource id of the destination Log analytics workspace where Azure Sentinel is connected to
    .EXAMPLE
        .\Move-AzSentinelAlertRules.ps1  -SrcWorkspaceResourceId  "{resource_id}" `
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


$srcSubscriptionId =  $SrcWorkspaceResourceId.Split('/')[2]
$srcResourceGroupName = $SrcWorkspaceResourceId.Split('/')[4]
$srcWorkspaceName = $SrcWorkspaceResourceId.Split('/')[8]

$dstSubscriptionId = $DstWorkspaceResourceId.Split('/')[2]
$dstResourceGroupName = $DstWorkspaceResourceId.Split('/')[4]
$dstWorkspaceName = $DstWorkspaceResourceId.Split('/')[8]

function Get-ScheduledAnalyticsRule {
    Write-Host -ForegroundColor Green "[-] Set Subscription Context before retrieving alert rules...."
    $context = Set-AzContext -SubscriptionId $srcSubscriptionId
    if ($context){
        $srcWorkspace = Get-AzOperationalInsightsWorkspace -Name $srcWorkspaceName -ResourceGroupName $srcResourceGroupName
        if ($srcWorkspace) {
            Write-Host -ForegroundColor Green "[-] Found the workspace named: " $srcWorkspace.Name
            Write-Host -ForegroundColor Green "[-] Start retrieving alert rules...."
            $alertRules = Get-AzSentinelAlertRule -ResourceGroupName $srcResourceGroupName -WorkspaceName $srcWorkspaceName | Where-Object {$_.Kind -eq 'Scheduled' }
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

$alertRules = Get-ScheduledAnalyticsRule 

# Switch to destination subscription if not the same
if ($dstSubscriptionId -ne $srcSubscriptionId) {
    Set-AzContext -SubscriptionId $dstSubscriptionId
}

$dstWorkspace = Get-AzOperationalInsightsWorkspace -Name $dstWorkspaceName -ResourceGroupName $dstResourceGroupName
if ($dstWorkspace) {
    Write-Host -ForegroundColor Blue "[-] Start retrieving rules...."
    $SentinelConnection = @{
        ResourceGroupName = $dstResourceGroupName
        WorkspaceName = $dstWorkspaceName
    }
    foreach ($alertRule in $alertRules) {
        Write-Host -ForegroundColor Green "Found a rule named: $($alertRule.DisplayName)"
    
        # Not all the analytics rules have description defined. 
        # For example, the built-in one named Encoded Invoke-WebRequest PowerShell doesn't have description.
        if ($($alertRule.Description)) {
            $alertDescription = $($alertRule.Description)
        }
        else {
            $alertDescription = "TBD"
        }
    
        # Not all the analytics rules have tactic defined. 
        # For example, the built-in one named Encoded Invoke-WebRequest PowerShell doesn't have Tactics.
        # Temporarily set tactic
        if ($($alertRule.Tactics)) {
            [Collections.Generic.List[String]]$alertTactics = $($alertRule.Tactics)
        }
        else {
            Write-Host -ForegroundColor Yellow "`t[-] Rule $($alertRule.DisplayName) doesn't have description"
            Write-Host -ForegroundColor Yellow "`t[-] Set Discovery as a tactic temporarily"
            [Collections.Generic.List[String]]$alertTactics = "Discovery"
        }
        $alertRuleObject = @{
            Scheduled = $true
            Enabled = $alertRule.Enabled
            Query = $alertRule.Query
            DisplayName = $alertRule.DisplayName
            Description = $alertDescription
            QueryPeriod = $alertRule.QueryPeriod
            QueryFrequency = $alertRule.QueryFrequency
            TriggerThreshold = $alertRule.TriggerThreshold
            TriggerOperator = $alertRule.TriggerOperator
            Severity = $alertRule.Severity
            Tactic = $alertTactics
        }
        Write-Host -ForegroundColor Yellow "`t[-] Start migrating rules named: $($alertRule.DisplayName)"  
        $rule = New-AzSentinelAlertRule @SentinelConnection @alertRuleObject
        if ($rule){
            Write-Host -ForegroundColor Green "`t[-] Succesfully migrated rule named: $($alertRule.DisplayName)"
        }
        else {
            Write-Host -ForegroundColor Red "`t[!] Failed to migrate rule named: $($alertRule.DisplayName)"
        }
    }
}
else {
    throw "[!] Destination Workspace could not be found. Please try again!"
}
