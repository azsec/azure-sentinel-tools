<#
    .SYNOPSIS
        This script is used to add Log4J IoC to Microsoft Sentinel Threat Intelligence
    .DESCRIPTION
        This script is used to add Log4J IoC to Microsoft Sentinel Threat Intelligence.
        IoC Source: https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Sample%20Data/Feeds/Log4j_IOC_List.csv
    .NOTES
        This script is written with Azure PowerShell (Az) module.

        File Name     : Add-Log4jIoCs.ps1
        Version       : 1.0.0.0
        Author        : AzSec (https://azsec.azurewebsites.net/)
        Prerequisite  : Az
        Reference     : https://azsec.azurewebsites.net/2021/12/19/bulk-upload-log4shell-ioc-to-microsoft-sentinel-threat-intelligence/

    This script uses from here to create an indicator https://github.com/azsec/azure-sentinel-tools/blob/master/scripts/threat-intelligence/New-AzThreatIntelligenceIndicator.ps1
    More information about Microsoft Sentinel TI API https://azsec.azurewebsites.net/2021/11/25/azure-sentinel-threat-intelligence-api/
    .EXAMPLE
        .\Add-Log4jIoCs.ps1 -WorkspaceRg "azsec-corporate-rg" `
                            -WorkspaceName "azsec-shared-workspace" `
                            -IoCSource "https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Sample%20Data/Feeds/Log4j_IOC_List.csv"
#>

Param(
    [Parameter(Mandatory = $false,
               HelpMessage = "Resource group name of the Log Analytics workspace Azure Sentinel connects to",
               Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string]
    $WorkspaceRg,

    [Parameter(Mandatory = $false,
               HelpMessage = "Name of the Log Analytics workspace Azure Sentinel connects to",
               Position = 1)]
    [ValidateNotNullOrEmpty()]
    [string]
    $WorkspaceName,

    [Parameter(Mandatory = $false,
               HelpMessage = "Name (GUID) of the Indicator",
               Position = 1)]
    [ValidateNotNullOrEmpty()]
    [string]
    $IoCSource
)

$date = Get-Date -UFormat "%Y_%m_%d_%H%M%S"
$fileName = "Log4j_IOC_List_$($date).csv"
$output = "$PSScriptRoot\$fileName"
$wc = New-Object System.Net.WebClient
$wc.DownloadFile($IoCSource, $output)

$iocs = Get-Content $output | Select-Object -Skip 1
foreach ($ioc in $iocs) {
  .\New-AzThreatIntelligenceIndicator.ps1 -WorkspaceRg $WorkspaceRg `
                                          -WorkspaceName $WorkspaceName `
                                          -IndicatorType "ipv4-addr" `
                                          -Pattern "ipv4-addr:value = '$ioc'" `
                                          -IndicatorDisplayName "log4jIoC-$ioc" `
                                          -IndicatorDescription "Log4j IoC" `
                                          -ThreatType "attribution","compromised" `
                                          -IsRevoked "false" `
                                          -Confidence 80 `
                                          -ValidFrom "2021-12-10T00:00:00Z" `
                                          -ValidUntil "2023-12-10T00:00:00Z" `
                                          -CreatedBy "azsec"
}