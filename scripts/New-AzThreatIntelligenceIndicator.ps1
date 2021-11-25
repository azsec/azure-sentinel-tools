<#
    .SYNOPSIS
        This script is used to create a custom Threat Intelligence (TI) indicator in Azure Sentinel.
    .DESCRIPTION
        Use this script as a reference for Azure Sentinel REST API for TI indicator operation. 
        You may need to import indicators from a 3rd TI system to Azure Sentinel.
    .NOTES
        This script is written with Azure PowerShell (Az) module.

        File Name     : New-AzThreatIntelligenceIndicator.ps1
        Version       : 1.0.0.0
        Author        : AzSec (https://azsec.azurewebsites.net/)
        Prerequisite  : Az
        Reference     : https://azsec.azurewebsites.net/2021/11/25/azure-sentinel-threat-intelligence-api/
    .PARAMETER WorkspaceRg
        The resource group name of the Log Analytics workspace Azure Sentinel connects to.
    .PARAMETER WorkspaceName
        The name of the Log Analytics workspace Azure Sentinel connects to.
    .PARAMETER IndicatorType
        The type of the indicator. 
        Supported values:
         - url
         - ipv4-addr
         - ipv6-addr
         - file
         - domain
    .PARAMETER Pattern
        The pattern of the indicator
        # | type      | pattern           | sample value                                                  |
        # | --------- | ----------------- | ------------------------------------------------------------- |
        # | url       | url:value         | url:value = 'http://contoso.com'                              |
        # | ipv4-addr | ipv4-addr:value   | ipv4-addr:value = '195.133.20.78'                             |
        # | ipv6-addr | ipv6-addr:value   | ipv6-addr:value = 'FE80:0202:B3FF:FE1E:8329'                  |
        # | file      | file:hashes.      | file:hashes.'SHA-256' = '279D7A3C1CCA7D3C786154ACB40XXXXXXX7' |
        # | domain    | domain-name:value | domain-name:value = 'sampledomain.com'                        |        
    .PARAMETER IndicatorDisplayName
        The display name of the indicator
    .PARAMETER IndicatorDescription
        The description of the indicator
    .PARAMETER ThreatType
        The threat type of the indicator.
        Supported values:
         - malicious-activity
         - attribution
         - compromised
         - anonymization
         - benign
         - anomalous-activity
         - unknown
    .PARAMETER IsRevoked
        Indicate whether the indicator is revoked
    .PARAMETER Confidence
        The confidence of the indicator
    .PARAMETER ValidFrom
        Date and time the indicator is valid From. 
        Valid format is +%Y-%m-%dT%H:%M:%S.000Z
    .PARAMETER ValidUntil
        Date and time the indicator is valid Until.
        Valid format is +%Y-%m-%dT%H:%M:%S.000Z
    .EXAMPLE
        .\New-AzThreatIntelligenceIndicator.ps1 -WorkspaceRg "azsec-corporate-rg" `
                                                -WorkspaceName "azsec-shared-workspace" `
                                                -IndicatorType "ipv4-addr" `
                                                -Pattern "ipv4-addr:value = '195.133.20.11'" `
                                                -IndicatorDisplayName "ip-0001-195.133.20.11" `
                                                -IndicatorDescription "Bad IP from country X" `
                                                -ThreatType "attribution","compromised" `
                                                -IsRevoked "false" `
                                                -Confidence 80 `
                                                -ValidFrom "2021-11-27T00:00:00Z" `
                                                -ValidUntil "2022-11-27T00:00:00Z" `
                                                -CreatedBy "azsec"
#>


Param(
    [Parameter(Mandatory = $true,
               HelpMessage = "The resource group name of the Log Analytics workspace Azure Sentinel connects to",
               Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string]
    $WorkspaceRg,

    [Parameter(Mandatory = $true,
               HelpMessage = "The name of the Log Analytics workspace Azure Sentinel connects to",
               Position = 1)]
    [ValidateNotNullOrEmpty()]
    [string]
    $WorkspaceName,

    [Parameter(Mandatory = $true,
               HelpMessage = "The type of the indicator",
               Position = 2)]
    [ValidateSet("url",
                "ipv4-addr",
                "ipv6-addr",
                "file",
                "domain")]
    [string]
    $IndicatorType,

    [Parameter(Mandatory = $true,
               HelpMessage = "The pattern of the indicator",
               Position = 3)]
        [ValidateNotNullOrEmpty()]
    [string]
    $Pattern,

    [Parameter(Mandatory = $true,
               HelpMessage = "The display name of the indicator",
               Position = 4)]
    [ValidateNotNullOrEmpty()]
    [String]
    $IndicatorDisplayName,
    
    [Parameter(Mandatory = $true,
               HelpMessage = "The description of the indicator",
               Position = 5)]
    [ValidateNotNullOrEmpty()]
    [String]
    $IndicatorDescription,

    [Parameter(Mandatory = $true,
               HelpMessage = "The threat type of the indicator",
               Position = 6)]
    [ValidateSet("malicious-activity",
                 "attribution",
                 "compromised",
                 "anonymization",
                 "benign",
                 "anomalous-activity",
                 "unknown")]
    [String[]]
    $ThreatType,

    [Parameter(Mandatory = $true,
               HelpMessage = "Indicate whether the indicator is revoked",
               Position = 7)]
    [ValidateSet("true", "false")]
    [String]
    $IsRevoked,

    [Parameter(Mandatory = $true,
               HelpMessage = "The confidence of the indicator",
               Position = 8)]
    [ValidateRange(0,100)]
    [Int]
    $Confidence,

    [Parameter(Mandatory = $true,
               HelpMessage = "Date and time the indicator is valid From",
               Position = 9)]
    [ValidateNotNullOrEmpty()]
    [String]
    $ValidFrom,

    [Parameter(Mandatory = $true,
               HelpMessage = "Date and time the indicator is valid Until",
               Position = 10)]
    [ValidateNotNullOrEmpty()]
    [String]
    $ValidUntil,

    [Parameter(Mandatory = $true,
               HelpMessage = "The creator of the indicator",
               Position = 11)]
    [ValidateNotNullOrEmpty()]
    [String]
    $CreatedBy
)

# Verify Azure Sentinel Workspace
$workspaceId = (Get-AzOperationalInsightsWorkspace -Name $WorkspaceName `
                                                   -ResourceGroupName $WorkspaceRg).ResourceId
if (!$workspaceId) {
    Write-Host -ForegroundColor Red "[!] Workspace cannot be found. Please try again"
}
else {
    Write-Host -ForegroundColor Green "[-] Your Azure Sentinel is connected to workspace: $WorkspaceName"
}

# Get Azure Access Token for https://management.azure.com endpoint
$accessToken = Get-AzAccessToken -ResourceTypeName "ResourceManager"
$authHeader = @{
    'Content-Type'  = 'application/json'
    'Authorization' = 'Bearer ' + $accessToken.Token
}


# Create an indicator object
$indicatorName = (New-Guid).Guid
$indicator = [ordered]@{
    name = $indicatorName
    kind = "indicator"
    properties = @{
        patternType = $IndicatorType
        source = "Azure Sentinel"
        pattern = "[$Pattern]"
        displayName = $IndicatorDisplayName
        description = $IndicatorDescription
        threatTypes = @(
            $ThreatType
        )
        revoked = $IsRevoked
        confidence = $Confidence
        validFrom = $ValidFrom
        validUntil = $ValidUntil
        createdByRef = $CreatedBy
    }
}

$requestBody = $indicator | ConvertTo-Json -Depth 3

$uri = "https://management.azure.com" + $workspaceId `
                                      + "/providers/Microsoft.SecurityInsights/ThreatIntelligence/main/createIndicator" `
                                      + "?api-version=2021-04-01"

$response = Invoke-RestMethod -Uri $uri `
                              -Method POST `
                              -Headers $authHeader `
                              -Body $requestBody
$response
