<#
    .SYNOPSIS
        This script is used to test Microsoft Sentinel GET API.
    .DESCRIPTION
        This script is used to test Microsoft Sentinel GET API.
    .NOTES
        This script is written with Azure PowerShell (Az) module.

        File Name     : Test-AzSentinelGetApi.ps1
        Version       : 1.0.0.0
        Author        : AzSec (https://azsec.azurewebsites.net/)
        Prerequisite  : Az
    
    .PARAMETER WorkspaceResourceId
        The resource Id of the Log Analytics workspace Azure Sentinel connects to
    .PARAMETER ApiType
        The operation type
    .PARAMETER Method
        Method to use.Use GET to get a specific item. Use LIST to get all
    .PARAMETER Id
        The Id of the target entity to retrieve e.g.Alert Id, Incident Id...
    .EXAMPLE
        .\Test-AzSentinelGetApi.ps1 -WorkspaceResourceId "/supscriptions/xxxx...."" `
                                    -ApiType "connector" `
                                    -Method "LIST"
                                    -Id "f232f1d8-5117-4bed-85f7-3b93e9c77d86" `
#>

Param(
    [Parameter(Mandatory = $true,
               HelpMessage = "The resource Id of the Log Analytics workspace Azure Sentinel connects to",
               Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string]
    $WorkspaceResourceId,

    [Parameter(Mandatory = $true,
               HelpMessage = "The operation type",
               Position = 0)]
    [ValidateSet("alert", 
                 "incident",
                 "threat-intelligence",
                 "watchlist",
                 "bookmark",
                 "connector",
                 IgnoreCase = $true)]
    [string]
    $ApiType,

    [Parameter(Mandatory = $true,
               HelpMessage = "Method to use.Use GET to get a specific item. Use LIST to get all",
               Position = 0)]
    [ValidateSet("GET", 
                 "LIST",
                 IgnoreCase = $true)]
    [string]
    $Method,
    
    [Parameter(Mandatory = $false,
               HelpMessage = "The Id of the target entity to retrieve e.g.Alert Id, Incident Id...",
               Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string]
    $Id
)

$resourceGroupName = $WorkspaceResourceId.split('/')[4]
$workspaceName = $WorkspaceResourceId.split('/')[8]


$workspaceId = (Get-AzOperationalInsightsWorkspace -Name $workspaceName `
                                                   -ResourceGroupName $resourceGroupName).ResourceId
if (!$workspaceId) {
    Write-Host -ForegroundColor Red "[!] Workspace cannot be found. Please try again"
}
else {
    Write-Host -ForegroundColor Green "[-] Your Azure Sentinel is connected to workspace: $WorkspaceName"
}

switch ($ApiType) {
    alert {
        Write-Host -ForegroundColor Green "[-] Target API type is: " $ApiType
        $apiName    = "alertRules"
        $apiVersion = "2021-03-01-preview"
    }
    incident {
        Write-Host -ForegroundColor Green "[-] Target API type is: " $ApiType
        $apiName    = "incidents"
        $apiVersion = "2021-04-01"
    }
    threat-intelligence {
        Write-Host -ForegroundColor Green "[-] Target API type is: " $ApiType
        $apiName    = "ThreatIntelligence/main/indicators"
        $apiVersion = "2021-04-01"
    }
    watchlist {
        Write-Host -ForegroundColor Green "[-] Target API type is: " $ApiType
        $apiName    = "watchlists"
        $apiVersion = "2021-04-01"
    }
    bookmarks {
        Write-Host -ForegroundColor Green "[-] Target API type is: " $ApiType
        $apiName    = "bookmarks"
        $apiVersion = "2020-01-01"
    }
    connector {
        Write-Host -ForegroundColor Green "[-] Target API type is: " $ApiType
        $apiName    = "dataConnectors"
        $apiVersion = "2020-01-01"
    }
}

$accessToken = Get-AzAccessToken -ResourceTypeName "ResourceManager"
$authHeader = @{
    'Content-Type'  = 'application/json'
    'Authorization' = 'Bearer ' + $accessToken.Token
}


if ($Method -eq "GET") {
    $uri = "https://management.azure.com" + $workspaceId `
                                          + "/providers/Microsoft.SecurityInsights/" `
                                          + $apiName `
                                          + "/" `
                                          + $Id `
                                          + "?api-version=" `
                                          + $apiVersion
}
else {
    $uri = "https://management.azure.com" + $workspaceId `
                                          + "/providers/Microsoft.SecurityInsights/" `
                                          + $apiName `
                                          + "?api-version=" `
                                          + $apiVersion
}

Write-Host -ForegroundColor Blue "`t[-] Uri: " $uri
$response = Invoke-RestMethod -Uri $uri `
                              -Method GET `
                              -Headers $authHeader
$response | ConvertTo-Json -Depth 5