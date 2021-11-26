# Collection of scripts to support Azure Sentinel operation.

## Incident 

Collection of scripts to support Microsoft Sentinel Incident operation
| **Script**                                                                                  | **Description**                                                                           |
| ------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| [Get-AzSentinelIncidentListV2.ps1](/scripts/incidents/Get-AzSentinelIncidentListV2.ps1)     | This script allows you to export all Azure Sentinel incidents into a friendly CSV report. |
| [New-AzSentinelIncident.ps1](/scripts/incidents/New-AzSentinelIncident.ps1)                 | This script allows you to create a fully-customized incident in Azure Sentinel            |
| [Get-AzSentinelIncidentComments.ps1](/scripts/incidents/Get-AzSentinelIncidentComments.ps1) | This script allows you to extract all comments in an Azure Sentinel incident              |
| [Get-AzSentinelIncidentListV2.ps1](/scripts/incidents/Get-AzSentinelIncidentListV2.ps1)                                                            | This script allows you to export all Azure Sentinel incidents into a friendly CSV report. This script is using a new Incident API |
| [Delete-AzSentinelIncident.ps1](https://github.com/azsec/azure-sentinel-tools/blob/master/scripts/Delete-AzureSentinelIncident.ps1)                | This script allows you to delete an Azure Sentinel incident generated from ASC                                                    |
| [New-AzSentinelIncident.ps1](/scripts/incidents/New-AzSentinelIncident.ps1)                                                                        | This script allows you to create a fully-customized incident in Azure Sentinel                                                    |
| [Set-AzSentinelIncident.ps1](https://github.com/azsec/azure-sentinel-tools/blob/master/scripts/Set-AzSentinelIncident.ps1)                         | This script allows you to update an existing Azure Sentinel incident                                                              |
| [Update-MultipleAzSentinelIncidents.ps1](https://github.com/azsec/azure-sentinel-tools/blob/master/scripts/Update-MultipleAzSentinelIncidents.ps1) | This script allows you to update multiple Azure Sentinel incidents once at a time                                                 |

## Threat Intelligence

Collection of scripts to support Microsoft Sentinel Threat Intelligence Indicator operation
| **Script**                                                                                                                | **Description**                                                                                            |
| ------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| [Get-AzThreatIntelligenceIndicators.ps1](/scripts/Get-AzThreatIntelligenceIndicators.ps1)                                 | This script is used to get all custom Threat Intelligence (TI) Indicators in your Azure Sentinel.          |
| [Get-AzThreatIntelligenceIndicatorById.ps1](/scripts/Get-AzThreatIntelligenceIndicatorById.ps1)                           | This script is used to get a custom Threat Intelligence (TI) Indicators by Name in your Azure Sentinel.    |
| [New-AzThreatIntelligenceIndicator](/scripts/threat-intelligence/New-AzThreatIntelligenceIndicator.ps1)                   | This script is used to create a custom Threat Intelligence (TI) indicator in Microsoft Azure Sentinel      |
| [Delete-AzThreatIntelligenceIndicatorById.ps1](/scripts/threat-intelligence/Delete-AzThreatIntelligenceIndicatorById.ps1) | This script is used to delete a custom Threat Intelligence (TI) Indicators by Name in your Azure Sentinel. |


## Watchlist

Collection of scripts to support Microsoft Sentinel Threat Intelligence Indicator operation
| **Script**                                                                                    | **Description**                                                                                |
| --------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| [New-AzRoleAssignmentWatchList.ps1.ps1](/scripts/watchlist/New-AzRoleAssignmentWatchList.ps1) | This script is used to create a new Azure Sentinel Watchlist to monitor Azure Role Assignment. |


## Connector
Collection of scripts to support Microsoft Sentinel Threat Intelligence Indicator operation
| **Script**                                                                            | **Description**                                                                                                         |
| ------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| [Connect-AzureSecurityCenter.ps1](/scripts/connector/Connect-AzureSecurityCenter.ps1) | This script allows you to connect multiple Azure Security Center from multiple subscriptions to a single Azure Sentinel |

| **Script**                                                                                                                                         | **Usage**                                                                                                                         |
| -------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| [Get-AzSentinelIncidentListV2.ps1](/scripts/incidents/Get-AzSentinelIncidentListV2.ps1)                                                            | This script allows you to export all Azure Sentinel incidents into a friendly CSV report. This script is using a new Incident API |
| [Delete-AzSentinelIncident.ps1](https://github.com/azsec/azure-sentinel-tools/blob/master/scripts/Delete-AzureSentinelIncident.ps1)                | This script allows you to delete an Azure Sentinel incident generated from ASC                                                    |
| [New-AzSentinelIncident.ps1](/scripts/incidents/New-AzSentinelIncident.ps1)                                                                        | This script allows you to create a fully-customized incident in Azure Sentinel                                                    |
| [Set-AzSentinelIncident.ps1](https://github.com/azsec/azure-sentinel-tools/blob/master/scripts/Set-AzSentinelIncident.ps1)                         | This script allows you to update an existing Azure Sentinel incident                                                              |
| [Update-MultipleAzSentinelIncidents.ps1](https://github.com/azsec/azure-sentinel-tools/blob/master/scripts/Update-MultipleAzSentinelIncidents.ps1) | This script allows you to update multiple Azure Sentinel incidents once at a time                                                 |