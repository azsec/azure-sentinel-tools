# Collection of scripts to support Azure Sentinel operation.

## Alert 

Collection of scripts to support Microsoft Sentinel Alert operation
| **Script**                                                                             | **Description**                                                                                                                                                |
| -------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [New-AzSentinelAlertRule.ps1](/scripts/alert-rule/New-AzSentinelAlertRule.ps1)         | This script allows you to create a scheduled analytics rule including custom entity mapping, custom details, alert format and incident grouping configuration. |
| [Get-AzSentinelAlertRuleById.ps1](/scripts/alert-rule/Get-AzSentinelAlertRuleById.ps1) | This script is used to get a full Microsoft Sentinel Alert rule including custom entities and incident grouping configuration.                                 |

## Incident 

Collection of scripts to support Microsoft Sentinel Incident operation
| **Script**                                                                                          | **Description**                                                                           |
| --------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| [Get-AzSentinelIncidentListV2.ps1](/scripts/incidents/Get-AzSentinelIncidentListV2.ps1)             | This script allows you to export all Azure Sentinel incidents into a friendly CSV report. |
| [New-AzSentinelIncident.ps1](/scripts/incidents/New-AzSentinelIncident.ps1)                         | This script allows you to create a fully-customized incident in Azure Sentinel            |
| [Get-AzSentinelIncidentComments.ps1](/scripts/incidents/Get-AzSentinelIncidentComments.ps1)         | This script allows you to extract all comments in an Azure Sentinel incident              |
| [Delete-AzSentinelIncident.ps1](/scripts/incidents/Delete-AzureSentinelIncident.ps1)                | This script allows you to delete an Azure Sentinel incident generated from ASC            |
| [New-AzSentinelIncident.ps1](/scripts/incidents/New-AzSentinelIncident.ps1)                         | This script allows you to create a fully-customized incident in Azure Sentinel            |
| [Set-AzSentinelIncident.ps1](/scripts/incidents/Set-AzSentinelIncident.ps1)                         | This script allows you to update an existing Azure Sentinel incident                      |
| [Update-MultipleAzSentinelIncidents.ps1](/scripts/incidents/Update-MultipleAzSentinelIncidents.ps1) | This script allows you to update multiple Azure Sentinel incidents once at a time         |

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

## Migration

Collection of scripts to support Microsoft Sentinel migration
| **Script**                                                                            | **Description**                                                                                                                                                       |
| ------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [Move-AzSentinelAlertRules.ps1](/scripts/migration/Move-AzSentinelAlertRules.ps1)     | This script is used to migrate alert rules to another Azure Sentinel in the same Azure tenant.                                                                        |
| [Move-AzSentinelAlertRulesV2.ps1](/scripts/migration/Move-AzSentinelAlertRulesV2.ps1) | This script is used to migrate alert rules with custom entity mapping, details or incident grouping configuration to another Azure Sentinel in the same Azure tenant. |

## Utils

Collection of utility scripts to support Microsoft Sentinel API
| **Script**                                                            | **Description**                                         |
| --------------------------------------------------------------------- | ------------------------------------------------------- |
| [Test-AzSentinelGetApi.ps1](/scripts/utils/Test-AzSentinelGetApi.ps1) | This script is used to test Microsoft Sentinel GET API. |