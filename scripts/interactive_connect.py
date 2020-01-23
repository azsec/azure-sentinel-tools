"""
This script provides you the way to interactly login to Azure and connect to Azure Log Analytics workspace from kqlmagic.
Secrets are stored in Azure Key Vault as a security practice.
"""

import adal
import requests
import json
 
TENANT_ID = "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXX"
# Azure CLI Client ID - fixed ID
AZURE_CLI_CLIENT_ID = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"
AUTH_URI = "https://login.microsoftonline.com" + "/" + TENANT_ID
SUBSCRIPTION_ID = "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXX"
VAULT_NAME = 'shared-corporate-kv'
JUPITER_CLIENT_ID='XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXX'
KV_SECRET_NAME = 'jupyterClientSecret'
WORKSPACE_ID='XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXX
 
def get_auth_header():
    context = adal.AuthenticationContext(AUTH_URI)
    code = context.acquire_user_code(
        'https://vault.azure.net', AZURE_CLI_CLIENT_ID)
    message = code['message']
    # You must print message
    print(message)
    token = context.acquire_token_with_device_code('https://vault.azure.net',
                                                   code,
                                                   AZURE_CLI_CLIENT_ID)
    authHeader = {
        'Authorization': 'Bearer ' + token['accessToken'],
        'Content-Type': 'application/json'
    }
    return authHeader
 
 
client_id_secret_uri = 'https://' + VAULT_NAME + '.vault.azure.net/secrets/' + \
    KV_SECRET_NAME + '?api-version=7.0'
 
response = requests.get(client_id_secret_uri, headers=(get_auth_header()))
jsonData = response.json()
client_secret = jsonData['value']
 
%reload_ext Kqlmagic
 
%kql loganalytics://tenant=TENANT_ID;clientid=JUPITER_CLIENT_ID;clientsecret=client_secret;workspace=WORKSPACE_ID;alias='azsecdb'
