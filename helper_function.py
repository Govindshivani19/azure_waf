import requests
import adal
import os
import ast
import boto3
import json


def rest_api_call(token, url, api_version=None):
    response = ""
    try:
        headers = {'Authorization': 'Bearer ' + token['accessToken'], 'Content-Type': 'application/json'}
        if api_version is None:
            params = {'api-version': '2019-06-01'}
        else:
            params = {'api-version': api_version}
        response = requests.get(url, headers=headers, params=params)
        response = response.json()
    except Exception as e:
        print(str(e))
    finally:
        return response


def get_auth_token(credentials):
    token = ""
    try:
        tenant = credentials['AZURE_TENANT_ID']
        authority_url = 'https://login.microsoftonline.com/' + tenant
        client_id = credentials['AZURE_CLIENT_ID']
        client_secret = credentials['AZURE_CLIENT_SECRET']
        resource = 'https://management.azure.com/'
        context = adal.AuthenticationContext(authority_url)
        token = context.acquire_token_with_client_credentials(resource, client_id, client_secret)
    except Exception as e:
        print(str(e))
    finally:
        return token


def get_auth_token_services(credentials, az_resource):
    token = ""
    try:
        tenant = credentials['AZURE_TENANT_ID']
        authority_url = 'https://login.microsoftonline.com/' + tenant
        client_id = credentials['AZURE_CLIENT_ID']
        client_secret = credentials['AZURE_CLIENT_SECRET']
        resource = az_resource
        context = adal.AuthenticationContext(authority_url)
        token = context.acquire_token_with_client_credentials(resource, client_id, client_secret)
    except Exception as e:
        print(str(e))
    finally:
        return token


def get_adal_token(credentials):
    token = ""
    try:
        url = "https://login.microsoftonline.com/{}/oauth2/token".format(credentials['AZURE_TENANT_ID'])

        payload = "grant_type=client_credentials&client_id={}&client_secret={}&resource=https://graph.microsoft.com/".format(credentials['AZURE_CLIENT_ID'],credentials['AZURE_CLIENT_SECRET'])

        #url = "https://login.microsoftonline.com/3e53c24a-181d-4e1a-8a6b-93327212e0e6/oauth2/token"
        #payload = "grant_type=client_credentials&client_id=ad558f11-4d0c-4126-b11c-3360156bd181&client_secret=eBD-]CD]U0_vltqrQYvf9Byh693d3TJ9&resource=https://graph.microsoft.com/"

        headers = {
            'Content-Type': "application/x-www-form-urlencoded",
            'Accept': "*/*",
        }

        response = requests.request("POST", url, data=payload, headers=headers)
        if response.status_code == 200:
            token = ast.literal_eval(response.text)
    except Exception as e:
        print(str(e))
    finally:
        return token


def get_application_key(account_hash):
    account_key = ""
    try:
        client_secret = boto3.client('secretsmanager', region_name='us-east-1',
                                     aws_access_key_id=os.environ['access_key'],
                                     aws_secret_access_key=os.environ['secret_key'])
        secret_response = client_secret.get_secret_value(SecretId=account_hash)
        if secret_response:
            response = json.loads(secret_response['SecretString'])
            account_key = response['secret_key']
    except Exception as e:
        print("Error occurred when getting application key. ", str(e))
    return account_key
