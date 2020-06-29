import requests
import adal
import ast
import logging as logger


def rest_api_call(credentials, url, api_version=None):

    response = dict()

    try:

        headers = {
            'Authorization': 'Bearer {}'.format(
                get_auth_token(credentials)["accessToken"]),
            'Content-Type': 'application/json'
        }

        if api_version is None:
            params = {'api-version': '2019-06-01'}
        else:
            params = {'api-version': api_version}

        response = requests.get(url, headers=headers, params=params).json()

        if response.get("nextLink") not in ["", None]:

            next_response = response
            response_data = response.get("value", [])
            pagination = True

            while pagination:

                headers = {
                    'Authorization': 'Bearer{}'.format(
                        get_auth_token(credentials)["accessToken"]),
                    'Content-Type': 'application/json'
                }

                next_response = requests.get(
                    next_response["nextLink"],
                    headers=headers,
                    params=params
                ).json()

                response_data.extend(next_response.get("value", []))

                if "nextLink" not in next_response:
                    pagination = False

            response = {"value": response_data}

    except Exception as e:
        logger.error(e);
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
        logger.error(e);
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
        logger.error(e);
    finally:
        return token


def get_adal_token(credentials):
    token = ""
    try:
        url = "https://login.microsoftonline.com/{}/oauth2/token".format(credentials['AZURE_TENANT_ID'])

        payload = "grant_type=client_credentials&client_id={}&client_secret={}&resource=https://graph.microsoft.com/".format(credentials['AZURE_CLIENT_ID'],credentials['AZURE_CLIENT_SECRET'])

        headers = {
            'Content-Type': "application/x-www-form-urlencoded",
            'Accept': "*/*",
        }

        response = requests.request("POST", url, data=payload, headers=headers)
        if response.status_code == 200:
            token = ast.literal_eval(response.text)
    except Exception as e:
        logger.error(e);
    finally:
        return token

