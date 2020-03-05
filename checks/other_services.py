from checks.common_services import CommonServices
from helper_function import get_auth_token, rest_api_call, get_auth_token_services
from contants import redis_url, key_vault_list_url, vault_base_url


class AzureServices:
    def __init__(self, credentials):
        self.credentials = credentials

    def redis_secure_connection(self):
        issues = []
        try:
            token = get_auth_token(self.credentials)
            cs = CommonServices()
            subscription_list = cs.get_subscriptions_list(token)
            for subscription in subscription_list:
                redis_list = []
                url = redis_url.format(subscription['subscriptionId'])
                response = rest_api_call(token, url, api_version='2016-04-01')
                for r in response['value']:
                    redis_list.append(r)

                for r in redis_list:
                    temp = dict()
                    if r['properties']['enableNonSslPort']:
                        temp["region"] = r["location"]
                        temp["status"] = "Fail"
                        temp["resource_name"] = r['name']
                        temp["resource_id"] = r['id']
                        temp["problem"] = "Secure Connections to Redis Cache {} in subscription {} is not enabled.".format(
                            r['name'], subscription['subscriptionId'])
                    else:
                        temp["region"] = r["location"]
                        temp["status"] = "Pass"
                        temp["resource_name"] = r['name']
                        temp["resource_id"] = r['id']
                        temp["problem"] = "Secure Connections to Redis Cache {} in subscription {} is enabled.".format(
                            r['name'], subscription['subscriptionId'])

                issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def get_key_expiry_date(self):
        issues = []
        try:
            token = get_auth_token(self.credentials)
            cs = CommonServices()
            subscription_list = cs.get_subscriptions_list(token)
            for subscription in subscription_list:
                vault_list = []
                vault_url = key_vault_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(token, vault_url)
                for r in response['value']:
                    vault_list.append(r)

                for vault in vault_list:
                    vault_name = vault["name"]
                    get_keys = vault_base_url.format(vault_name) + "keys"
                    vault_token = get_auth_token_services(self.credentials, az_resource="https://vault.azure.net")
                    response = rest_api_call(vault_token, get_keys, api_version='7.0')
                    print(response)
        except Exception as e:
            print(str(e))
        finally:
            return issues