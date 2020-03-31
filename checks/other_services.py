from checks.common_services import CommonServices
from helper_function import rest_api_call, get_auth_token_services
from constants import redis_url, key_vault_list_url, vault_base_url, vault_policy_url, monitor_diagnostic_url, \
    certificate_policy_url, issuer_url
from datetime import datetime, timezone, timedelta


class AzureServices:
    def __init__(self, credentials, subscription_list):
        self.credentials = credentials
        self.subscription_list = subscription_list

    def redis_secure_connection(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                redis_list = []
                url = redis_url.format(subscription['subscriptionId'])
                response = rest_api_call(self.credentials, url, api_version='2016-04-01')
                for r in response['value']:
                    redis_list.append(r)

                for r in redis_list:
                    temp = dict()
                    if r['properties']['enableNonSslPort']:
                        temp["region"] = r["location"]
                        temp["status"] = "Fail"
                        temp["resource_name"] = r['name']
                        temp["resource_id"] = r['id']
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]
                    else:
                        temp["region"] = r["location"]
                        temp["status"] = "Pass"
                        temp["resource_name"] = r['name']
                        temp["resource_id"] = r['id']
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]

                issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def get_certificate_expiry(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                vault_list = []
                vault_url = key_vault_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(self.credentials, vault_url)
                for r in response['value']:
                    vault_list.append(r)

                for vault in vault_list:
                    vault_name = vault["name"]
                    # print("vault", vault)

                    get_certificates = vault_base_url.format(vault_name) + "certificates"
                    vault_token = get_auth_token_services(self.credentials, az_resource="https://vault.azure.net")
                    try:
                        certificate_response = rest_api_call(vault_token, get_certificates, api_version='7.0')['value']
                        # print('certificate', response)
                    except Exception as e:
                        continue
                    for each_certificate in certificate_response:
                        # print(each_certificate, each_certificate.keys(), 'cert')
                        date_of_expiry = datetime.fromtimestamp(each_certificate['attributes']['exp'])
                        now = datetime.now()
                        temp = dict()
                        temp["region"] = ""
                        if (date_of_expiry - now).days < 30:
                            temp["status"] = "Fail"
                            temp["resource_name"] = each_certificate['id'].split("/")[-1]
                            temp["resource_id"] = each_certificate['id']
                            temp["subscription_id"] = subscription['subscriptionId']
                            temp["subscription_name"] = subscription["displayName"]
                            temp['value_one'] = (date_of_expiry - now).days
                        else:
                            temp["status"] = "Pass"
                            temp["resource_name"] = each_certificate['id'].split("/")[-1]
                            temp["resource_id"] = each_certificate['id']
                            temp["subscription_id"] = subscription['subscriptionId']
                            temp["subscription_name"] = subscription["displayName"]
                            temp['value_one'] = (date_of_expiry - now).days

                        issues.append(temp)

        except Exception as e:
            print(str(e))
        finally:
            return issues

    def get_RSA_key_size(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                vault_list = []
                vault_url = key_vault_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(self.credentials, vault_url)
                for r in response['value']:
                    vault_list.append(r)

                for vault in vault_list:
                    vault_name = vault["name"]
                    # print("vault", vault)

                    get_certificates = vault_base_url.format(vault_name) + "certificates"
                    vault_token = get_auth_token_services(self.credentials, az_resource="https://vault.azure.net")
                    try:
                        certificate_response = rest_api_call(vault_token, get_certificates, api_version='7.0')['value']
                        # print('certificate', response)
                    except Exception as e:
                        continue
                    for each_certificate in certificate_response:
                        # print(each_certificate, each_certificate.keys(), 'cert')
                        date_of_expiry = datetime.fromtimestamp(each_certificate['attributes']['exp'])
                        now = datetime.now()
                        temp = dict()
                        temp["region"] = ""
                        if (date_of_expiry - now).days < 30:
                            temp["status"] = "Fail"
                            temp["resource_name"] = each_certificate['id'].split("/")[-1]
                            temp["resource_id"] = each_certificate['id']
                            temp["subscription_id"] = subscription['subscriptionId']
                            temp["subscription_name"] = subscription["displayName"]
                            temp['value_one'] = (date_of_expiry - now).days
                        else:
                            temp["status"] = "Pass"
                            temp["resource_name"] = each_certificate['id'].split("/")[-1]
                            temp["resource_id"] = each_certificate['id']
                            temp["subscription_id"] = subscription['subscriptionId']
                            temp["subscription_name"] = subscription["displayName"]
                            temp['value_one'] = (date_of_expiry - now).days

                        issues.append(temp)

        except Exception as e:
            print(str(e))
        finally:
            return issues

    def get_recoverable_objects(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                vault_list = []
                vault_url = key_vault_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(self.credentials, vault_url)
                for r in response['value']:
                    vault_list.append(r)

                for vault in vault_list:
                    vault_name = vault["name"]
                    # print("vault", vault)

                    vault_policy_url = "https://management.azure.com/{}".format(vault['id'])
                    try:
                        vault_response = rest_api_call(self.credentials, vault_policy_url, api_version='2019-09-01')['properties']

                    except Exception as e:
                        print(e)
                        continue

                    temp = dict()
                    temp["region"] = ""
                    if 'enableSoftDelete' in vault_response.keys() and vault_response['enableSoftDelete'] is 'false':

                        temp["status"] = "Fail"
                        temp["resource_name"] = vault['name']
                        temp["resource_id"] = vault['id']
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]
                    else:
                        temp["status"] = "Pass"
                        temp["resource_name"] = vault['name']
                        temp["resource_id"] = vault['id']
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]

                    issues.append(temp)

        except Exception as e:
            print(str(e))
        finally:
            return issues

    def check_event_hub_enable_for_keyvault(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                vault_url = key_vault_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(self.credentials, vault_url)
                vault_list = response['value']
                for vault in vault_list:

                    url = monitor_diagnostic_url.format(vault['id'])
                    monitor_response = rest_api_call(self.credentials, url, '2017-05-01-preview')
                    diag_settings = monitor_response['value']
                    for diag in diag_settings:
                        logs = diag['properties']['logs']

                        for log in logs:
                            if log['enabled']:
                                metrics = diag['properties']['metrics']
                                for each_metrics in metrics:
                                    temp = dict()
                                    vault_id = vault['id']
                                    if each_metrics['enabled']:
                                        temp["status"] = "Pass"
                                        temp["resource_name"] = vault["name"]
                                        temp["resource_id"] = vault["id"]
                                        temp["region"] = vault["location"]
                                        temp["subscription_id"] = subscription['subscriptionId']
                                        temp["subscription_name"] = subscription["displayName"]
                                    else:
                                        temp["status"] = "Fail"
                                        temp["resource_name"] = vault["name"]
                                        temp["resource_id"] = vault["id"]
                                        temp["region"] = vault["location"]
                                        temp["subscription_id"] = subscription['subscriptionId']
                                        temp["subscription_name"] = subscription["displayName"]
                                    issues.append(temp)
        except Exception as e:
            print(str(e))
            import traceback
            print(traceback.format_exc())
        finally:
            return issues

    def get_validity_period(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                vault_list = []
                vault_url = key_vault_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(self.credentials, vault_url)
                for r in response['value']:
                    vault_list.append(r)

                for vault in vault_list:
                    vault_name = vault["name"]
                    # print("vault", vault)

                    get_certificates = vault_base_url.format(vault_name) + "certificates"
                    vault_token = get_auth_token_services(self.credentials, az_resource="https://vault.azure.net")
                    try:
                        certificate_response = rest_api_call(vault_token, get_certificates, api_version='7.0')['value']
                        # print('certificate', response)
                    except Exception as e:
                        continue
                    for each_certificate in certificate_response:

                        certificate_policy = certificate_policy_url.format(vault_name,
                                                                           each_certificate['id'].split("/")[-1])

                        try:
                            certificate_policy_response = \
                            rest_api_call(vault_token, certificate_policy, api_version='7.0')['x509_props'][
                                'validity_months']

                        except Exception as e:
                            print(e)
                            continue

                        temp = dict()
                        temp["region"] = ""
                        if certificate_policy_response > 6:
                            temp["status"] = "Fail"
                            temp["resource_name"] = each_certificate['id'].split("/")[-1]
                            temp["resource_id"] = each_certificate['id']
                            temp["subscription_id"] = subscription['subscriptionId']
                            temp["subscription_name"] = subscription["displayName"]

                        else:
                            temp["status"] = "Pass"
                            temp["resource_name"] = each_certificate['id'].split("/")[-1]
                            temp["resource_id"] = each_certificate['id']
                            temp["subscription_id"] = subscription['subscriptionId']
                            temp["subscription_name"] = subscription["displayName"]

                        issues.append(temp)

        except Exception as e:
            print(str(e))
        finally:
            return issues

    def get_certificate_key_types(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                vault_list = []
                vault_url = key_vault_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(self.credentials, vault_url)
                for r in response['value']:
                    vault_list.append(r)

                for vault in vault_list:
                    vault_name = vault["name"]
                    # print("vault", vault)

                    get_certificates = vault_base_url.format(vault_name) + "certificates"
                    vault_token = get_auth_token_services(self.credentials, az_resource="https://vault.azure.net")
                    try:
                        certificate_response = rest_api_call(vault_token, get_certificates, api_version='7.0')['value']
                        # print('certificate', response)
                    except Exception as e:
                        continue
                    for each_certificate in certificate_response:

                        certificate_policy = certificate_policy_url.format(vault_name,
                                                                           each_certificate['id'].split("/")[-1])

                        try:
                            certificate_key_response = \
                                rest_api_call(vault_token, certificate_policy, api_version='7.0')['key_props'][
                                    'kty']

                        except Exception as e:
                            print(e)
                            continue

                        temp = dict()
                        temp["region"] = ""
                        if certificate_key_response not in ['RSA', 'RSA-HSM', 'ECC', 'ECC-HSM']:
                            temp["status"] = "Fail"
                            temp["resource_name"] = each_certificate['id'].split("/")[-1]
                            temp["resource_id"] = each_certificate['id']
                            temp["subscription_id"] = subscription['subscriptionId']
                            temp["subscription_name"] = subscription["displayName"]

                        else:
                            temp["status"] = "Pass"
                            temp["resource_name"] = each_certificate['id'].split("/")[-1]
                            temp["resource_id"] = each_certificate['id']
                            temp["subscription_id"] = subscription['subscriptionId']
                            temp["subscription_name"] = subscription["displayName"]

                        issues.append(temp)

        except Exception as e:
            print(str(e))
        finally:
            return issues

    def get_lifetime_action_triggers(self, threshold=80):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                vault_list = []
                vault_url = key_vault_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(self.credentials, vault_url)
                for r in response['value']:
                    vault_list.append(r)

                for vault in vault_list:
                    vault_name = vault["name"]
                    # print("vault", vault)

                    get_certificates = vault_base_url.format(vault_name) + "certificates"
                    vault_token = get_auth_token_services(self.credentials, az_resource="https://vault.azure.net")
                    try:
                        certificate_response = rest_api_call(vault_token, get_certificates, api_version='7.0')['value']
                        # print('certificate', response)
                    except Exception as e:
                        continue
                    for each_certificate in certificate_response:

                        certificate_policy = certificate_policy_url.format(vault_name,
                                                                           each_certificate['id'].split("/")[-1])

                        try:
                            lifetime_trigger_response = \
                                rest_api_call(vault_token, certificate_policy, api_version='7.0')['lifetime_actions']


                        except Exception as e:
                            print(e)
                            continue
                        for each_trigger in lifetime_trigger_response:

                            temp = dict()
                            temp["region"] = ""
                            if each_trigger['trigger']['lifetime_percentage'] < threshold:
                                temp["status"] = "Fail"
                                temp["resource_name"] = each_certificate['id'].split("/")[-1]
                                temp["resource_id"] = each_certificate['id']
                                temp["subscription_id"] = subscription['subscriptionId']
                                temp["subscription_name"] = subscription["displayName"]

                            else:
                                temp["status"] = "Pass"
                                temp["resource_name"] = each_certificate['id'].split("/")[-1]
                                temp["resource_id"] = each_certificate['id']
                                temp["subscription_id"] = subscription['subscriptionId']
                                temp["subscription_name"] = subscription["displayName"]

                            issues.append(temp)

        except Exception as e:
            print(str(e))
        finally:
            return issues

    def get_issuer(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                vault_list = []
                vault_url = key_vault_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(self.credentials, vault_url)
                for r in response['value']:
                    vault_list.append(r)

                for vault in vault_list:
                    vault_name = vault["name"]
                    # print("vault", vault)

                    get_certificates = vault_base_url.format(vault_name) + "certificates"
                    vault_token = get_auth_token_services(self.credentials, az_resource="https://vault.azure.net")
                    try:
                        certificate_response = rest_api_call(vault_token, get_certificates, api_version='7.0')['value']
                        # print('certificate', response)
                    except Exception as e:
                        continue
                    for each_certificate in certificate_response:
                        provider = ""
                        certificate_policy = certificate_policy_url.format(vault_name,
                                                                           each_certificate['id'].split("/")[-1])

                        try:
                            issuer_response = \
                                rest_api_call(vault_token, certificate_policy, api_version='7.0')['issuer']['name']


                        except Exception as e:
                            print(e)
                            continue

                        if issuer_response != 'Unknown':
                            # vault_token = get_auth_token_services(self.credentials,
                            #                                       az_resource="https://vault.azure.net")
                            issue_url = issuer_url.format(vault_name, each_certificate['id'].split("/")[-1])

                            try:
                                provider = rest_api_call(vault_token, issue_url, api_version='7.0')[
                                    "provider"]

                                # print('certificate', response)
                            except Exception as e:
                                print(e)
                                continue
                        temp = dict()
                        temp["region"] = ""
                        if provider not in ['Digicert', 'GlobalSign']:
                            temp["status"] = "Fail"
                            temp["resource_name"] = each_certificate['id'].split("/")[-1]
                            temp["resource_id"] = each_certificate['id']
                            temp["subscription_id"] = subscription['subscriptionId']
                            temp["subscription_name"] = subscription["displayName"]
                        else:
                            temp["status"] = "Pass"
                            temp["resource_name"] = each_certificate['id'].split("/")[-1]
                            temp["resource_id"] = each_certificate['id']
                            temp["subscription_id"] = subscription['subscriptionId']
                            temp["subscription_name"] = subscription["displayName"]

                        issues.append(temp)

        except Exception as e:
            print(str(e))
        finally:
            return issues

    def get_curve_name(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                vault_list = []
                vault_url = key_vault_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(self.credentials, vault_url)
                for r in response['value']:
                    vault_list.append(r)

                for vault in vault_list:
                    vault_name = vault["name"]
                    # print("vault", vault)

                    get_certificates = vault_base_url.format(vault_name) + "certificates"
                    vault_token = get_auth_token_services(self.credentials, az_resource="https://vault.azure.net")
                    try:
                        certificate_response = rest_api_call(vault_token, get_certificates, api_version='7.0')['value']
                        # print('certificate', response)
                    except Exception as e:
                        continue
                    for each_certificate in certificate_response:

                        certificate_policy = certificate_policy_url.format(vault_name,
                                                                           each_certificate['id'].split("/")[-1])

                        try:
                            key_response = rest_api_call(vault_token, certificate_policy, api_version='7.0')[
                                'key_props']



                        except Exception as e:
                            print(e)
                            continue

                        temp = dict()
                        temp["region"] = ""
                        if key_response['kty'] == 'ECC':
                            if key_response['crv'] not in ['P-256', 'P-256K', 'P-384', 'P-521']:
                                temp["status"] = "Fail"
                                temp["resource_name"] = each_certificate['id'].split("/")[-1]
                                temp["resource_id"] = each_certificate['id']
                                temp["subscription_id"] = subscription['subscriptionId']
                                temp["subscription_name"] = subscription["displayName"]

                            else:
                                temp["status"] = "Pass"
                                temp["resource_name"] = each_certificate['id'].split("/")[-1]
                                temp["resource_id"] = each_certificate['id']
                                temp["subscription_id"] = subscription['subscriptionId']
                                temp["subscription_name"] = subscription["displayName"]

                            issues.append(temp)

        except Exception as e:
            print(str(e))
        finally:
            return issues

    def get_certificate_key_size(self, key_size='2048'):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                vault_list = []
                vault_url = key_vault_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(self.credentials, vault_url)
                for r in response['value']:
                    vault_list.append(r)

                for vault in vault_list:
                    vault_name = vault["name"]
                    # print("vault", vault)

                    get_certificates = vault_base_url.format(vault_name) + "certificates"
                    vault_token = get_auth_token_services(self.credentials, az_resource="https://vault.azure.net")
                    try:
                        certificate_response = rest_api_call(vault_token, get_certificates, api_version='7.0')['value']
                        # print('certificate', response)
                    except Exception as e:
                        continue
                    for each_certificate in certificate_response:

                        certificate_policy = certificate_policy_url.format(vault_name,
                                                                           each_certificate['id'].split("/")[-1])

                        try:
                            key_response = \
                                rest_api_call(vault_token, certificate_policy, api_version='7.0')['key_props'][
                                    'key_size']

                        except Exception as e:
                            print(e)
                            continue

                        temp = dict()
                        temp["region"] = ""
                        if key_response != key_size:
                            temp["status"] = "Fail"
                            temp["resource_name"] = each_certificate['id'].split("/")[-1]
                            temp["resource_id"] = each_certificate['id']
                            temp["subscription_id"] = subscription['subscriptionId']
                            temp["subscription_name"] = subscription["displayName"]
                            temp['value_one'] = key_size

                        else:
                            temp["status"] = "Pass"
                            temp["resource_name"] = each_certificate['id'].split("/")[-1]
                            temp["resource_id"] = each_certificate['id']
                            temp["subscription_id"] = subscription['subscriptionId']
                            temp["subscription_name"] = subscription["displayName"]
                            temp['value_one'] = key_size
                        issues.append(temp)

        except Exception as e:
            print(str(e))
        finally:
            return issues


