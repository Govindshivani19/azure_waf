from contants import log_profile_list_url, base_url, key_vault_list_url, monitor_diagnostic_url
from helper_function import get_auth_token, rest_api_call


class MonitorLogService:
    def __init__(self, credentials, subscription_list):
        self.credentials = credentials
        self.subscription_list = subscription_list

    def get_log_profiles(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                url = log_profile_list_url.format(subscription['subscriptionId'])
                token = get_auth_token(self.credentials)
                response = rest_api_call(token, url, '2016-03-01')
                log_profiles = response['value']
                for profile in log_profiles:
                    temp = dict()
                    if profile['location'] is not None:
                        temp["region"] = profile['location']
                    else:
                        temp["region"] = ""
                    if not profile:
                        temp["status"] = "Fail"
                        temp["resource_name"] = subscription['displayName']
                        temp["resource_id"] = subscription['subscriptionId']
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]
                    else:
                        temp["status"] = "Pass"
                        temp["resource_name"] = subscription['displayName']
                        temp["resource_id"] = subscription['subscriptionId']
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]
                    issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def get_log_retention_period(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                url = log_profile_list_url.format(subscription['subscriptionId'])
                token = get_auth_token(self.credentials)
                response = rest_api_call(token, url, '2016-03-01')
                log_profiles = response['value']
                for profile in log_profiles:
                    temp = dict()
                    if profile['location'] is not None:
                        temp["region"] = profile['location']
                    else:
                        temp["region"] = ""
                    retention_period = profile['properties']['retentionPolicy']['days']
                    if retention_period <= 0:
                        temp["status"] = "Fail"
                        temp["resource_name"] = profile["name"]
                        temp["resource_id"] = profile["id"]
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]
                    elif retention_period < 365:
                        temp["status"] = "Fail" 
                        temp["resource_name"] = profile["name"]
                        temp["resource_id"] = profile["id"]
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]
                    else:
                        temp["status"] = "Pass"
                        temp["resource_name"] = profile["name"]
                        temp["resource_id"] = profile["id"]
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]
                    issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def get_total_region_export_count(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                url = log_profile_list_url.format(subscription['subscriptionId'])
                token = get_auth_token(self.credentials)
                response = rest_api_call(token, url, '2016-03-01')
                log_profiles = response['value']
                for profile in log_profiles:
                    temp = dict()
                    if profile['location'] is not None:
                        temp["region"] = profile['location']
                    else:
                        temp["region"] = ""
                    locations_count = len(profile['properties']['locations'])
                    if locations_count < 35:
                        temp["status"] = "Fail"
                        temp["resource_name"] = profile["name"]
                        temp["resource_id"] = profile["id"]
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]
                    else:
                        temp["status"] = "Pass"
                        temp["resource_name"] = profile["name"]
                        temp["resource_id"] = profile["id"]
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]
                    issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def get_log_profile_export_activities(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                url = log_profile_list_url.format(subscription['subscriptionId'])
                token = get_auth_token(self.credentials)
                response = rest_api_call(token, url, '2016-03-01')
                log_profiles = response['value']
                for profile in log_profiles:
                    temp = dict()
                    if profile['location'] is not None:
                        temp["region"] = profile['location']
                    else:
                        temp["region"] = ""
                    categories_count = len(profile["properties"]["categories"])
                    if categories_count < 3:
                        temp["status"] = "Fail"
                        temp["resource_name"] = profile["name"]
                        temp["resource_id"] = profile["id"]
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]
                    else:
                        temp["status"] = "Pass"
                        temp["resource_name"] = profile["name"]
                        temp["resource_id"] = profile["id"]
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]
                    issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def is_activity_log_storage_encrypted(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                url = log_profile_list_url.format(subscription['subscriptionId'])
                token = get_auth_token(self.credentials)
                response = rest_api_call(token, url, '2016-03-01')
                log_profiles = response['value']
                for profile in log_profiles:
                    temp = dict()
                    storage_account_id = profile['properties']['storageAccountId']
                    url = base_url+storage_account_id
                    token = get_auth_token(self.credentials)
                    response = rest_api_call(token, url)
                    try:
                        key_source = response['properties']['encryption']['keySource']
                        if key_source == 'Microsoft.Storage':
                            temp["status"] = "Fail"
                            temp["resource_name"] = response["name"]
                            temp["resource_id"] = response["id"]
                            temp["region"] = response["location"]
                            temp["subscription_id"] = subscription['subscriptionId']
                            temp["subscription_name"] = subscription["displayName"]
                        else:
                            temp["status"] = "Pass"
                            temp["resource_name"] = response["name"]
                            temp["resource_id"] = response["id"]
                            temp["region"] = response["location"]
                            temp["subscription_id"] = subscription['subscriptionId']
                            temp["subscription_name"] = subscription["displayName"]
                        issues.append(temp)
                    except:
                        continue
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def check_auditevent_enable_for_keyvault(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                vault_url = key_vault_list_url.format(subscription['subscriptionId'])
                token = get_auth_token(self.credentials)
                response = rest_api_call(token, vault_url)
                vault_list = response['value']
                for vault in vault_list:
                    temp = dict()
                    vault_id = vault['id']
                    url = monitor_diagnostic_url.format(vault_id)
                    token = get_auth_token(self.credentials)
                    monitor_response = rest_api_call(token, url, '2017-05-01-preview')
                    diag_settings = monitor_response['value']
                    for diag in diag_settings:
                        logs = diag['properties']['logs']
                        for log in logs:
                            if log['enabled']:
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
        finally:
            return issues

    def check_public_accessible_log_storage_accounts(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                url = log_profile_list_url.format(subscription['subscriptionId'])
                token = get_auth_token(self.credentials)
                response = rest_api_call(token, url, '2016-03-01')
                #print(response)
                log_profiles = response['value']
                for profile in log_profiles:
                    #print(profile)
                    storage_account_id = profile['properties']['storageAccountId']
                    temp = dict()
                    temp["region"] = ""
                    storage_url = base_url + storage_account_id + "/blobServices/default/containers"
                    token = get_auth_token(self.credentials)
                    try:
                        storage_response = rest_api_call(token, storage_url)
                        #print(storage_response)
                        container_list = storage_response['value']
                        for container in container_list:
                            if container['name'] == "insights-operational-logs":
                                if container['properties']['publicAccess'] == "Container":
                                    temp["status"] = "Fail"
                                    temp["resource_name"] = container["name"]
                                    temp["resource_id"] = container["id"]
                                    temp["subscription_id"] = subscription['subscriptionId']
                                    temp["subscription_name"] = subscription["displayName"]
                                else:
                                    temp["status"] = "Pass"
                                    temp["resource_name"] = container["name"]
                                    temp["resource_id"] = container["id"]
                                    temp["subscription_id"] = subscription['subscriptionId']
                                    temp["subscription_name"] = subscription["displayName"]
                                issues.append(temp)
                    except:
                        continue
        except Exception as e:
            print(str(e))
        finally:
            return issues
