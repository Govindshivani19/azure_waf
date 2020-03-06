from contants import log_profile_list_url, base_url, key_vault_list_url, monitor_diagnostic_url
from checks.common_services import CommonServices
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
                        temp["problem"] = "Log Profile not created for subscription {} ".format(subscription['displayName'])
                    else:
                        temp["status"] = "Pass"
                        temp["resource_name"] = subscription['displayName']
                        temp["resource_id"] = subscription['subscriptionId']
                        temp["problem"] = "Log Profile created for subscription {} ".format(subscription['displayName'])
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
                        temp["problem"] = "Log Profile {} for subcription {} does not have a sufficient activity log data retention period configured. " \
                            .format(profile["name"], subscription['displayName'])
                    elif retention_period < 365:
                        temp["status"] = "Fail" 
                        temp["resource_name"] = profile["name"]
                        temp["resource_id"] = profile["id"]
                        temp["problem"] = "Log Profile {} for subscription {} does not have a sufficient activity log data retention period configured. " \
                            .format(profile["name"], subscription['displayName'])
                    else:
                        temp["status"] = "Pass"
                        temp["resource_name"] = profile["name"]
                        temp["resource_id"] = profile["id"]
                        temp["problem"] = "Log Profile {} for subscription {} have a sufficient activity log data retention period configured. " \
                            .format(profile["name"], subscription['displayName'])
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
                        temp["problem"] = "Log Profile {} for the subscription {} is  not configured to export activities from all supported Azure regions/locations." \
                            .format(profile["name"], subscription['displayName'])
                    else:
                        temp["status"] = "Pass"
                        temp["resource_name"] = profile["name"]
                        temp["resource_id"] = profile["id"]
                        temp["problem"] = "Log Profile {} for the subscription {} is configured to export activities from all supported Azure regions/locations." \
                            .format(profile["name"], subscription['displayName'])
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
                        temp["problem"] = "Log Profile {} for the subscription {} is  not configured to export Write, Delete and Action events. " \
                            .format(profile["name"], subscription['displayName'])
                    else:
                        temp["status"] = "Pass"
                        temp["resource_name"] = profile["name"]
                        temp["resource_id"] = profile["id"]
                        temp["problem"] = "Log Profile {} for the subscription {} is  configured to export Write, Delete and Action events. " \
                            .format(subscription['displayName'], subscription['displayName'])
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
                    key_source = response['properties']['encryption']['keySource']
                    if key_source == 'Microsoft.Storage':
                        temp["status"] = "Fail"
                        temp["resource_name"] = response["name"]
                        temp["resource_id"] = response["id"]
                        temp["region"] = response["location"]
                        temp["problem"] = "Microsoft Azure storage  {} container that contains  activity log files is encrypted using a service-managed key instead of a customer-managed key." \
                            .format(response["name"])
                    else:
                        temp["status"] = "Pass"
                        temp["resource_name"] = response["name"]
                        temp["resource_id"] = response["id"]
                        temp["region"] = response["location"]
                        temp["problem"] = "Microsoft Azure storage  {} container that contains  activity log files is encrypted using a customer-managed key." \
                            .format(response["name"])
                    issues.append(temp)
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
                                temp["problem"] = "AuditEvent logging enabled for Azure Key Vault {} " \
                                    .format(vault["name"])
                            else:
                                temp["status"] = "Fail"
                                temp["resource_name"] = vault["name"]
                                temp["resource_id"] = vault["id"]
                                temp["region"] = vault["location"]
                                temp["problem"] = "AuditEvent logging not enabled for Azure Key Vault {} " \
                                    .format(vault["name"])
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
                log_profiles = response['value']
                for profile in log_profiles:
                    storage_account_id = profile['properties']['storageAccountId']
                    temp = dict()
                    temp["region"] = ""
                    storage_url = base_url + storage_account_id + "/blobServices/default/containers"
                    token = get_auth_token(self.credentials)
                    storage_response = rest_api_call(token, storage_url)
                    container_list = storage_response['value']
                    for container in container_list:
                        if container['name'] == "insights-operational-logs":
                            if container['properties']['publicAccess'] == "Container":
                                temp["status"] = "Fail"
                                temp["resource_name"] = container["name"]
                                temp["resource_id"] = container["id"]
                                temp["problem"] = "Storage container {} holding the activity logs is publicly accessible.".format(container["name"])
                            else:
                                temp["status"] = "Pass"
                                temp["resource_name"] = container["name"]
                                temp["resource_id"] = container["id"]
                                temp["problem"] = "Storage container {} holding the activity logs is not publicly accessible.".format(container["name"])
                            issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues
