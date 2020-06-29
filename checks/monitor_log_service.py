from constants import log_profile_list_url, base_url, key_vault_list_url, monitor_diagnostic_url
from helper_function import rest_api_call


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
                response = rest_api_call(self.credentials, url, '2016-03-01')
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
                response = rest_api_call(self.credentials, url, '2016-03-01')
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
                response = rest_api_call(self.credentials, url, '2016-03-01')
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
                response = rest_api_call(self.credentials, url, '2016-03-01')
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
                response = rest_api_call(self.credentials, url, '2016-03-01')
                log_profiles = response['value']
                for profile in log_profiles:
                    temp = dict()
                    storage_account_id = profile['properties']['storageAccountId']
                    url = base_url+storage_account_id
                    response = rest_api_call(self.credentials, url)
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
                response = rest_api_call(self.credentials, vault_url)
                vault_list = response['value']
                for vault in vault_list:
                    temp = dict()
                    vault_id = vault['id']
                    url = monitor_diagnostic_url.format(vault_id)
                    monitor_response = rest_api_call(self.credentials, url, '2017-05-01-preview')
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
                response = rest_api_call(self.credentials, url, '2016-03-01')
                #print(response)
                log_profiles = response['value']
                for profile in log_profiles:
                    #print(profile)
                    storage_account_id = profile['properties']['storageAccountId']
                    temp = dict()
                    temp["region"] = ""
                    storage_url = base_url + storage_account_id + "/blobServices/default/containers"
                    try:
                        storage_response = rest_api_call(self.credentials, storage_url)
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

    # Diagnostic logs in Key Vault should be enabled

    def enable_diagnostic_logs_in_key_vault(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                vault_url = key_vault_list_url.format(
                    subscription['subscriptionId'])
                response = rest_api_call(self.credentials, vault_url)
                vault_list = response['value']
                for vault in vault_list:
                    temp = dict()
                    vault_id = vault['id']
                    url = monitor_diagnostic_url.format(vault_id)
                    monitor_response = rest_api_call(self.credentials, url,
                                                     '2017-05-01-preview')
                    diag_settings = monitor_response['value']
                    for diag in diag_settings:
                        logs = diag['properties']['logs']
                        for log in logs:
                            if log['enabled'] is True:
                                if log['retentionPolicy']['enabled'] is True:
                                    if log['retentionPolicy']['days'] < 1:
                                        temp['status'] = "Fail"
                                        temp["resource_name"] = vault["name"]
                                        temp["resource_id"] = vault["id"]
                                        temp["region"] = vault["location"]
                                        temp["subscription_id"] = subscription[
                                            'subscriptionId']
                                        temp["subscription_name"] = \
                                        subscription["displayName"]
                                    elif log['retentionPolicy']['days'] > 365:
                                        temp['status'] = "Fail"
                                        temp["resource_name"] = vault["name"]
                                        temp["resource_id"] = vault["id"]
                                        temp["region"] = vault["location"]
                                        temp["subscription_id"] = subscription[
                                            'subscriptionId']
                                        temp["subscription_name"] = \
                                        subscription["displayName"]
                                    else:
                                        temp["status"] = "Pass"
                                        temp["resource_name"] = vault["name"]
                                        temp["resource_id"] = vault["id"]
                                        temp["region"] = vault["location"]
                                        temp["subscription_id"] = subscription[
                                            'subscriptionId']
                                        temp["subscription_name"] = \
                                        subscription["displayName"]
                                else:
                                    temp['status'] = "Disabled"
                                    temp["resource_name"] = vault["name"]
                                    temp["resource_id"] = vault["id"]
                                    temp["region"] = vault["location"]
                                    temp["subscription_id"] = subscription[
                                        'subscriptionId']
                                    temp["subscription_name"] = subscription[
                                        "displayName"]
                            else:
                                temp['status'] = 'Disabled'
                                temp["resource_name"] = vault["name"]
                                temp["resource_id"] = vault["id"]
                                temp["region"] = vault["location"]
                                temp["subscription_id"] = subscription[
                                    'subscriptionId']
                                temp["subscription_name"] = subscription[
                                    "displayName"]
                            issues.append(temp)

        except Exception as e:
            print(str(e))
        finally:
            return issues

    # Diagnostic logs in Event Hub should be enabled

    def enable_diagnostic_logs_in_event_hub(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                namespace_url = namespace_list_url.format(
                    subscription['subscriptionId'])
                response = rest_api_call(self.credentials, namespace_url,
                                         '2016-06-01')
                namespace_list = response['value']
                for namespace in namespace_list:
                    temp = dict()
                    namespace_id = namespace['id']
                    url = monitor_diagnostic_url.format(namespace_id)
                    monitor_response = rest_api_call(self.credentials, url,
                                                     '2017-05-01-preview')
                    diag_settings = monitor_response['value']
                    for diag in diag_settings:
                        logs = diag['properties']['logs']
                        for log in logs:
                            if log['enabled'] is True:
                                if log['retentionPolicy']['enabled'] is True:
                                    if log['retentionPolicy']['days'] < 1:
                                        temp['status'] = "Fail"
                                        temp["resource_name"] = namespace[
                                            "name"]
                                        temp["resource_id"] = namespace["id"]
                                        temp["region"] = namespace["location"]
                                        temp["subscription_id"] = subscription[
                                            'subscriptionId']
                                        temp["subscription_name"] = \
                                        subscription["displayName"]
                                    elif log['retentionPolicy']['days'] > 365:
                                        temp['status'] = "Fail"
                                        temp["resource_name"] = namespace[
                                            "name"]
                                        temp["resource_id"] = namespace["id"]
                                        temp["region"] = namespace["location"]
                                        temp["subscription_id"] = subscription[
                                            'subscriptionId']
                                        temp["subscription_name"] = \
                                        subscription["displayName"]
                                    else:
                                        temp["status"] = "Pass"
                                        temp["resource_name"] = namespace[
                                            "name"]
                                        temp["resource_id"] = namespace["id"]
                                        temp["region"] = namespace["location"]
                                        temp["subscription_id"] = subscription[
                                            'subscriptionId']
                                        temp["subscription_name"] = \
                                        subscription["displayName"]
                                else:
                                    temp['status'] = "Disabled"
                                    temp["resource_name"] = namespace["name"]
                                    temp["resource_id"] = namespace["id"]
                                    temp["region"] = namespace["location"]
                                    temp["subscription_id"] = subscription[
                                        'subscriptionId']
                                    temp["subscription_name"] = subscription[
                                        "displayName"]
                            else:
                                temp['status'] = "Disabled"
                                temp["resource_name"] = namespace["name"]
                                temp["resource_id"] = namespace["id"]
                                temp["region"] = namespace["location"]
                                temp["subscription_id"] = subscription[
                                    'subscriptionId']
                                temp["subscription_name"] = subscription[
                                    "displayName"]
                            issues.append(temp)



        except Exception as e:
            print(str(e))
        finally:
            return issues

    # Diagnostic logs in IoT Hub should be enabled

    def enable_diagnostic_logs_in_IoT(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                IoT_hub_url = IoT_hub_list_url.format(
                    subscription['subscriptionId'])
                response = rest_api_call(self.credentials, IoT_hub_url,
                                         '2016-06-01')
                IoT_hub_list = response['value']
                for hub in IoT_hub_list:
                    temp = dict()
                    hub_id = hub['id']
                    url = monitor_diagnostic_url.format(hub_id)
                    monitor_response = rest_api_call(self.credentials, url,
                                                     '2017-05-01-preview')
                    diag_settings = monitor_response['value']
                    for diag in diag_settings:
                        logs = diag['properties']['logs']
                        for log in logs:
                            if log['enabled'] is True:
                                if log['retentionPolicy']['enabled'] is True:
                                    if log['retentionPolicy']['days'] < 1:
                                        temp['status'] = "Fail"
                                        temp["resource_name"] = hub["name"]
                                        temp["resource_id"] = hub["id"]
                                        temp["region"] = hub["location"]
                                        temp["subscription_id"] = subscription[
                                            'subscriptionId']
                                        temp["subscription_name"] = \
                                        subscription["displayName"]
                                    elif log['retentionPolicy']['days'] > 365:
                                        temp['status'] = "Fail"
                                        temp["resource_name"] = hub["name"]
                                        temp["resource_id"] = hub["id"]
                                        temp["region"] = hub["location"]
                                        temp["subscription_id"] = subscription[
                                            'subscriptionId']
                                        temp["subscription_name"] = \
                                        subscription["displayName"]
                                    else:
                                        temp["status"] = "Pass"
                                        temp["resource_name"] = hub["name"]
                                        temp["resource_id"] = hub["id"]
                                        temp["region"] = hub["location"]
                                        temp["subscription_id"] = subscription[
                                            'subscriptionId']
                                        temp["subscription_name"] = \
                                        subscription["displayName"]
                                else:
                                    temp['status'] = "Disabled"
                                    temp["resource_name"] = hub["name"]
                                    temp["resource_id"] = hub["id"]
                                    temp["region"] = hub["location"]
                                    temp["subscription_id"] = subscription[
                                        'subscriptionId']
                                    temp["subscription_name"] = subscription[
                                        "displayName"]
                                issues.append(temp)

        except Exception as e:
            print(str(e))
        finally:
            return issues

    # Diagnostic logs in Azure Stream Analytics should be enabled


    def enable_diagnostic_logs_in_azure_stream_analytics(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                azure_stream_analytics_url = Azure_stream_analytics_list_url.format(
                    subscription['subscriptionId'])
                response = rest_api_call(self.credentials,
                                         azure_stream_analytics_url, '2016-06-01')
                azure_stream_analytics_list = response['value']
                for azure_stream in azure_stream_analytics_list:
                    temp = dict()
                    azure_stream_id = azure_stream['id']
                    url = monitor_diagnostic_url.format(azure_stream_id)
                    monitor_response = rest_api_call(self.credentials, url,
                                                     '2017-05-01-preview')
                    diag_settings = monitor_response['value']
                    for diag in diag_settings:
                        logs = diag['properties']['logs']
                        for log in logs:
                            if log['enabled'] is True:
                                if log['retentionPolicy']['enabled'] is True:
                                    if log['retentionPolicy']['days'] < 1 or \
                                            log['retentionPolicy']['days'] > 365:
                                        temp['status'] = "Fail"
                                        temp["resource_name"] = azure_stream["name"]
                                        temp["resource_id"] = azure_stream["id"]
                                        temp["region"] = azure_stream["location"]
                                        temp["subscription_id"] = subscription[
                                            'subscriptionId']
                                        temp["subscription_name"] = subscription[
                                            "displayName"]
                                    else:
                                        temp["status"] = "Pass"
                                        temp["resource_name"] = azure_stream["name"]
                                        temp["resource_id"] = azure_stream["id"]
                                        temp["region"] = azure_stream["location"]
                                        temp["subscription_id"] = subscription[
                                            'subscriptionId']
                                        temp["subscription_name"] = subscription[
                                            "displayName"]
                                else:
                                    temp['status'] = "Disabled"
                                    temp["resource_name"] = azure_stream["name"]
                                    temp["resource_id"] = azure_stream["id"]
                                    temp["region"] = azure_stream["location"]
                                    temp["subscription_id"] = subscription[
                                        'subscriptionId']
                                    temp["subscription_name"] = subscription[
                                        "displayName"]
                            else:
                                temp['status'] = "Disabled"
                                temp["resource_name"] = azure_stream["name"]
                                temp["resource_id"] = azure_stream["id"]
                                temp["region"] = azure_stream["location"]
                                temp["subscription_id"] = subscription[
                                    'subscriptionId']
                                temp["subscription_name"] = subscription[
                                    "displayName"]
                            issues.append(temp)


        except Exception as e:
            print(str(e))
        finally:
            return issues

        # Diagnostic logs in Service Bus should be enabled


    def enable_diagnostic_logs_in_service_bus(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                service_bus_url = service_bus_list_url.format(
                    subscription['subscriptionId'])
                response = rest_api_call(self.credentials, service_bus_url,
                                         '2018-01-01-preview')
                service_bus_list = response['value']
                for service_bus in service_bus_list:
                    temp = dict()
                    service_bus_id = service_bus['id']
                    url = monitor_diagnostic_url.format(service_bus_id)
                    monitor_response = rest_api_call(self.credentials, url,
                                                     '2017-05-01-preview')
                    diag_settings = monitor_response['value']
                    for diag in diag_settings:
                        logs = diag['properties']['logs']
                        for log in logs:
                            if log['enabled'] is True:
                                if log['retentionPolicy']['enabled'] is True:
                                    if log['retentionPolicy']['days'] < 1 or \
                                            log['retentionPolicy']['days'] > 365:
                                        temp['status'] = "Fail"
                                        temp["resource_name"] = service_bus["name"]
                                        temp["resource_id"] = service_bus["id"]
                                        temp["region"] = service_bus["location"]
                                        temp["subscription_id"] = subscription[
                                            'subscriptionId']
                                        temp["subscription_name"] = subscription[
                                            "displayName"]
                                    else:
                                        temp["status"] = "Pass"
                                        temp["resource_name"] = service_bus["name"]
                                        temp["resource_id"] = service_bus["id"]
                                        temp["region"] = service_bus["location"]
                                        temp["subscription_id"] = subscription[
                                            'subscriptionId']
                                        temp["subscription_name"] = subscription[
                                            "displayName"]
                                else:
                                    temp['status'] = "Disabled"
                                    temp["resource_name"] = service_bus["name"]
                                    temp["resource_id"] = service_bus["id"]
                                    temp["region"] = service_bus["location"]
                                    temp["subscription_id"] = subscription[
                                        'subscriptionId']
                                    temp["subscription_name"] = subscription[
                                        "displayName"]
                            else:
                                temp['status'] = "Disabled"
                                temp["resource_name"] = service_bus["name"]
                                temp["resource_id"] = service_bus["id"]
                                temp["region"] = service_bus["location"]
                                temp["subscription_id"] = subscription[
                                    'subscriptionId']
                                temp["subscription_name"] = subscription[
                                    "displayName"]
                            issues.append(temp)



        except Exception as e:
            print(str(e))
        finally:
            return issues

        # Diagnostic logs in Search services should be enabled


    def enable_diagnostic_logs_in_search_services(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                search_url = search_services_list_url.format(
                    subscription['subscriptionId'])
                response = rest_api_call(self.credentials, search_url, '2016-06-01')
                search_list = response['value']
                for search in search_list:
                    temp = dict()
                    search_id = search['id']
                    url = monitor_diagnostic_url.format(search_id)
                    monitor_response = rest_api_call(self.credentials, url,
                                                     '2017-05-01-preview')
                    diag_settings = monitor_response['value']
                    for diag in diag_settings:
                        logs = diag['properties']['logs']
                        for log in logs:
                            if log['enabled'] is True:
                                if log['retentionPolicy']['enabled'] is True:
                                    if log['retentionPolicy']['days'] < 1 or \
                                            log['retentionPolicy']['days'] > 365:
                                        temp['status'] = "Fail"
                                        temp["resource_name"] = search["name"]
                                        temp["resource_id"] = search["id"]
                                        temp["region"] = search["location"]
                                        temp["subscription_id"] = subscription[
                                            'subscriptionId']
                                        temp["subscription_name"] = subscription[
                                            "displayName"]
                                    else:
                                        temp["status"] = "Pass"
                                        temp["resource_name"] = search["name"]
                                        temp["resource_id"] = search["id"]
                                        temp["region"] = search["location"]
                                        temp["subscription_id"] = subscription[
                                            'subscriptionId']
                                        temp["subscription_name"] = subscription[
                                            "displayName"]
                                else:
                                    temp['status'] = "Disabled"
                                    temp["resource_name"] = search["name"]
                                    temp["resource_id"] = search["id"]
                                    temp["region"] = search["location"]
                                    temp["subscription_id"] = subscription[
                                        'subscriptionId']
                                    temp["subscription_name"] = subscription[
                                        "displayName"]
                            else:
                                temp['status'] = "Disabled"
                                temp["resource_name"] = search["name"]
                                temp["resource_id"] = search["id"]
                                temp["region"] = search["location"]
                                temp["subscription_id"] = subscription[
                                    'subscriptionId']
                                temp["subscription_name"] = subscription[
                                    "displayName"]
                            issues.append(temp)

        except Exception as e:
            print(str(e))
        finally:
            return issues

        # Diagnostic logs in Logic Apps should be enabled


    def enable_diagnostic_logs_in_logic_apps(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                workflows_url = workflows_list_url.format(
                    subscription['subscriptionId'])
                response = rest_api_call(self.credentials, workflows_url,
                                         '2016-06-01')
                workflows_list = response['value']
                for workflows in workflows_list:
                    temp = dict()
                    workflow_id = workflows['id']
                    url = monitor_diagnostic_url.format(workflow_id)
                    monitor_response = rest_api_call(self.credentials, url,
                                                     '2017-05-01-preview')
                    diag_settings = monitor_response['value']
                    for diag in diag_settings:
                        logs = diag['properties']['logs']
                        for log in logs:
                            if log['enabled'] is True:
                                if log['retentionPolicy']['enabled'] is True:
                                    if log['retentionPolicy']['days'] < 1:
                                        temp['status'] = "Fail"
                                        temp["resource_name"] = workflows["name"]
                                        temp["resource_id"] = workflows["id"]
                                        temp["region"] = workflows["location"]
                                        temp["subscription_id"] = subscription[
                                            'subscriptionId']
                                        temp["subscription_name"] = subscription[
                                            "displayName"]
                                    elif log['retentionPolicy']['days'] > 365:
                                        temp['status'] = "Fail"
                                        temp["resource_name"] = workflows["name"]
                                        temp["resource_id"] = workflows["id"]
                                        temp["region"] = workflows["location"]
                                        temp["subscription_id"] = subscription[
                                            'subscriptionId']
                                        temp["subscription_name"] = subscription[
                                            "displayName"]
                                    else:
                                        temp["status"] = "Pass"
                                        temp["resource_name"] = workflows["name"]
                                        temp["resource_id"] = workflows["id"]
                                        temp["region"] = workflows["location"]
                                        temp["subscription_id"] = subscription[
                                            'subscriptionId']
                                        temp["subscription_name"] = subscription[
                                            "displayName"]
                                else:
                                    temp['status'] = "Disabled"
                                    temp["resource_name"] = workflows["name"]
                                    temp["resource_id"] = workflows["id"]
                                    temp["region"] = workflows["location"]
                                    temp["subscription_id"] = subscription[
                                        'subscriptionId']
                                    temp["subscription_name"] = subscription[
                                        "displayName"]
                            else:
                                temp['status'] = "Disabled"
                                temp["resource_name"] = workflows["name"]
                                temp["resource_id"] = workflows["id"]
                                temp["region"] = workflows["location"]
                                temp["subscription_id"] = subscription[
                                    'subscriptionId']
                                temp["subscription_name"] = subscription[
                                    "displayName"]
                            issues.append(temp)

        except Exception as e:
            print(str(e))
        finally:
            return issues

        # Diagnostic logs in Azure Data Lake Store should be enabled


    def enable_diagnostic_logs_in_azure_data_lake_store(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                store_url = Data_lake_store_list_url.format(
                    subscription['subscriptionId'])
                response = rest_api_call(self.credentials, store_url, '2016-06-01')
                store_list = response['value']
                for store in store_list:
                    temp = dict()
                    store_id = store['id']
                    url = monitor_diagnostic_url.format(store_id)
                    monitor_response = rest_api_call(self.credentials, url,
                                                     '2017-05-01-preview')
                    diag_settings = monitor_response['value']
                    for diag in diag_settings:
                        logs = diag['properties']['logs']
                        for log in logs:
                            if log['enabled'] is True:
                                if log['retentionPolicy']['enabled'] is True:
                                    if log['retentionPolicy']['days'] < 1:
                                        temp['status'] = "Fail"
                                        temp["resource_name"] = store["name"]
                                        temp["resource_id"] = store["id"]
                                        temp["region"] = store["location"]
                                        temp["subscription_id"] = subscription[
                                            'subscriptionId']
                                        temp["subscription_name"] = subscription[
                                            "displayName"]
                                    elif log['retentionPolicy']['days'] > 365:
                                        temp['status'] = "Fail"
                                        temp["resource_name"] = store["name"]
                                        temp["resource_id"] = store["id"]
                                        temp["region"] = store["location"]
                                        temp["subscription_id"] = subscription[
                                            'subscriptionId']
                                        temp["subscription_name"] = subscription[
                                            "displayName"]
                                    else:
                                        temp["status"] = "Pass"
                                        temp["resource_name"] = store["name"]
                                        temp["resource_id"] = store["id"]
                                        temp["region"] = store["location"]
                                        temp["subscription_id"] = subscription[
                                            'subscriptionId']
                                        temp["subscription_name"] = subscription[
                                            "displayName"]

                                else:
                                    temp['status'] = "Disabled"
                                    temp["resource_name"] = store["name"]
                                    temp["resource_id"] = store["id"]
                                    temp["region"] = store["location"]
                                    temp["subscription_id"] = subscription[
                                        'subscriptionId']
                                    temp["subscription_name"] = subscription[
                                        "displayName"]

                            issues.append(temp)

        except Exception as e:
            print(str(e))
        finally:
            return issues

        # Diagnostic logs in Data Lake Analytics should be enabled


    def enable_diagnostic_logs_in_data_lake_analytics(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                data_lake_analytics_url = Data_lake_analytics_list_url.format(
                    subscription['subscriptionId'])
                response = rest_api_call(self.credentials, data_lake_analytics_url,
                                         '2016-06-01')
                data_lake_analytics_list = response['value']
                for datalake in data_lake_analytics_list:
                    temp = dict()
                    data_lake_id = datalake['id']
                    url = monitor_diagnostic_url.format(data_lake_id)
                    monitor_response = rest_api_call(self.credentials, url,
                                                     '2017-05-01-preview')
                    diag_settings = monitor_response['value']
                    for diag in diag_settings:
                        logs = diag['properties']['logs']
                        for log in logs:
                            if log['enabled'] is True:
                                if log['retentionPolicy']['enabled'] is True:
                                    if log['retentionPolicy']['days'] < 1:
                                        temp['status'] = "Fail"
                                        temp["resource_name"] = datalake["name"]
                                        temp["resource_id"] = datalake["id"]
                                        temp["region"] = datalake["location"]
                                        temp["subscription_id"] = subscription[
                                            'subscriptionId']
                                        temp["subscription_name"] = subscription[
                                            "displayName"]
                                    elif log['retentionPolicy']['days'] > 365:
                                        temp['status'] = "Fail"
                                        temp["resource_name"] = datalake["name"]
                                        temp["resource_id"] = datalake["id"]
                                        temp["region"] = datalake["location"]
                                        temp["subscription_id"] = subscription[
                                            'subscriptionId']
                                        temp["subscription_name"] = subscription[
                                            "displayName"]
                                    else:
                                        temp["status"] = "Pass"
                                        temp["resource_name"] = datalake["name"]
                                        temp["resource_id"] = datalake["id"]
                                        temp["region"] = datalake["location"]
                                        temp["subscription_id"] = subscription[
                                            'subscriptionId']
                                        temp["subscription_name"] = subscription[
                                            "displayName"]
                                else:
                                    temp['status'] = "Disabled"
                                    temp["resource_name"] = datalake["name"]
                                    temp["resource_id"] = datalake["id"]
                                    temp["region"] = datalake["location"]
                                    temp["subscription_id"] = subscription[
                                        'subscriptionId']
                                    temp["subscription_name"] = subscription[
                                        "displayName"]

                            issues.append(temp)


        except Exception as e:
            print(str(e))
        finally:
            return issues

        # Diagnostic logs in Batch accounts should be enabled


    def enable_diagnostic_logs_in_batch_accounts(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                batch_accounts_url = batch_accounts_list_url.format(
                    subscription['subscriptionId'])
                response = rest_api_call(self.credentials, batch_accounts_url)
                batch_accounts_list = response['value']
                for batch_account in batch_accounts_list:
                    temp = dict()
                    batch_account_id = batch_account['id']
                    url = monitor_diagnostic_url.format(batch_account_id)
                    monitor_response = rest_api_call(self.credentials, url,
                                                     '2017-05-01-preview')
                    diag_settings = monitor_response['value']
                    for diag in diag_settings:
                        logs = diag['properties']['logs']
                        for log in logs:
                            if log['enabled'] is True:
                                if log['retentionPolicy']['enabled'] is True:
                                    if log['retentionPolicy']['days'] < 1 or \
                                            log['retentionPolicy']['days'] > 365:
                                        temp['status'] = "Fail"
                                        temp["resource_name"] = batch_account[
                                            "name"]
                                        temp["resource_id"] = batch_account["id"]
                                        temp["region"] = batch_account["location"]
                                        temp["subscription_id"] = subscription[
                                            'subscriptionId']
                                        temp["subscription_name"] = subscription[
                                            "displayName"]
                                    else:
                                        temp["status"] = "Pass"
                                        temp["resource_name"] = batch_account[
                                            "name"]
                                        temp["resource_id"] = batch_account["id"]
                                        temp["region"] = batch_account["location"]
                                        temp["subscription_id"] = subscription[
                                            'subscriptionId']
                                        temp["subscription_name"] = subscription[
                                            "displayName"]
                                else:
                                    temp['status'] = "Disabled"
                                    temp["resource_name"] = batch_account["name"]
                                    temp["resource_id"] = batch_account["id"]
                                    temp["region"] = batch_account["location"]
                                    temp["subscription_id"] = subscription[
                                        'subscriptionId']
                                    temp["subscription_name"] = subscription[
                                        "displayName"]
                            else:
                                temp['status'] = "Disabled"
                                temp["resource_name"] = batch_account["name"]
                                temp["resource_id"] = batch_account["id"]
                                temp["region"] = batch_account["location"]
                                temp["subscription_id"] = subscription[
                                    'subscriptionId']
                                temp["subscription_name"] = subscription[
                                    "displayName"]
                            issues.append(temp)


        except Exception as e:
            print(str(e))
        finally:
            return issues
