from constants import log_profile_list_url, base_url, key_vault_list_url, monitor_diagnostic_url, resource_type_list_url, vm_list_url,activity_log_alert_url,resource_group_list_url
from helper_function import rest_api_call
import logging as logger
from checks.common_services import CommonServices


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
            logger.error(e);
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
            logger.error(e);
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
            logger.error(e);
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
            logger.error(e);
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
            logger.error(e);
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
            logger.error(e);
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
            logger.error(e);
        finally:
            return issues

        # Audit diagnostic setting category:Audit and accountable [policy category:Monitoring]

    def audit_diagnostic_settings(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                url = resource_type_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(self.credentials, url, '2019-10-01')['value']
                temp = dict()
                for resource in response:
                    monitor_url = monitor_diagnostic_url.format(resource['id'])
                    resp = rest_api_call(self.credentials, monitor_url, '2017-05-01-preview')
                    for data in resp:
                        if data == 'value':
                            for info in resp['value']:
                                for log in info['properties']['logs']:
                                    temp['name'] = "logs"
                                    if log['enabled'] is True:
                                        temp['status'] = 'Pass'
                                        temp['category'] = log['category']
                                        temp['resource_id'] = resource['id']
                                        temp['subscription'] = subscription['subscriptionId']
                                    else:
                                        temp['status'] = 'Fail'
                                        temp['resource_id'] = resource['id']
                                        temp['subscription'] = subscription['subscriptionId']
                                    issues.append(temp)
                                    print(temp)
                                for metric in info['properties']['metrics']:
                                    temp2 = dict()
                                    temp2['name'] = "metrics"
                                    if metric['enabled'] is True:
                                        temp2['status'] = 'Pass'
                                        temp2['category'] = metric['category']
                                        temp2['resource_id'] = resource['id']
                                        temp2['subscription'] = subscription['subscriptionId']
                                    else:
                                        temp2['status'] = 'Fail'
                                        temp2['resource_id'] = resource['id']
                                        temp2['subscription'] = subscription['subscriptionId']
                                    issues.append(temp2)
                                    print(temp2)

        except Exception as e:
            logger.error(e)
        finally:
            return issues

    def audit_log_analytics_workspace_for_vm(self,log_analytics_workspace_id=None):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                resource_list = CommonServices().get_resource_groups(self.credentials, subscription['subscriptionId'])
                for resource in resource_list:
                    url = vm_list_url.format(subscription['subscriptionId']+'/resourceGroups/'+resource['name'])
                    response = rest_api_call(self.credentials, url, '2019-12-01')['value']
                    for vm in response:
                        vm_url = base_url + vm['id'] + '/extensions'
                        resp = rest_api_call(self.credentials, vm_url, '2019-12-01')['value']
                        for info in resp:
                            temp = dict()
                            link = base_url + info['id']
                            data = rest_api_call(self.credentials, link, '2019-12-01')
                            if data['properties']['publisher'] == "Microsoft.EnterpriseCloud.Monitoring":
                                print(data['properties']['settings']['workspaceId'])
                                if data['properties']['settings']['workspaceId'] != log_analytics_workspace_id:#unable to get logAnalytics workspace id
                                    temp['status'] = 'Fail'
                                    temp['extension_name'] = info['name']
                                    temp['Virtual_machine_name'] = vm['name']
                                    temp['resource_group'] = resource['name']
                                    temp['subscriptionId'] = subscription['subscriptionId']
                                else:
                                    temp['status'] = 'Pass'
                                    temp['extension_name'] = info['name']
                                    temp['Virtual_machine_name'] = vm['name']
                                    temp['resource_group'] = resource['name']
                                    temp['subscriptionId'] = subscription['subscriptionId']
                                issues.append(temp)
                                print(temp)

        except Exception as e:
            logger.error(e)
        finally:
            return issues

        # Create Alert for "Create, Update or Delete SQL Server Firewall Rule" Events
    def create_alert_sql_server_firewall(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                url = resource_group_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(self.credentials, url)
                for resource in response["value"]:
                    resource_group = resource["name"]
                    logs_url = activity_log_alert_url.format(
                        subscription['subscriptionId'], resource_group)
                    log_response = rest_api_call(self.credentials, logs_url, '2017-04-01')
                    print(log_response)
                    for each_response in log_response['value']:
                        temp = dict()
                        temp["region"] = ""
                        print(each_response)
                        if each_response['properties']['enabled'] == "true":
                            if each_response['properties']['condition']['allOf']['field'] == "operationName" & \
                                    each_response['properties']['condition']['allOf'][
                                        'equals'] == "Microsoft.Network/networkSecurityGroups/securityRules/write":
                                temp["status"] = "Pass"
                                temp["resource_name"] = each_response["name"]
                                temp["resource_id"] = each_response["id"]
                                temp["subscription_id"] = subscription['subscriptionId']
                                temp["subscription_name"] = subscription["displayName"]
                        else:
                            temp["status"] = "Fail"
                            temp["resource_name"] = each_response["name"]
                            temp["resource_id"] = each_response["id"]
                            temp["subscription_id"] = subscription['subscriptionId']
                            temp["subscription_name"] = subscription["displayName"]
                        issues.append(temp)

        except Exception as e:
            logger.error(e)
            import traceback
            print(traceback.format_exc())
        finally:
            return issues
