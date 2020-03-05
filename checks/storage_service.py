from checks.common_services import CommonServices
from helper_function import get_auth_token, rest_api_call
from contants import storage_accounts_list_url, container_list_url, monitor_activity_log_url
import datetime


class StorageService:
    def __init__(self, credentials):
        self.credentials = credentials

    def check_access_to_anonymous_users(self):
        issues = []
        try:
            token = get_auth_token(self.credentials)
            cs = CommonServices()
            subscription_list = cs.get_subscriptions_list(token)
            for subscription in subscription_list:
                url = storage_accounts_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(token, url)
                storage_accounts = response['value']
                for account in storage_accounts:
                    resource_groups = CommonServices().get_resource_groups(token, subscription['subscriptionId'])
                    for resource_group in resource_groups:
                        container_url = container_list_url.format(subscription['subscriptionId'], resource_group['name'], account['name'])
                        response = rest_api_call(token, container_url)
                        print(response)
                        if 'value' in response:
                            for container in response.get('value'):
                                temp = dict()
                                temp['region'] = ""
                                if container['properties']['publicAccess'] == 'Container':
                                    temp["status"] = "Fail"
                                    temp["resource_name"] = container["name"]
                                    temp["resource_id"] = ""
                                    temp["problem"] = "Container {} in storage account {} has access to anonymous users".format(container["name"], account["name"])
                                else:
                                    temp["status"] = "Pass"
                                    temp["resource_name"] = container["name"]
                                    temp["resource_id"] = ""
                                    temp["problem"] = "Container {} in storage account {} doesn't allow access to anonymous users".format(container["name"], account["name"])
                                issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def enable_secure_transfer(self):
        issues = []
        try:
            token = get_auth_token(self.credentials)
            cs = CommonServices()
            subscription_list = cs.get_subscriptions_list(token)
            for subscription in subscription_list:
                url = storage_accounts_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(token, url)
                storage_accounts = response['value']
                for account in storage_accounts:
                    temp = dict()
                    temp["region"] = account["location"]
                    if not account['properties']['supportsHttpsTrafficOnly']:
                        temp["status"] = "Fail"
                        temp["resource_name"] = account["name"]
                        temp["resource_id"] = ""
                        temp["problem"] = "Secure data transfer is not enabled for Storage Account {} ".format(account["name"])
                    else:
                        temp["status"] = "Pass"
                        temp["resource_name"] = account["name"]
                        temp["resource_id"] = ""
                        temp["problem"] = "Secure data transfer is enabled for Storage Account {} ".format(account["name"])
                    issues.append(temp)

        except Exception as e:
            print(str(e));
        finally:
            return issues

    def check_trusted_services_access(self):
        issues = []
        try:
            token = get_auth_token(self.credentials)
            cs = CommonServices()
            subscription_list = cs.get_subscriptions_list(token)
            for subscription in subscription_list:
                url = storage_accounts_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(token, url)
                storage_accounts = response['value']
                for account in storage_accounts:
                    temp = dict()
                    temp["region"] = account["location"]
                    if account['properties']['networkAcls']['bypass'] is None:
                        temp["status"] = "Fail"
                        temp["resource_name"] = account["name"]
                        temp["resource_id"] = ""
                        temp["problem"] = "Trusted Microsoft Services are not allowed to access the Storage Account {} ".format(account["name"])
                    else:
                        temp["status"] = "Pass"
                        temp["resource_name"] = account["name"]
                        temp["resource_id"] = ""
                        temp["problem"] = "Trusted Microsoft Services are allowed to access the Storage Account {}".format(account["name"])
                    issues.append(temp)

        except Exception as e:
            print(str(e));
        finally:
            return issues

    def restrict_default_network_access(self):
        issues = []
        try:
            token = get_auth_token(self.credentials)
            cs = CommonServices()
            subscription_list = cs.get_subscriptions_list(token)
            for subscription in subscription_list:
                url = storage_accounts_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(token, url)
                storage_accounts = response['value']
                for account in storage_accounts:
                    temp = dict()
                    temp["region"] = account["location"]
                    if account['properties']['networkAcls']['defaultAction'] == "Allow":
                        temp["status"] = "Fail"
                        temp["resource_name"] = account["name"]
                        temp["resource_id"] = ""
                        temp["problem"] = "Storage Account {} is accessible from default network". format(account["name"])
                    else:
                        temp["status"] = "Pass"
                        temp["resource_name"] = account["name"]
                        temp["resource_id"] = ""
                        temp["problem"] = "Storage Account {} is not accessible from default network".format(account["name"])
                    issues.append(temp)

        except Exception as e:
            print(str(e));
        finally:
            return issues

    def regenerate_storage_keys(self):
        issues = []
        try:
            next_link_flag = 0
            next_link = ""
            log_list = list()
            token = get_auth_token(self.credentials)
            cs = CommonServices()
            subscription_list = cs.get_subscriptions_list(token)
            end_date = datetime.datetime.now()
            start_date = (datetime.datetime.now() - datetime.timedelta(days=90))
            for subscription in subscription_list:
                url = storage_accounts_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(token, url)
                storage_accounts = response['value']
                for account in storage_accounts:
                    temp_resp = dict()
                    temp_resp['region'] = account['location']
                    storage_name = account["name"]
                    temp = account["id"].split("resourceGroups")
                    resource_group = temp[1].split("/")[1]
                    filters = "eventTimestamp ge '{}' and eventTimestamp le '{}'  and status eq 'Succeeded' and resourceGroupName eq '{}' ".format(start_date, end_date, resource_group)
                    logs_url = monitor_activity_log_url.format(subscription['subscriptionId']) + "?$filter="+filters+""
                    log_response = rest_api_call(token, logs_url, '2015-04-01')
                    for log in log_response['value']:
                        log_list.append(log)
                    if 'nextLink' in log_response:
                        next_link_flag = 1
                        next_link = log_response['nextLink'].split('skipToken=')[1]
                    else:
                        next_link_flag = 0
                        next_link = ""

                    while next_link_flag == 1:
                        filters = "eventTimestamp ge '{}' and eventTimestamp le '{}'  and status eq 'Succeeded' and resourceGroupName eq '{}' &$skipToken={} ".format(
                            start_date, end_date, resource_group, next_link)
                        logs_url = monitor_activity_log_url.format(subscription['subscriptionId']) + "?$filter=" + filters + ""
                        log_response = rest_api_call(token, logs_url, '2015-04-01')
                        for log in log_response['value']:
                            log_list.append(log)
                        if 'nextLink' in log_response:
                            next_link_flag = 1
                            next_link = log_response['nextLink'].split('skipToken=')[1]
                        else:
                            next_link_flag = 0
                            next_link = ""
                    for log in log_list:
                        if 'authorization' in log:
                            if log['authorization']['action'] == "Microsoft.Storage/storageAccounts/regenerateKey/action":
                                temp_resp["status"] = "Pass"
                                temp_resp["resource_name"] = account["name"]
                                temp_resp["resource_id"] = ""
                                temp_resp["problem"] = "Access keys regenerated for Storage Account {}".format(account["name"])
                            else:
                                temp_resp["status"] = "Fail"
                                temp_resp["resource_name"] = account["name"]
                                temp_resp["resource_id"] = ""
                                temp_resp["problem"] = "Access keys not regenerated for Storage Account {}".format(account["name"])
                        issues.append(temp_resp)
        except Exception as e:
            print(str(e));
        finally:
            return issues

    def enable_storage_queue_logging(self):
        issues = []
        try:
            token = get_auth_token(self.credentials)
            cs = CommonServices()
            subscription_list = cs.get_subscriptions_list(token)
            for subscription in subscription_list:
                url = storage_accounts_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(token, url)
                storage_accounts = response['value']
                for account in storage_accounts:
                    temp_resp = dict()
                    temp_resp['region'] = account['location']
                    queue_log_url = "https://{}.queue.core.windows.net".format(account["name"])
                    print(queue_log_url)
                    response = rest_api_call(token, queue_log_url, api_version='2013-08-15')
                    print(response)
        except Exception as e:
            print(str(e))
        finally:
            return issues