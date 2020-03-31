from checks.common_services import CommonServices
from helper_function import rest_api_call, get_adal_token
from constants import storage_accounts_list_url, container_list_url, monitor_activity_log_url, base_url, resource_group_list_url
import datetime
import requests


class StorageService:
    def __init__(self, credentials, subscription_list):
        self.credentials = credentials
        self.subscription_list = subscription_list

    def check_access_to_anonymous_users(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                url = storage_accounts_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(self.credentials, url)
                storage_accounts = response['value']
                for account in storage_accounts:
                    try:
                        container_url = base_url + account["id"] + "/blobServices/default/containers"
                        response = rest_api_call(self.credentials, container_url)
                        # print(response)
                        if 'value' in response:
                            for container in response.get('value'):
                                temp = dict()
                                temp['region'] = ""
                                if container['properties']['publicAccess'] == 'Container':
                                    temp["status"] = "Fail"
                                    temp["resource_name"] = container["name"]
                                    temp["resource_id"] = ""
                                    temp["subscription_id"] = subscription['subscriptionId']
                                    temp["subscription_name"] = subscription["displayName"]
                                    temp["value_one"] = account["name"]
                                else:
                                    temp["status"] = "Pass"
                                    temp["resource_name"] = container["name"]
                                    temp["resource_id"] = ""
                                    temp["subscription_id"] = subscription['subscriptionId']
                                    temp["subscription_name"] = subscription["displayName"]
                                    temp["value_one"] = account["name"]
                                issues.append(temp)
                    except:
                        continue
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def enable_secure_transfer(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                url = storage_accounts_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(self.credentials, url)
                storage_accounts = response['value']
                for account in storage_accounts:
                    temp = dict()
                    temp["region"] = account["location"]
                    if not account['properties']['supportsHttpsTrafficOnly']:
                        temp["status"] = "Fail"
                        temp["resource_name"] = account["name"]
                        temp["resource_id"] = ""
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]
                    else:
                        temp["status"] = "Pass"
                        temp["resource_name"] = account["name"]
                        temp["resource_id"] = ""
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]
                    issues.append(temp)

        except Exception as e:
            print(str(e));
        finally:
            return issues

    def check_trusted_services_access(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                url = storage_accounts_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(self.credentials, url)
                storage_accounts = response['value']
                for account in storage_accounts:
                    temp = dict()
                    temp["region"] = account["location"]
                    if account['properties']['networkAcls']['bypass'] is None:
                        temp["status"] = "Fail"
                        temp["resource_name"] = account["name"]
                        temp["resource_id"] = ""
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]
                    else:
                        temp["status"] = "Pass"
                        temp["resource_name"] = account["name"]
                        temp["resource_id"] = ""
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]
                    issues.append(temp)

        except Exception as e:
            print(str(e));
        finally:
            return issues

    def restrict_default_network_access(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                url = storage_accounts_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(self.credentials, url)
                storage_accounts = response['value']
                for account in storage_accounts:
                    temp = dict()
                    temp["region"] = account["location"]
                    if account['properties']['networkAcls']['defaultAction'] == "Allow":
                        temp["status"] = "Fail"
                        temp["resource_name"] = account["name"]
                        temp["resource_id"] = ""
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]
                    else:
                        temp["status"] = "Pass"
                        temp["resource_name"] = account["name"]
                        temp["resource_id"] = ""
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]
                    issues.append(temp)

        except Exception as e:
            print(str(e));
        finally:
            return issues

    def regenerate_storage_keys(self):
        print("regenerate_storage_keys")
        issues = []
        try:
            subscription_list = self.subscription_list
            end_date = datetime.datetime.now().strftime("%Y-%m-%d")
            start_date = (datetime.datetime.now() - datetime.timedelta(days=5)).strftime("%Y-%m-%d")
            for subscription in subscription_list:
                resource_group_list = ["CloudEnsure-test"]
                url = resource_group_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(self.credentials, url)
                storage_accounts_passed = []
                for resource in response["value"]:
                    next_link_flag = 0
                    next_link = ""
                    log_list = []
                    resource_group = resource["name"]
                    filters = "eventTimestamp ge '{}' and eventTimestamp le '{}'  and status eq 'Succeeded' and resourceGroupName eq '{}' "\
                        .format(start_date, end_date, resource_group)
                    logs_url = monitor_activity_log_url.format(
                        subscription['subscriptionId']) + "?$filter=" + filters + ""
                    log_response = rest_api_call(self.credentials, logs_url, '2015-04-01')

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
                        logs_url = monitor_activity_log_url.format(
                            subscription['subscriptionId']) + "?$filter=" + filters + ""
                        log_response = rest_api_call(self.credentials, logs_url, '2015-04-01')
                        for log in log_response['value']:
                            log_list.append(log)
                        if 'nextLink' in log_response:
                            next_link_flag = 1
                            next_link = log_response['nextLink'].split('skipToken=')[1]
                        else:
                            next_link_flag = 0
                            next_link = ""

                    try:
                        for log in log_list:
                            if 'authorization' in log:
                                if log['authorization']['action'] == "Microsoft.Storage/storageAccounts/regenerateKey/action":
                                    print("pass")
                                    temp = log["authorization"]["scope"].split("storageAccounts/")
                                    storage_accounts_passed.append(temp[1])
                    except:
                        continue

                print(storage_accounts_passed)
                storage_url = storage_accounts_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(self.credentials, storage_url)
                storage_accounts = response['value']
                for account in storage_accounts:
                    temp = dict()
                    temp["region"] = account["location"]
                    if account["name"] in storage_accounts_passed:
                        temp["status"] = "Pass"
                        temp["resource_name"] = account["name"]
                        temp["resource_id"] = ""
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]
                    else:
                        temp["status"] = "Fail"
                        temp["resource_name"] = account["name"]
                        temp["resource_id"] = ""
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]
                    issues.append(temp)
        except Exception as e:
            print(str(e));
        finally:
            return issues

    def enable_storage_queue_logging(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                url = storage_accounts_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(self.credentials, url)
                storage_accounts = response['value']
                for account in storage_accounts:
                    temp_resp = dict()
                    temp_resp['region'] = account['location']
                    queue_log_url = "https://{}.queue.core.windows.net/".format(account["name"])
                    token = get_adal_token(self.credentials)

                    headers = {'Authorization': 'Bearer ' + token['access_token'], 'Content-Type': 'application/json'
                               , "x-ms-version": '2017-11-09'}
                    params = {'api-version': "2019-06-01"}
                    response = requests.get(queue_log_url, headers=headers)
                    #response = rest_api_call(self.credentials, queue_log_url, api_version='2012-02-12')
                    print(response.text)
        except Exception as e:
            print(str(e))
        finally:
            return issues