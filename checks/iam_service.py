from checks.common_services import CommonServices
from helper_function import rest_api_call, get_adal_token
from constants import storage_accounts_list_url, role_definitions_list_url
import requests


class IamServices:
    def __init__(self, credentials, subscription_list):
        self.credentials = credentials
        self.subscription_list = subscription_list

    def get_custom_roles(self):
        issues = []
        try:
            subscription_list = self.credentials
            for subscription in subscription_list:
                scope_reg_exp = '/subscriptions/{}'.format(subscription['subscriptionId'])
                resource_groups = CommonServices().get_resource_groups(token, subscription['subscriptionId'])
                for resource_group in resource_groups:
                    scope = "/subscriptions/{}/resourceGroups/{}".format(subscription['subscriptionId'], resource_group["name"])
                    filter = "type eq 'CustomRole'"
                    url = role_definitions_list_url.format(scope) + "?$filter={$"+filter+"}"
                    response = rest_api_call(self.credentials, url, api_version='2015-07-01')
                    role_definitions_list = response['value']
                    for role_definition in role_definitions_list:
                        temp = dict()
                        temp["region"] = ""
                        scope_flag = 0
                        permission_flag = 0
                        role_scope = role_definition['properties']['assignableScopes']
                        permissions = role_definition['properties']['permissions']
                        for scope in role_scope:
                            if scope == '/' or scope == scope_reg_exp:
                                scope_flag = 1
                        for permission in permissions:
                            for action in permission['actions']:
                                if action == "*":
                                    permission_flag = 1

                        if scope_flag == 1 and permission_flag == 1:
                            temp["status"] = "Fail"
                            temp["resource_name"] = role_definition['properties']['roleName']
                            temp["resource_id"] = role_definition['id']
                            temp["subscription_id"] = subscription['subscriptionId']
                            temp["subscription_name"] = subscription["displayName"]
                        else:
                            temp["status"] = "Pass"
                            temp["resource_name"] = role_definition['properties']['roleName']
                            temp["resource_id"] = role_definition['id']
                            temp["subscription_id"] = subscription['subscriptionId']
                            temp["subscription_name"] = subscription["displayName"]
                        issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def guest_users(self):
        issues = []
        try:
            token = get_adal_token(self.credentials)
            headers = {'Authorization': 'Bearer ' + token['access_token'], 'Content-Type': 'application/json'}
            url = "https://graph.microsoft.com/v1.0/users?$filter=userType eq 'Guest'"
            response = requests.get(url, headers=headers)
            response = response.json()
            users_list = response['value']
            temp = dict()
            if len(users_list) > 0:
                temp['region'] = ""
                temp["status"] = "Fail"
                temp["resource_name"] = ""
                temp["resource_id"] = ""

            else:
                temp['region'] = ""
                temp["status"] = "Pass"
                temp["resource_name"] = ""
                temp["resource_id"] = ""

            if temp:
                issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def enable_mfa_non_privileged_users(self):
        issues = []
        try:
            token = get_adal_token()
            mgt_api_headers = {'Authorization': 'Bearer ' + token['access_token'], 'Content-Type': 'application/json'}
            url = "https://graph.microsoft.com/v1.0/users"
            response = requests.get(url, headers=headers)
            response = response.json()
            users_list = response['value']
            for user in users_list:
                filter = "assignedTo('{{}}')".format(user['id'])
                assignment_url = "https://management.azure.com/providers/Microsoft.Authorization/roleAssignments?$filter={"+filter+"}"
                response = rest_api_call(mgt_api_token, assignment_url)
                print(response)
        except Exception as e:
            print(str(e))
        finally:
            return issues
