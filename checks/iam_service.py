from checks.common_services import CommonServices
from helper_function import rest_api_call, get_adal_token
from constants import storage_accounts_list_url, role_definitions_list_url
import requests
import logging as logger


class IamServices:
    def __init__(self, credentials, subscription_list):
        self.credentials = credentials
        self.subscription_list = subscription_list

    def get_custom_roles(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                scope_reg_exp = '/subscriptions/{}'.format(subscription['subscriptionId'])
                resource_groups = CommonServices().get_resource_groups(self.credentials, subscription['subscriptionId'])
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
            logger.error(e);
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
            logger.error(e);
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
            logger.error(e);
        finally:
            return issues

#Allowed locations

    def Allowed_locations(self):
        issues=[]
        allowed_locations = ['eastus','westus','southindia', 'centralindia', 'centralus']
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                #scope_reg_exp = '/subscriptions/{}'.format(subscription['subscriptionId'])
                url = resource_group_list_url.format(subscription['subscriptionId'])
                resp = rest_api_call(self.credentials, url, api_version='2016-06-01')
                resource_groups = resp['value']
                for resource_group in resource_groups:
                    location = resource_group['location']
                    temp = dict()
                    for allowed_location in allowed_locations:
                        if location == allowed_location or location == "global":
                            temp['status'] = "Allowed location"
                            temp['location'] = location
                            break
                        else:
                            temp['status'] = "Denied location"
                            temp['location'] = location
                    issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

#Allowed locations for resource groups

    def Allowed_location_for_resourse_group(self):
        issues=[]
        allowed_locations = ['eastus', 'westus', 'southindia', 'centralindia', 'centralus']
        resourse_group_location = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                #scope_reg_exp = '/subscriptions/{}'.format(subscription['subscriptionId'])
                url = resource_group_list_url.format(subscription['subscriptionId'])
                # print(url)
                resp = rest_api_call(self.credentials, url, api_version='2016-06-01')
                res = resp['value']
                for r in res:
                    res_url = base_url + r['id']
                    response = rest_api_call(self.credentials, res_url, api_version='2016-06-01')
                    location = response['location']
                    temp = dict()
                    for allowed_location in allowed_locations:
                        if location == allowed_location:
                            temp['status'] = "Allowed location"
                            temp['location'] = location
                            break
                        else:
                            temp['status'] = "Denied location"
                            temp['location'] = allowed_locations
                    issues.append(temp)

        except Exception as e:
            print(str(e))
        finally:
            return issues

#Geo-redundant storage should be enabled for Storage Accounts

    def enable_Georedundant_storage(self):
        issues= []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                url = storage_accounts_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(self.credentials, url, api_version='2019-06-01')
                temp = dict()
                for each_response in response['value']:
                    sku_data= each_response['sku']
                    sku_name= sku_data['name']
                    if sku_name == "Standard_GRS" or sku_name == "Standard_RAGRS":
                        temp['Geo_redundant storage'] = "Enabled"
                        temp['sku_name'] = sku_name
                    else:
                        temp['Geo_redundant storage'] = "Disabled"
                        temp['sku_name'] = sku_name
                    issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

