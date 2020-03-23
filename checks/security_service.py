from checks.common_services import CommonServices
from helper_function import get_auth_token, rest_api_call
from contants import policy_assignments_url, security_contacts_url, auto_provision_url, pricing_url, vm_list_url, compliance_result_url, manage_cluster_url


class SecurityService:
    def __init__(self, credentials, subscription_list):
        self.credentials = credentials
        self.subscription_list = subscription_list

    def network_hardening_recommendations(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                instance_list = []
                url = vm_list_url.format(subscription['subscriptionId'])
                token = get_auth_token(self.credentials)
                response = rest_api_call(token, url, api_version='2019-07-01')
                for instance in response['value']:
                    instance_list.append(instance)
                if len(instance_list) > 0:
                    compliance_result = compliance_result_url.format(subscription['subscriptionId'] )
                    try:
                        compliance_result_response = rest_api_call(token, compliance_result, api_version='2017-08-01')['value']
                        print(compliance_result_response)
                    except Exception as e:
                        print(e)
                        continue
                    for each_response in compliance_result_response:
                        if each_response['name'] == "adaptiveNetworkHardenings" :
                            temp = dict()

                            if each_response['properties']['resourceStatus'] not in ["OffByPolicy", "Healthy"]:

                                temp["status"] = "Fail"
                                temp["resource_name"] = each_response["name"]
                                temp["resource_id"] = each_response["id"]
                                temp["subscription_id"] = subscription['subscriptionId']
                                temp["subscription_name"] = subscription["displayName"]
                            else:
                                temp["status"] = "Pass"
                                temp["resource_name"] = each_response["name"]
                                temp["resource_id"] = each_response["id"]
                                temp["subscription_id"] = subscription['subscriptionId']
                                temp["subscription_name"] = subscription["displayName"]
                            issues.append(temp)
        except Exception as e:
            print(str(e))

        finally:
            return issues

    def designate_subscription_owner(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                instance_list = []
                url = vm_list_url.format(subscription['subscriptionId'])
                token = get_auth_token(self.credentials)
                response = rest_api_call(token, url, api_version='2019-07-01')
                for instance in response['value']:
                    instance_list.append(instance)
                if len(instance_list) > 0:
                    compliance_result = compliance_result_url.format(subscription['subscriptionId'] )
                    try:
                        compliance_result_response = rest_api_call(token, compliance_result, api_version='2017-08-01')['value']
                        print(compliance_result_response)
                    except Exception as e:
                        print(e)
                        continue
                    for each_response in compliance_result_response:
                        if each_response['name'] == "DesignateMoreThanOneOwner" :
                            temp = dict()
                            if each_response['properties']['resourceStatus'] not in ["OffByPolicy", "Healthy"]:
                                temp["status"] = "Fail"
                                temp["resource_name"] = each_response["name"]
                                temp["resource_id"] = each_response["id"]
                                temp["subscription_id"] = subscription['subscriptionId']
                                temp["subscription_name"] = subscription["displayName"]
                            else:
                                temp["status"] = "Pass"
                                temp["resource_name"] = each_response["name"]
                                temp["resource_id"] = each_response["id"]
                                temp["subscription_id"] = subscription['subscriptionId']
                                temp["subscription_name"] = subscription["displayName"]
                            issues.append(temp)
        except Exception as e:
            print(str(e))

        finally:
            return issues

    def disk_encryption_for_vms(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                instance_list = []
                url = vm_list_url.format(subscription['subscriptionId'])
                token = get_auth_token(self.credentials)
                response = rest_api_call(token, url, api_version='2019-07-01')
                for instance in response['value']:
                    instance_list.append(instance)
                if len(instance_list) > 0:
                    compliance_result = compliance_result_url.format(subscription['subscriptionId'] )
                    try:
                        compliance_result_response = rest_api_call(token, compliance_result, api_version='2017-08-01')['value']
                        print(compliance_result_response)
                    except Exception as e:
                        print(e)
                        continue
                    for each_response in compliance_result_response:
                        if each_response['name'] == "encryption" :
                            temp = dict()
                            if each_response['properties']['resourceStatus'] not in ["OffByPolicy", "Healthy"]:
                                temp["status"] = "Fail"
                                temp["resource_name"] = each_response["name"]
                                temp["resource_id"] = each_response["id"]
                                temp["subscription_id"] = subscription['subscriptionId']
                                temp["subscription_name"] = subscription["displayName"]
                            else:
                                temp["status"] = "Pass"
                                temp["resource_name"] = each_response["name"]
                                temp["resource_id"] = each_response["id"]
                                temp["subscription_id"] = subscription['subscriptionId']
                                temp["subscription_name"] = subscription["displayName"]
                            issues.append(temp)
        except Exception as e:
            print(str(e))

        finally:
            return issues

    def open_management_ports(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                instance_list = []
                url = vm_list_url.format(subscription['subscriptionId'])
                token = get_auth_token(self.credentials)
                response = rest_api_call(token, url, api_version='2019-07-01')
                for instance in response['value']:
                    instance_list.append(instance)
                if len(instance_list) > 0:
                    compliance_result = compliance_result_url.format(subscription['subscriptionId'] )
                    try:
                        compliance_result_response = rest_api_call(token, compliance_result, api_version='2017-08-01')['value']
                        print(compliance_result_response)
                    except Exception as e:
                        print(e)
                        continue
                    for each_response in compliance_result_response:
                        if each_response['name'] == "restrictAccessToManagementPorts" :
                            temp = dict()
                            if each_response['properties']['resourceStatus'] not in ["OffByPolicy", "Healthy"]:
                                temp["status"] = "Fail"
                                temp["resource_name"] = each_response["name"]
                                temp["resource_id"] = each_response["id"]
                                temp["subscription_id"] = subscription['subscriptionId']
                                temp["subscription_name"] = subscription["displayName"]
                            else:
                                temp["status"] = "Pass"
                                temp["resource_name"] = each_response["name"]
                                temp["resource_id"] = each_response["id"]
                                temp["subscription_id"] = subscription['subscriptionId']
                                temp["subscription_name"] = subscription["displayName"]
                            issues.append(temp)
        except Exception as e:
            print(str(e))

        finally:
            return issues

    def os_vulnerabilities(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                instance_list = []
                url = vm_list_url.format(subscription['subscriptionId'])
                token = get_auth_token(self.credentials)
                response = rest_api_call(token, url, api_version='2019-07-01')
                for instance in response['value']:
                    instance_list.append(instance)
                if len(instance_list) > 0:
                    compliance_result = compliance_result_url.format(subscription['subscriptionId'] )
                    try:
                        compliance_result_response = rest_api_call(token, compliance_result, api_version='2017-08-01')['value']
                        print(compliance_result_response)
                    except Exception as e:
                        print(e)
                        continue
                    for each_response in compliance_result_response:
                        if each_response['name'] == "OsVulnerabilities" :
                            temp = dict()
                            if each_response['properties']['resourceStatus'] not in ["OffByPolicy", "Healthy"]:
                                temp["status"] = "Fail"
                                temp["resource_name"] = each_response["name"]
                                temp["resource_id"] = each_response["id"]
                                temp["subscription_id"] = subscription['subscriptionId']
                                temp["subscription_name"] = subscription["displayName"]
                            else:
                                temp["status"] = "Pass"
                                temp["resource_name"] = each_response["name"]
                                temp["resource_id"] = each_response["id"]
                                temp["subscription_id"] = subscription['subscriptionId']
                                temp["subscription_name"] = subscription["displayName"]
                            issues.append(temp)
        except Exception as e:
            print(str(e))

        finally:
            return issues


    def adaptive_application_controls(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                instance_list = []
                url = vm_list_url.format(subscription['subscriptionId'])
                token = get_auth_token(self.credentials)
                response = rest_api_call(token, url, api_version='2019-07-01')
                for instance in response['value']:
                    instance_list.append(instance)
                if len(instance_list) > 0:
                    compliance_result = compliance_result_url.format(subscription['subscriptionId'] )
                    try:
                        compliance_result_response = rest_api_call(token, compliance_result, api_version='2017-08-01')['value']
                        print(compliance_result_response)
                    except Exception as e:
                        print(e)
                        continue
                    for each_response in compliance_result_response:
                        if each_response['name'] == "applicationWhitelisting" :
                            temp = dict()
                            if each_response['properties']['resourceStatus'] not in ["OffByPolicy", "Healthy"]:
                                temp["status"] = "Fail"
                                temp["resource_name"] = each_response["name"]
                                temp["resource_id"] = each_response["id"]
                                temp["subscription_id"] = subscription['subscriptionId']
                                temp["subscription_name"] = subscription["displayName"]
                            else:
                                temp["status"] = "Pass"
                                temp["resource_name"] = each_response["name"]
                                temp["resource_id"] = each_response["id"]
                                temp["subscription_id"] = subscription['subscriptionId']
                                temp["subscription_name"] = subscription["displayName"]
                            issues.append(temp)
        except Exception as e:
            print(str(e))

        finally:
            return issues
    def no_of_owners(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                instance_list = []
                url = vm_list_url.format(subscription['subscriptionId'])
                token = get_auth_token(self.credentials)
                response = rest_api_call(token, url, api_version='2019-07-01')
                for instance in response['value']:
                    instance_list.append(instance)
                if len(instance_list) > 0:
                    compliance_result = compliance_result_url.format(subscription['subscriptionId'] )
                    try:
                        compliance_result_response = rest_api_call(token, compliance_result, api_version='2017-08-01')['value']
                        print(compliance_result_response)
                    except Exception as e:
                        print(e)
                        continue
                    for each_response in compliance_result_response:
                        if each_response['name'] == "DesignateLessThanXOwners" :
                            temp = dict()
                            if each_response['properties']['resourceStatus'] not in ["OffByPolicy", "Healthy"]:
                                temp["status"] = "Fail"
                                temp["resource_name"] = each_response["name"]
                                temp["resource_id"] = each_response["id"]
                                temp["subscription_id"] = subscription['subscriptionId']
                                temp["subscription_name"] = subscription["displayName"]
                            else:
                                temp["status"] = "Pass"
                                temp["resource_name"] = each_response["name"]
                                temp["resource_id"] = each_response["id"]
                                temp["subscription_id"] = subscription['subscriptionId']
                                temp["subscription_name"] = subscription["displayName"]
                            issues.append(temp)
        except Exception as e:
            print(str(e))

        finally:
            return issues

    def endpoint_protection(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                instance_list = []
                url = vm_list_url.format(subscription['subscriptionId'])
                token = get_auth_token(self.credentials)
                response = rest_api_call(token, url, api_version='2019-07-01')
                for instance in response['value']:
                    instance_list.append(instance)
                if len(instance_list) > 0:
                    compliance_result = compliance_result_url.format(subscription['subscriptionId'])
                    try:
                        compliance_result_response = \
                        rest_api_call(token, compliance_result, api_version='2017-08-01')['value']
                        print(compliance_result_response)
                    except Exception as e:
                        print(e)
                        continue
                    for each_response in compliance_result_response:
                        if each_response['name'] == "EndpointProtection":
                            temp = dict()
                            if each_response['properties']['resourceStatus'] not in ["OffByPolicy", "Healthy"]:
                                temp["status"] = "Fail"
                                temp["resource_name"] = each_response["name"]
                                temp["resource_id"] = each_response["id"]
                                temp["subscription_id"] = subscription['subscriptionId']
                                temp["subscription_name"] = subscription["displayName"]
                            else:
                                temp["status"] = "Pass"
                                temp["resource_name"] = each_response["name"]
                                temp["resource_id"] = each_response["id"]
                                temp["subscription_id"] = subscription['subscriptionId']
                                temp["subscription_name"] = subscription["displayName"]
                            issues.append(temp)
        except Exception as e:
            print(str(e))

        finally:
            return issues

    def authorized_ip_ranges(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                url = manage_cluster_url.format(subscription['subscriptionId'])
                token = get_auth_token(self.credentials)
                response = rest_api_call(token, url, api_version='2017-08-31')['value']

                for each_response in response:
                    if each_response['properties'].get("apiServerAccessProfile"):
                        temp = dict()
                        if each_response['properties']["apiServerAccessProfile"]["authorizedIPRanges"] is False:
                            temp["status"] = "Fail"
                            temp["resource_name"] = each_response["name"]
                            temp["resource_id"] = each_response["id"]
                            temp["subscription_id"] = subscription['subscriptionId']
                            temp["subscription_name"] = subscription["displayName"]
                        else:
                            temp["status"] = "Pass"
                            temp["resource_name"] = each_response["name"]
                            temp["resource_id"] = each_response["id"]
                            temp["subscription_id"] = subscription['subscriptionId']
                            temp["subscription_name"] = subscription["displayName"]
                        issues.append(temp)
        except Exception as e:
            print(str(e))

        finally:
            return issues

    def pod_security_policies(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                url = manage_cluster_url.format(subscription['subscriptionId'])
                token = get_auth_token(self.credentials)
                response = rest_api_call(token, url, api_version='2017-08-31')['value']
                for each_response in response:
                    each_response['properties']["pod_security_policies"] = False

                    if each_response['properties'].get("pod_security_policies") is not None:
                        temp = dict()

                        if each_response['properties']["pod_security_policies"] is False:
                            temp["status"] = "Fail"
                            temp["resource_name"] = each_response["name"]
                            temp["resource_id"] = each_response["id"]
                            temp["subscription_id"] = subscription['subscriptionId']
                            temp["subscription_name"] = subscription["displayName"]
                        else:
                            temp["status"] = "Pass"
                            temp["resource_name"] = each_response["name"]
                            temp["resource_id"] = each_response["id"]
                            temp["subscription_id"] = subscription['subscriptionId']
                            temp["subscription_name"] = subscription["displayName"]
                        issues.append(temp)
        except Exception as e:
            print(str(e))

        finally:
            return issues

    def enable_application_whitelisting_monitor(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                temp = dict()
                temp["region"] = ""
                url = policy_assignments_url.format(subscription['subscriptionId'])
                token = get_auth_token(self.credentials)
                response = rest_api_call(token, url, api_version='2018-05-01')
                if response['properties']['parameters']:
                    if 'adaptiveApplicationControlsMonitoringEffect' in response['properties']['parameters']:
                        if response['properties']['parameters']['adaptiveApplicationControlsMonitoringEffect']['value'] == "Disabled":
                            temp["status"] = "Fail"
                            temp["resource_name"] = subscription["displayName"]
                            temp["resource_id"] = subscription['subscriptionId']
                            temp["subscription_id"] = subscription['subscriptionId']
                            temp["subscription_name"] = subscription["displayName"]
                        else:
                            temp["status"] = "Pass"
                            temp["resource_name"] = subscription["displayName"]
                            temp["resource_id"] = subscription['subscriptionId']
                            temp["subscription_id"] = subscription['subscriptionId']
                            temp["subscription_name"] = subscription["displayName"]
                    else:
                        temp["status"] = "Fail"
                        temp["resource_name"] = subscription["displayName"]
                        temp["resource_id"] = subscription['subscriptionId']
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]
                else:
                    temp["status"] = "Fail"
                    temp["resource_name"] = subscription["displayName"]
                    temp["resource_id"] = subscription['subscriptionId']
                    temp["subscription_id"] = subscription['subscriptionId']
                    temp["subscription_name"] = subscription["displayName"]
                issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def enable_application_whitelisting_monitor(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                temp = dict()
                temp["region"] = ""
                url = policy_assignments_url.format(subscription['subscriptionId'])
                token = get_auth_token(self.credentials)
                response = rest_api_call(token, url, api_version='2018-05-01')
                if response['properties']['parameters']:
                    if 'adaptiveApplicationControlsMonitoringEffect' in response['properties']['parameters']:
                        if response['properties']['parameters']['adaptiveApplicationControlsMonitoringEffect']['value'] == "Disabled":
                            temp["status"] = "Fail"
                            temp["resource_name"] = subscription["displayName"]
                            temp["resource_id"] = subscription['subscriptionId']
                            temp["subscription_id"] = subscription['subscriptionId']
                            temp["subscription_name"] = subscription["displayName"]
                        else:
                            temp["status"] = "Pass"
                            temp["resource_name"] = subscription["displayName"]
                            temp["resource_id"] = subscription['subscriptionId']
                            temp["subscription_id"] = subscription['subscriptionId']
                            temp["subscription_name"] = subscription["displayName"]
                    else:
                        temp["status"] = "Fail"
                        temp["resource_name"] = subscription["displayName"]
                        temp["resource_id"] = subscription['subscriptionId']
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]
                else:
                    temp["status"] = "Fail"
                    temp["resource_name"] = subscription["displayName"]
                    temp["resource_id"] = subscription['subscriptionId']
                    temp["subscription_id"] = subscription['subscriptionId']
                    temp["subscription_name"] = subscription["displayName"]
                issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def enable_alert_subscription_owners(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                temp = dict()
                temp["region"] = ""
                url = security_contacts_url.format(subscription['subscriptionId'])
                token = get_auth_token(self.credentials)
                response = rest_api_call(token, url, api_version='2017-08-01-preview')
                if not response['value']:
                    temp["status"] = "Fail"
                    temp["resource_name"] = subscription['displayName']
                    temp["resource_id"] = subscription['subscriptionId']
                    temp["subscription_id"] = subscription['subscriptionId']
                    temp["subscription_name"] = subscription["displayName"]

                else:
                    for value in response['value']:
                        if value['properties']['alertsToAdmins'] == "On":
                            temp["status"] = "Pass"
                            temp["resource_name"] = subscription['displayName']
                            temp["resource_id"] = subscription['subscriptionId']
                            temp["subscription_id"] = subscription['subscriptionId']
                            temp["subscription_name"] = subscription["displayName"]
                        else:
                            temp["status"] = "Fail"
                            temp["resource_name"] = subscription['displayName']
                            temp["resource_id"] = subscription['subscriptionId']
                            temp["subscription_id"] = subscription['subscriptionId']
                            temp["subscription_name"] = subscription["displayName"]
                issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def enable_auto_provision_montioring_agent(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                temp = dict()
                temp["region"] = ""
                url = auto_provision_url.format(subscription['subscriptionId'])
                token = get_auth_token(self.credentials)
                response = rest_api_call(token, url, api_version='2017-08-01-preview')
                if not response['value']:
                    temp["status"] = "Fail"
                    temp["resource_name"] = subscription['displayName']
                    temp["resource_id"] = subscription['subscriptionId']
                    temp["subscription_id"] = subscription['subscriptionId']
                    temp["subscription_name"] = subscription["displayName"]
                else:
                    for value in response['value']:
                        if value['properties']['autoProvision'] == "On":
                            temp["status"] = "Pass"
                            temp["resource_name"] = subscription['displayName']
                            temp["resource_id"] = subscription['subscriptionId']
                            temp["subscription_id"] = subscription['subscriptionId']
                            temp["subscription_name"] = subscription["displayName"]
                        else:
                            temp["status"] = "Fail"
                            temp["resource_name"] = subscription['displayName']
                            temp["resource_id"] = subscription['subscriptionId']
                            temp["subscription_id"] = subscription['subscriptionId']
                            temp["subscription_name"] = subscription["displayName"]
                issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def enable_disk_encryption_monitor(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                temp = dict()
                temp["region"] = ""
                url = policy_assignments_url.format(subscription['subscriptionId'])
                token = get_auth_token(self.credentials)
                response = rest_api_call(token, url, api_version='2018-05-01')
                if response['properties']['parameters']:
                    if 'diskEncryptionMonitoringEffect' in response['properties']['parameters']:
                        if response['properties']['parameters']['diskEncryptionMonitoringEffect']['value'] == "Disabled":
                            temp["status"] = "Fail"
                            temp["resource_name"] = subscription["displayName"]
                            temp["resource_id"] = subscription['subscriptionId']
                            temp["subscription_id"] = subscription['subscriptionId']
                            temp["subscription_name"] = subscription["displayName"]

                        else:
                            temp["status"] = "Pass"
                            temp["resource_name"] = subscription["displayName"]
                            temp["resource_id"] = subscription['subscriptionId']
                            temp["problem"] = "Monitor Disk Encryption feature is enabled for subscription {}".format(subscription['subscriptionId'])
                    else:
                        temp["status"] = "Fail"
                        temp["resource_name"] = subscription["displayName"]
                        temp["resource_id"] = subscription['subscriptionId']
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]
                else:
                    temp["status"] = "Fail"
                    temp["resource_name"] = subscription["displayName"]
                    temp["resource_id"] = subscription['subscriptionId']
                    temp["subscription_id"] = subscription['subscriptionId']
                    temp["subscription_name"] = subscription["displayName"]

                issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def enable_endpoint_protection_monitor(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                temp = dict()
                temp["region"] = ""
                url = policy_assignments_url.format(subscription['subscriptionId'])
                token = get_auth_token(self.credentials)
                response = rest_api_call(token, url, api_version='2018-05-01')
                if response['properties']['parameters']:
                    if 'endpointProtectionMonitoringEffect' in response['properties']['parameters']:
                        if response['properties']['parameters']['endpointProtectionMonitoringEffect']['value'] == "Disabled":
                            temp["status"] = "Fail"
                            temp["resource_name"] = subscription["displayName"]
                            temp["resource_id"] = subscription['subscriptionId']
                            temp["subscription_id"] = subscription['subscriptionId']
                            temp["subscription_name"] = subscription["displayName"]

                        else:
                            temp["status"] = "Pass"
                            temp["resource_name"] = subscription["displayName"]
                            temp["resource_id"] = subscription['subscriptionId']
                            temp["subscription_id"] = subscription['subscriptionId']
                            temp["subscription_name"] = subscription["displayName"]
                    else:
                        temp["status"] = "Fail"
                        temp["resource_name"] = subscription["displayName"]
                        temp["resource_id"] = subscription['subscriptionId']
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]
                else:
                    temp["status"] = "Fail"
                    temp["resource_name"] = subscription["displayName"]
                    temp["resource_id"] = subscription['subscriptionId']
                    temp["subscription_id"] = subscription['subscriptionId']
                    temp["subscription_name"] = subscription["displayName"]
                issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def enable_alert_serverity_notifications(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                temp = dict()
                temp["region"] = ""
                url = security_contacts_url.format(subscription['subscriptionId'])
                token = get_auth_token(self.credentials)
                response = rest_api_call(token, url, api_version='2017-08-01-preview')
                if not response['value']:
                    temp["status"] = "Fail"
                    temp["resource_name"] = subscription['displayName']
                    temp["resource_id"] = subscription['subscriptionId']
                    temp["subscription_id"] = subscription['subscriptionId']
                    temp["subscription_name"] = subscription["displayName"]
                else:
                    for value in response['value']:
                        if value['properties']['alertNotifications'] == "On":
                            temp["status"] = "Pass"
                            temp["resource_name"] = subscription['displayName']
                            temp["resource_id"] = subscription['subscriptionId']
                            temp["subscription_id"] = subscription['subscriptionId']
                            temp["subscription_name"] = subscription["displayName"]
                        else:
                            temp["status"] = "Fail"
                            temp["resource_name"] = subscription['displayName']
                            temp["resource_id"] = subscription['subscriptionId']
                            temp["subscription_id"] = subscription['subscriptionId']
                            temp["subscription_name"] = subscription["displayName"]
                issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def enable_jit_network_access_monitor(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                temp = dict()
                temp["region"] = ""
                url = policy_assignments_url.format(subscription['subscriptionId'])
                token = get_auth_token(self.credentials)
                response = rest_api_call(token, url, api_version='2018-05-01')
                if response['properties']['parameters']:
                    if 'jitNetworkAccessMonitoringEffect' in response['properties']['parameters']:
                        if response['properties']['parameters']['jitNetworkAccessMonitoringEffect']['value'] == "Disabled":
                            temp["status"] = "Fail"
                            temp["resource_name"] = subscription["displayName"]
                            temp["resource_id"] = subscription['subscriptionId']
                            temp["subscription_id"] = subscription['subscriptionId']
                            temp["subscription_name"] = subscription["displayName"]
                        else:
                            temp["status"] = "Pass"
                            temp["resource_name"] = subscription["displayName"]
                            temp["resource_id"] = subscription['subscriptionId']
                            temp["subscription_id"] = subscription['subscriptionId']
                            temp["subscription_name"] = subscription["displayName"]
                    else:
                        temp["status"] = "Fail"
                        temp["resource_name"] = subscription["displayName"]
                        temp["resource_id"] = subscription['subscriptionId']
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]
                else:
                    temp["status"] = "Fail"
                    temp["resource_name"] = subscription["displayName"]
                    temp["resource_id"] = subscription['subscriptionId']
                    temp["subscription_id"] = subscription['subscriptionId']
                    temp["subscription_name"] = subscription["displayName"]
                issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def enable_os_vulnerability_monitor(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                temp = dict()
                temp["region"] = ""
                url = policy_assignments_url.format(subscription['subscriptionId'])
                token = get_auth_token(self.credentials)
                response = rest_api_call(token, url, api_version='2018-05-01')
                if response['properties']['parameters']:
                    if 'systemConfigurationsMonitoringEffect' in response['properties']['parameters']:
                        if response['properties']['parameters']['systemConfigurationsMonitoringEffect']['value'] == "Disabled":
                            temp["status"] = "Fail"
                            temp["resource_name"] = subscription["displayName"]
                            temp["resource_id"] = subscription['subscriptionId']
                            temp["subscription_id"] = subscription['subscriptionId']
                            temp["subscription_name"] = subscription["displayName"]

                        else:
                            temp["status"] = "Pass"
                            temp["resource_name"] = subscription["displayName"]
                            temp["resource_id"] = subscription['subscriptionId']
                            temp["subscription_id"] = subscription['subscriptionId']
                            temp["subscription_name"] = subscription["displayName"]

                    else:
                        temp["status"] = "Fail"
                        temp["resource_name"] = subscription["displayName"]
                        temp["resource_id"] = subscription['subscriptionId']
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]

                else:
                    temp["status"] = "Fail"
                    temp["resource_name"] = subscription["displayName"]
                    temp["resource_id"] = subscription['subscriptionId']
                    temp["subscription_id"] = subscription['subscriptionId']
                    temp["subscription_name"] = subscription["displayName"]

                issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def enable_vulnerability_assesment_monitor(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                temp = dict()
                temp["region"] = ""
                url = policy_assignments_url.format(subscription['subscriptionId'])
                token = get_auth_token(self.credentials)
                response = rest_api_call(token, url, api_version='2018-05-01')
                if response['properties']['parameters']:
                    if 'vulnerabilityAssesmentMonitoringEffect' in response['properties']['parameters']:
                        if response['properties']['parameters']['vulnerabilityAssesmentMonitoringEffect']['value'] == "Disabled":
                            temp["status"] = "Fail"
                            temp["resource_name"] = subscription["displayName"]
                            temp["resource_id"] = subscription['subscriptionId']
                            temp["subscription_id"] = subscription['subscriptionId']
                            temp["subscription_name"] = subscription["displayName"]

                        else:
                            temp["status"] = "Pass"
                            temp["resource_name"] = subscription["displayName"]
                            temp["resource_id"] = subscription['subscriptionId']
                            temp["subscription_id"] = subscription['subscriptionId']
                            temp["subscription_name"] = subscription["displayName"]

                    else:
                        temp["status"] = "Fail"
                        temp["resource_name"] = subscription["displayName"]
                        temp["resource_id"] = subscription['subscriptionId']
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]

                else:
                    temp["status"] = "Fail"
                    temp["resource_name"] = subscription["displayName"]
                    temp["resource_id"] = subscription['subscriptionId']
                    temp["subscription_id"] = subscription['subscriptionId']
                    temp["subscription_name"] = subscription["displayName"]

                issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def enable_security_group_monitor(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                temp = dict()
                temp["region"] = ""
                url = policy_assignments_url.format(subscription['subscriptionId'])
                token = get_auth_token(self.credentials)
                response = rest_api_call(token, url, api_version='2018-05-01')
                if response['properties']['parameters']:
                    if 'networkSecurityGroupsMonitoringEffect' in response['properties']['parameters']:
                        if response['properties']['parameters']['networkSecurityGroupsMonitoringEffect']['value'] == "Disabled":
                            temp["status"] = "Fail"
                            temp["resource_name"] = subscription["displayName"]
                            temp["resource_id"] = subscription['subscriptionId']
                            temp["subscription_id"] = subscription['subscriptionId']
                            temp["subscription_name"] = subscription["displayName"]
                        else:
                            temp["status"] = "Pass"
                            temp["resource_name"] = subscription["displayName"]
                            temp["resource_id"] = subscription['subscriptionId']
                            temp["subscription_id"] = subscription['subscriptionId']
                            temp["subscription_name"] = subscription["displayName"]
                    else:
                        temp["status"] = "Fail"
                        temp["resource_name"] = subscription["displayName"]
                        temp["resource_id"] = subscription['subscriptionId']
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]
                else:
                    temp["status"] = "Fail"
                    temp["resource_name"] = subscription["displayName"]
                    temp["resource_id"] = subscription['subscriptionId']
                    temp["subscription_id"] = subscription['subscriptionId']
                    temp["subscription_name"] = subscription["displayName"]
                issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def enable_ngfw_monitor(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                temp = dict()
                temp["region"] = ""
                url = policy_assignments_url.format(subscription['subscriptionId'])
                token = get_auth_token(self.credentials)
                response = rest_api_call(token, url, api_version='2018-05-01')
                if response['properties']['parameters']:
                    if 'nextGenerationFirewallMonitoringEffect' in response['properties']['parameters']:
                        if response['properties']['parameters']['nextGenerationFirewallMonitoringEffect']['value'] == "Disabled":
                            temp["status"] = "Fail"
                            temp["resource_name"] = subscription["displayName"]
                            temp["resource_id"] = subscription['subscriptionId']
                            temp["subscription_id"] = subscription['subscriptionId']
                            temp["subscription_name"] = subscription["displayName"]
                        else:
                            temp["status"] = "Pass"
                            temp["resource_name"] = subscription["displayName"]
                            temp["resource_id"] = subscription['subscriptionId']
                            temp["subscription_id"] = subscription['subscriptionId']
                            temp["subscription_name"] = subscription["displayName"]
                    else:
                        temp["status"] = "Fail"
                        temp["resource_name"] = subscription["displayName"]
                        temp["resource_id"] = subscription['subscriptionId']
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]
                else:
                    temp["status"] = "Fail"
                    temp["resource_name"] = subscription["displayName"]
                    temp["resource_id"] = subscription['subscriptionId']
                    temp["subscription_id"] = subscription['subscriptionId']
                    temp["subscription_name"] = subscription["displayName"]
                issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def enable_sql_audit_monitor(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                temp = dict()
                temp["region"] = ""
                url = policy_assignments_url.format(subscription['subscriptionId'])
                token = get_auth_token(self.credentials)
                response = rest_api_call(token, url, api_version='2018-05-01')
                if response['properties']['parameters']:
                    if 'sqlAuditingMonitoringEffect' in response['properties']['parameters']:
                        if response['properties']['parameters']['sqlAuditingMonitoringEffect']['value'] == "Disabled":
                            temp["status"] = "Fail"
                            temp["resource_name"] = subscription["displayName"]
                            temp["resource_id"] = subscription['subscriptionId']
                            temp["subscription_id"] = subscription['subscriptionId']
                            temp["subscription_name"] = subscription["displayName"]
                        else:
                            temp["status"] = "Pass"
                            temp["resource_name"] = subscription["displayName"]
                            temp["resource_id"] = subscription['subscriptionId']
                            temp["subscription_id"] = subscription['subscriptionId']
                            temp["subscription_name"] = subscription["displayName"]
                    else:
                        temp["status"] = "Fail"
                        temp["resource_name"] = subscription["displayName"]
                        temp["resource_id"] = subscription['subscriptionId']
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]
                else:
                    temp["status"] = "Fail"
                    temp["resource_name"] = subscription["displayName"]
                    temp["resource_id"] = subscription['subscriptionId']
                    temp["subscription_id"] = subscription['subscriptionId']
                    temp["subscription_name"] = subscription["displayName"]
                issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def enable_sql_encryption_monitor(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                temp = dict()
                temp["region"] = ""
                url = policy_assignments_url.format(subscription['subscriptionId'])
                token = get_auth_token(self.credentials)
                response = rest_api_call(token, url, api_version='2018-05-01')
                if response['properties']['parameters']:
                    if 'sqlEncryptionMonitoringEffect' in response['properties']['parameters']:
                        if response['properties']['parameters']['sqlEncryptionMonitoringEffect']['value'] == "Disabled":
                            temp["status"] = "Fail"
                            temp["resource_name"] = subscription["displayName"]
                            temp["resource_id"] = subscription['subscriptionId']
                            temp["subscription_id"] = subscription['subscriptionId']
                            temp["subscription_name"] = subscription["displayName"]
                        else:
                            temp["status"] = "Pass"
                            temp["resource_name"] = subscription["displayName"]
                            temp["resource_id"] = subscription['subscriptionId']
                            temp["subscription_id"] = subscription['subscriptionId']
                            temp["subscription_name"] = subscription["displayName"]
                    else:
                        temp["status"] = "Fail"
                        temp["resource_name"] = subscription["displayName"]
                        temp["resource_id"] = subscription['subscriptionId']
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]
                else:
                    temp["status"] = "Fail"
                    temp["resource_name"] = subscription["displayName"]
                    temp["resource_id"] = subscription['subscriptionId']
                    temp["subscription_id"] = subscription['subscriptionId']
                    temp["subscription_name"] = subscription["displayName"]
                issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def enable_storage_encryption_monitor(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                temp = dict()
                temp["region"] = ""
                url = policy_assignments_url.format(subscription['subscriptionId'])
                token = get_auth_token(self.credentials)
                response = rest_api_call(token, url, api_version='2018-05-01')
                if response['properties']['parameters']:
                    if 'storageEncryptionMonitoringEffect' in response['properties']['parameters']:
                        if response['properties']['parameters']['storageEncryptionMonitoringEffect']['value'] == "Disabled":
                            temp["status"] = "Fail"
                            temp["resource_name"] = subscription["displayName"]
                            temp["resource_id"] = subscription['subscriptionId']
                            temp["subscription_id"] = subscription['subscriptionId']
                            temp["subscription_name"] = subscription["displayName"]
                        else:
                            temp["status"] = "Pass"
                            temp["resource_name"] = subscription["displayName"]
                            temp["resource_id"] = subscription['subscriptionId']
                            temp["subscription_id"] = subscription['subscriptionId']
                            temp["subscription_name"] = subscription["displayName"]
                    else:
                        temp["status"] = "Fail"
                        temp["resource_name"] = subscription["displayName"]
                        temp["resource_id"] = subscription['subscriptionId']
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]
                else:
                    temp["status"] = "Fail"
                    temp["resource_name"] = subscription["displayName"]
                    temp["resource_id"] = subscription['subscriptionId']
                    temp["subscription_id"] = subscription['subscriptionId']
                    temp["subscription_name"] = subscription["displayName"]
                issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def enable_system_updates_monitor(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                temp = dict()
                temp["region"] = ""
                url = policy_assignments_url.format(subscription['subscriptionId'])
                token = get_auth_token(self.credentials)
                response = rest_api_call(token, url, api_version='2018-05-01')
                if response['properties']['parameters']:
                    if 'systemUpdatesMonitoringEffect' in response['properties']['parameters']:
                        if response['properties']['parameters']['systemUpdatesMonitoringEffect']['value'] == "Disabled":
                            temp["status"] = "Fail"
                            temp["resource_name"] = subscription["displayName"]
                            temp["resource_id"] = subscription['subscriptionId']
                            temp["subscription_id"] = subscription['subscriptionId']
                            temp["subscription_name"] = subscription["displayName"]
                        else:
                            temp["status"] = "Pass"
                            temp["resource_name"] = subscription["displayName"]
                            temp["resource_id"] = subscription['subscriptionId']
                            temp["subscription_id"] = subscription['subscriptionId']
                            temp["subscription_name"] = subscription["displayName"]
                    else:
                        temp["status"] = "Fail"
                        temp["resource_name"] = subscription["displayName"]
                        temp["resource_id"] = subscription['subscriptionId']
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]
                else:
                    temp["status"] = "Fail"
                    temp["resource_name"] = subscription["displayName"]
                    temp["resource_id"] = subscription['subscriptionId']
                    temp["subscription_id"] = subscription['subscriptionId']
                    temp["subscription_name"] = subscription["displayName"]
                issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def enable_web_app_firewall_monitor(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                temp = dict()
                temp["region"] = ""
                url = policy_assignments_url.format(subscription['subscriptionId'])
                token = get_auth_token(self.credentials)
                response = rest_api_call(token, url, api_version='2018-05-01')
                if response['properties']['parameters']:
                    if 'webApplicationFirewallMonitoringEffect' in response['properties']['parameters']:
                        if response['properties']['parameters']['webApplicationFirewallMonitoringEffect']['value'] == "Disabled":
                            temp["status"] = "Fail"
                            temp["resource_name"] = subscription["displayName"]
                            temp["resource_id"] = subscription['subscriptionId']
                            temp["subscription_id"] = subscription['subscriptionId']
                            temp["subscription_name"] = subscription["displayName"]
                        else:
                            temp["status"] = "Pass"
                            temp["resource_name"] = subscription["displayName"]
                            temp["resource_id"] = subscription['subscriptionId']
                            temp["subscription_id"] = subscription['subscriptionId']
                            temp["subscription_name"] = subscription["displayName"]
                    else:
                        temp["status"] = "Fail"
                        temp["resource_name"] = subscription["displayName"]
                        temp["resource_id"] = subscription['subscriptionId']
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]
                else:
                    temp["status"] = "Fail"
                    temp["resource_name"] = subscription["displayName"]
                    temp["resource_id"] = subscription['subscriptionId']
                    temp["subscription_id"] = subscription['subscriptionId']
                    temp["subscription_name"] = subscription["displayName"]
                issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def check_security_email(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                temp = dict()
                temp["region"] = ""
                url = security_contacts_url.format(subscription['subscriptionId'])
                token = get_auth_token(self.credentials)
                response = rest_api_call(token, url, api_version='2017-08-01-preview')
                if not response['value']:
                    temp["status"] = "Fail"
                    temp["resource_name"] = subscription['displayName']
                    temp["resource_id"] = subscription['subscriptionId']
                    temp["subscription_id"] = subscription['subscriptionId']
                    temp["subscription_name"] = subscription["displayName"]

                else:
                    for value in response['value']:
                        if len(value['properties']['email']) > 0:
                            temp["status"] = "Pass"
                            temp["resource_name"] = subscription['displayName']
                            temp["resource_id"] = subscription['subscriptionId']
                            temp["subscription_id"] = subscription['subscriptionId']
                            temp["subscription_name"] = subscription["displayName"]
                        else:
                            temp["status"] = "Fail"
                            temp["resource_name"] = subscription['displayName']
                            temp["resource_id"] = subscription['subscriptionId']
                            temp["subscription_id"] = subscription['subscriptionId']
                            temp["subscription_name"] = subscription["displayName"]
                issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def check_security_phone_number(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                temp = dict()
                temp["region"] = ""
                url = security_contacts_url.format(subscription['subscriptionId'])
                token = get_auth_token(self.credentials)
                response = rest_api_call(token, url, api_version='2017-08-01-preview')
                if not response['value']:
                    temp["status"] = "Fail"
                    temp["resource_name"] = subscription['displayName']
                    temp["resource_id"] = subscription['subscriptionId']
                    temp["subscription_id"] = subscription['subscriptionId']
                    temp["subscription_name"] = subscription["displayName"]
                else:
                    for value in response['value']:
                        if len(value['properties']['phone']) > 0:
                            temp["status"] = "Pass"
                            temp["resource_name"] = subscription['displayName']
                            temp["resource_id"] = subscription['subscriptionId']
                            temp["subscription_id"] = subscription['subscriptionId']
                            temp["subscription_name"] = subscription["displayName"]
                        else:
                            temp["status"] = "Fail"
                            temp["resource_name"] = subscription['displayName']
                            temp["resource_id"] = subscription['subscriptionId']
                            temp["subscription_id"] = subscription['subscriptionId']
                            temp["subscription_name"] = subscription["displayName"]
                issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def enable_standard_pricing(self):
        issues= []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                temp = dict()
                temp["region"] = ""
                url = pricing_url.format(subscription['subscriptionId'])
                token = get_auth_token(self.credentials)
                response = rest_api_call(token, url, api_version='2017-08-01-preview')
                pricing_values = response['value']
                for price in pricing_values:
                    if price['name'] == "default":
                        if price['properties']['pricingTier'] == "Free":
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

