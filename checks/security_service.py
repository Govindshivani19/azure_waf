from checks.common_services import CommonServices
from helper_function import get_auth_token, rest_api_call
from contants import policy_assignments_url, security_contacts_url, auto_provision_url, pricing_url


class SecurityService:
    def __init__(self, credentials):
        self.credentials = credentials

    def enable_application_whitelisting_monitor(self):
        issues = []
        try:
            token = get_auth_token(self.credentials)
            cs = CommonServices()
            subscription_list = cs.get_subscriptions_list(token)
            for subscription in subscription_list:
                temp = dict()
                temp["region"] = ""
                url = policy_assignments_url.format(subscription['subscriptionId'])
                response = rest_api_call(token, url, api_version='2018-05-01')
                if response['properties']['parameters']:
                    if 'adaptiveApplicationControlsMonitoringEffect' in response['properties']['parameters']:
                        if response['properties']['parameters']['adaptiveApplicationControlsMonitoringEffect']['value'] == "Disabled":
                            temp["status"] = "Fail"
                            temp["resource_name"] = subscription["displayName"]
                            temp["resource_id"] = subscription['subscriptionId']
                            temp["problem"] = "Adaptive application whitelisting monitoring is not enabled for Microsoft Azure virtual machines under subscription {}".format(subscription['subscriptionId'])
                        else:
                            temp["status"] = "Pass"
                            temp["resource_name"] = subscription["displayName"]
                            temp["resource_id"] = subscription['subscriptionId']
                            temp["problem"] = "Adaptive application whitelisting monitoring is enabled for Microsoft Azure virtual machines under subscription {}".format(
                                subscription['subscriptionId'])
                    else:
                        temp["status"] = "Fail"
                        temp["resource_name"] = subscription["displayName"]
                        temp["resource_id"] = subscription['subscriptionId']
                        temp["problem"] = "Adaptive application whitelisting monitoring is not enabled for Microsoft Azure virtual machines under subscription {}".format(subscription['subscriptionId'])
                else:
                    temp["status"] = "Fail"
                    temp["resource_name"] = subscription["displayName"]
                    temp["resource_id"] = subscription['subscriptionId']
                    temp["problem"] = "Adaptive application whitelisting monitoring is not enabled for Microsoft Azure virtual machines under subscription {}".format(subscription['subscriptionId'])
                issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def enable_alert_subscription_owners(self):
        issues = []
        try:
            token = get_auth_token(self.credentials)
            cs = CommonServices()
            subscription_list = cs.get_subscriptions_list(token)
            for subscription in subscription_list:
                temp = dict()
                temp["region"] = ""
                url = security_contacts_url.format(subscription['subscriptionId'])
                response = rest_api_call(token, url, api_version='2017-08-01-preview')
                if not response['value']:
                    temp["status"] = "Fail"
                    temp["resource_name"] = subscription['displayName']
                    temp["resource_id"] = subscription['subscriptionId']
                    temp["problem"] = "Azure Security Center is not configured to send alert email notifications to owners of  Azure subscription {}".format(subscription['subscriptionId'])
                else:
                    for value in response['value']:
                        if value['properties']['alertsToAdmins'] == "On":
                            temp["status"] = "Pass"
                            temp["resource_name"] = subscription['displayName']
                            temp["resource_id"] = subscription['subscriptionId']
                            temp["problem"] = "Azure Security Center is configured to send alert email notifications to owners of  Azure subscription {}".format(
                                subscription['subscriptionId'])
                        else:
                            temp["status"] = "Fail"
                            temp["resource_name"] = subscription['displayName']
                            temp["resource_id"] = subscription['subscriptionId']
                            temp["problem"] = "Azure Security Center is not configured to send alert email notifications to owners of  Azure subscription {}".format(
                                subscription['subscriptionId'])
                issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def enable_auto_provision_montioring_agent(self):
        issues = []
        try:
            token = get_auth_token(self.credentials)
            cs = CommonServices()
            subscription_list = cs.get_subscriptions_list(token)
            for subscription in subscription_list:
                temp = dict()
                temp["region"] = ""
                url = auto_provision_url.format(subscription['subscriptionId'])
                response = rest_api_call(token, url, api_version='2017-08-01-preview')
                if not response['value']:
                    temp["status"] = "Fail"
                    temp["resource_name"] = subscription['displayName']
                    temp["resource_id"] = subscription['subscriptionId']
                    temp["problem"] = "Automatic provisioning of the monitoring agent  is not enabled for Azure subscription {}".format(
                        subscription['subscriptionId'])
                else:
                    for value in response['value']:
                        if value['properties']['autoProvision'] == "On":
                            temp["status"] = "Pass"
                            temp["resource_name"] = subscription['displayName']
                            temp["resource_id"] = subscription['subscriptionId']
                            temp["problem"] = "Automatic provisioning of the monitoring agent is enabled for Azure subscription {}".format(
                                subscription['subscriptionId'])
                        else:
                            temp["status"] = "Fail"
                            temp["resource_name"] = subscription['displayName']
                            temp["resource_id"] = subscription['subscriptionId']
                            temp["problem"] = "Automatic provisioning of the monitoring agent  is not enabled for Azure subscription {}".format(
                                subscription['subscriptionId'])
                issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def enable_disk_encryption_monitor(self):
        issues = []
        try:
            token = get_auth_token(self.credentials)
            cs = CommonServices()
            subscription_list = cs.get_subscriptions_list(token)
            for subscription in subscription_list:
                temp = dict()
                temp["region"] = ""
                url = policy_assignments_url.format(subscription['subscriptionId'])
                response = rest_api_call(token, url, api_version='2018-05-01')
                if response['properties']['parameters']:
                    if 'diskEncryptionMonitoringEffect' in response['properties']['parameters']:
                        if response['properties']['parameters']['diskEncryptionMonitoringEffect']['value'] == "Disabled":
                            temp["status"] = "Fail"
                            temp["resource_name"] = subscription["displayName"]
                            temp["resource_id"] = subscription['subscriptionId']
                            temp["problem"] = "Monitor Disk Encryption feature is not enabled for subscription {}".format(subscription['subscriptionId'])
                        else:
                            temp["status"] = "Pass"
                            temp["resource_name"] = subscription["displayName"]
                            temp["resource_id"] = subscription['subscriptionId']
                            temp["problem"] = "Monitor Disk Encryption feature is enabled for subscription {}".format(subscription['subscriptionId'])
                    else:
                        temp["status"] = "Fail"
                        temp["resource_name"] = subscription["displayName"]
                        temp["resource_id"] = subscription['subscriptionId']
                        temp["problem"] = "Monitor Disk Encryption feature is not enabled for subscription {}".format(subscription['subscriptionId'])
                else:
                    temp["status"] = "Fail"
                    temp["resource_name"] = subscription["displayName"]
                    temp["resource_id"] = subscription['subscriptionId']
                    temp["problem"] = "Monitor Disk Encryption feature is not enabled for subscription {}".format(subscription['subscriptionId'])
                issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def enable_endpoint_protection_monitor(self):
        issues = []
        try:
            token = get_auth_token(self.credentials)
            cs = CommonServices()
            subscription_list = cs.get_subscriptions_list(token)
            for subscription in subscription_list:
                temp = dict()
                temp["region"] = ""
                url = policy_assignments_url.format(subscription['subscriptionId'])
                response = rest_api_call(token, url, api_version='2018-05-01')
                if response['properties']['parameters']:
                    if 'endpointProtectionMonitoringEffect' in response['properties']['parameters']:
                        if response['properties']['parameters']['endpointProtectionMonitoringEffect']['value'] == "Disabled":
                            temp["status"] = "Fail"
                            temp["resource_name"] = subscription["displayName"]
                            temp["resource_id"] = subscription['subscriptionId']
                            temp["problem"] = "Endpoint protection monitoring feature is not enabled within Microsoft Azure Security Center for subscription {}".format(subscription['subscriptionId'])
                        else:
                            temp["status"] = "Pass"
                            temp["resource_name"] = subscription["displayName"]
                            temp["resource_id"] = subscription['subscriptionId']
                            temp["problem"] = "Endpoint protection monitoring feature is enabled within Microsoft Azure Security Center for subscription {}".format(subscription['subscriptionId'])
                    else:
                        temp["status"] = "Fail"
                        temp["resource_name"] = subscription["displayName"]
                        temp["resource_id"] = subscription['subscriptionId']
                        temp["problem"] = "Endpoint protection monitoring feature is not enabled within Microsoft Azure Security Center for subscription {}".format(subscription['subscriptionId'])
                else:
                    temp["status"] = "Fail"
                    temp["resource_name"] = subscription["displayName"]
                    temp["resource_id"] = subscription['subscriptionId']
                    temp["problem"] = "Endpoint protection monitoring feature is not enabled within Microsoft Azure Security Center for subscription {}".format(subscription['subscriptionId'])
                issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def enable_alert_serverity_notifications(self):
        issues = []
        try:
            token = get_auth_token(self.credentials)
            cs = CommonServices()
            subscription_list = cs.get_subscriptions_list(token)
            for subscription in subscription_list:
                temp = dict()
                temp["region"] = ""
                url = security_contacts_url.format(subscription['subscriptionId'])
                response = rest_api_call(token, url, api_version='2017-08-01-preview')
                if not response['value']:
                    temp["status"] = "Fail"
                    temp["resource_name"] = subscription['displayName']
                    temp["resource_id"] = subscription['subscriptionId']
                    temp["problem"] = "Sending high severity alert notifications is not enabled for Azure subscription {}".format(subscription['subscriptionId'])
                else:
                    for value in response['value']:
                        if value['properties']['alertNotifications'] == "On":
                            temp["status"] = "Pass"
                            temp["resource_name"] = subscription['displayName']
                            temp["resource_id"] = subscription['subscriptionId']
                            temp["problem"] = "Sending high severity alert notifications is enabled for Azure subscription {}".format(
                                subscription['subscriptionId'])
                        else:
                            temp["status"] = "Fail"
                            temp["resource_name"] = subscription['displayName']
                            temp["resource_id"] = subscription['subscriptionId']
                            temp["problem"] = "Sending high severity alert notifications is not enabled for Azure subscription{}".format(
                                subscription['subscriptionId'])
                issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def enable_jit_network_access_monitor(self):
        issues = []
        try:
            token = get_auth_token(self.credentials)
            cs = CommonServices()
            subscription_list = cs.get_subscriptions_list(token)
            for subscription in subscription_list:
                temp = dict()
                temp["region"] = ""
                url = policy_assignments_url.format(subscription['subscriptionId'])
                response = rest_api_call(token, url, api_version='2018-05-01')
                if response['properties']['parameters']:
                    if 'jitNetworkAccessMonitoringEffect' in response['properties']['parameters']:
                        if response['properties']['parameters']['jitNetworkAccessMonitoringEffect']['value'] == "Disabled":
                            temp["status"] = "Fail"
                            temp["resource_name"] = subscription["displayName"]
                            temp["resource_id"] = subscription['subscriptionId']
                            temp["problem"] = "JIT network access monitoring is not enabled within Microsoft Azure Security Center for subscription {}".format(subscription['subscriptionId'])
                        else:
                            temp["status"] = "Pass"
                            temp["resource_name"] = subscription["displayName"]
                            temp["resource_id"] = subscription['subscriptionId']
                            temp["problem"] = "JIT network access monitoring is enabled within Microsoft Azure Security Center for subscription {}".format(subscription['subscriptionId'])
                    else:
                        temp["status"] = "Fail"
                        temp["resource_name"] = subscription["displayName"]
                        temp["resource_id"] = subscription['subscriptionId']
                        temp["problem"] = "JIT network access monitoring is not enabled within Microsoft Azure Security Center for subscription {}".format(subscription['subscriptionId'])
                else:
                    temp["status"] = "Fail"
                    temp["resource_name"] = subscription["displayName"]
                    temp["resource_id"] = subscription['subscriptionId']
                    temp["problem"] = "JIT network access monitoring is not enabled within Microsoft Azure Security Center for subscription {}".format(subscription['subscriptionId'])
                issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def enable_os_vulnerability_monitor(self):
        issues = []
        try:
            token = get_auth_token(self.credentials)
            cs = CommonServices()
            subscription_list = cs.get_subscriptions_list(token)
            for subscription in subscription_list:
                temp = dict()
                temp["region"] = ""
                url = policy_assignments_url.format(subscription['subscriptionId'])
                response = rest_api_call(token, url, api_version='2018-05-01')
                if response['properties']['parameters']:
                    if 'systemConfigurationsMonitoringEffect' in response['properties']['parameters']:
                        if response['properties']['parameters']['systemConfigurationsMonitoringEffect']['value'] == "Disabled":
                            temp["status"] = "Fail"
                            temp["resource_name"] = subscription["displayName"]
                            temp["resource_id"] = subscription['subscriptionId']
                            temp["problem"] = "Monitor OS Vulnerabilities is not enabled within Microsoft Azure Security Center for subscription {}".format(subscription['subscriptionId'])
                        else:
                            temp["status"] = "Pass"
                            temp["resource_name"] = subscription["displayName"]
                            temp["resource_id"] = subscription['subscriptionId']
                            temp["problem"] = "Monitor OS Vulnerabilities is enabled within Microsoft Azure Security Center for subscription {}".format(subscription['subscriptionId'])
                    else:
                        temp["status"] = "Fail"
                        temp["resource_name"] = subscription["displayName"]
                        temp["resource_id"] = subscription['subscriptionId']
                        temp["problem"] = "Monitor OS Vulnerabilities is not enabled within Microsoft Azure Security Center for subscription {}".format(subscription['subscriptionId'])
                else:
                    temp["status"] = "Fail"
                    temp["resource_name"] = subscription["displayName"]
                    temp["resource_id"] = subscription['subscriptionId']
                    temp["problem"] = "Monitor OS Vulnerabilities is not enabled within Microsoft Azure Security Center for subscription {}".format(subscription['subscriptionId'])
                issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def enable_vulnerability_assesment_monitor(self):
        issues = []
        try:
            token = get_auth_token(self.credentials)
            cs = CommonServices()
            subscription_list = cs.get_subscriptions_list(token)
            for subscription in subscription_list:
                temp = dict()
                temp["region"] = ""
                url = policy_assignments_url.format(subscription['subscriptionId'])
                response = rest_api_call(token, url, api_version='2018-05-01')
                if response['properties']['parameters']:
                    if 'vulnerabilityAssesmentMonitoringEffect' in response['properties']['parameters']:
                        if response['properties']['parameters']['vulnerabilityAssesmentMonitoringEffect']['value'] == "Disabled":
                            temp["status"] = "Fail"
                            temp["resource_name"] = subscription["displayName"]
                            temp["resource_id"] = subscription['subscriptionId']
                            temp["problem"] = "Vulnerability assessment monitoring is not enabled within Microsoft Azure Security Center for subscription {}".format(subscription['subscriptionId'])
                        else:
                            temp["status"] = "Pass"
                            temp["resource_name"] = subscription["displayName"]
                            temp["resource_id"] = subscription['subscriptionId']
                            temp["problem"] = "Vulnerability assessment monitoring is enabled within Microsoft Azure Security Center for subscription {}".format(subscription['subscriptionId'])
                    else:
                        temp["status"] = "Fail"
                        temp["resource_name"] = subscription["displayName"]
                        temp["resource_id"] = subscription['subscriptionId']
                        temp["problem"] = "Vulnerability assessment monitoring is not enabled within Microsoft Azure Security Center for subscription {}".format(subscription['subscriptionId'])
                else:
                    temp["status"] = "Fail"
                    temp["resource_name"] = subscription["displayName"]
                    temp["resource_id"] = subscription['subscriptionId']
                    temp["problem"] = "Vulnerability assessment monitoring is not enabled within Microsoft Azure Security Center for subscription {}".format(subscription['subscriptionId'])
                issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def enable_security_group_monitor(self):
        issues = []
        try:
            token = get_auth_token(self.credentials)
            cs = CommonServices()
            subscription_list = cs.get_subscriptions_list(token)
            for subscription in subscription_list:
                temp = dict()
                temp["region"] = ""
                url = policy_assignments_url.format(subscription['subscriptionId'])
                response = rest_api_call(token, url, api_version='2018-05-01')
                if response['properties']['parameters']:
                    if 'networkSecurityGroupsMonitoringEffect' in response['properties']['parameters']:
                        if response['properties']['parameters']['networkSecurityGroupsMonitoringEffect']['value'] == "Disabled":
                            temp["status"] = "Fail"
                            temp["resource_name"] = subscription["displayName"]
                            temp["resource_id"] = subscription['subscriptionId']
                            temp["problem"] = "Network Security Groups monitoring is not enabled in Microsoft Azure Security Center for subscription {}".format(
                                subscription['subscriptionId'])
                        else:
                            temp["status"] = "Pass"
                            temp["resource_name"] = subscription["displayName"]
                            temp["resource_id"] = subscription['subscriptionId']
                            temp["problem"] = "Network Security Groups monitoring is enabled in Microsoft Azure Security Center for subscription {}".format(
                                subscription['subscriptionId'])
                    else:
                        temp["status"] = "Fail"
                        temp["resource_name"] = subscription["displayName"]
                        temp["resource_id"] = subscription['subscriptionId']
                        temp["problem"] = "Network Security Groups monitoring is not enabled in Microsoft Azure Security Center for subscription {}".format(
                            subscription['subscriptionId'])
                else:
                    temp["status"] = "Fail"
                    temp["resource_name"] = subscription["displayName"]
                    temp["resource_id"] = subscription['subscriptionId']
                    temp["problem"] = "Network Security Groups monitoring is not enabled in Microsoft Azure Security Center for subscription {}".format(
                        subscription['subscriptionId'])
                issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def enable_ngfw_monitor(self):
        issues = []
        try:
            token = get_auth_token(self.credentials)
            cs = CommonServices()
            subscription_list = cs.get_subscriptions_list(token)
            for subscription in subscription_list:
                temp = dict()
                temp["region"] = ""
                url = policy_assignments_url.format(subscription['subscriptionId'])
                response = rest_api_call(token, url, api_version='2018-05-01')
                if response['properties']['parameters']:
                    if 'nextGenerationFirewallMonitoringEffect' in response['properties']['parameters']:
                        if response['properties']['parameters']['nextGenerationFirewallMonitoringEffect']['value'] == "Disabled":
                            temp["status"] = "Fail"
                            temp["resource_name"] = subscription["displayName"]
                            temp["resource_id"] = subscription['subscriptionId']
                            temp["problem"] = "Next Generation Firewall (NGFW) monitoring is not enabled in Microsoft Azure Security Center for subscription {}".format(
                                subscription['subscriptionId'])
                        else:
                            temp["status"] = "Pass"
                            temp["resource_name"] = subscription["displayName"]
                            temp["resource_id"] = subscription['subscriptionId']
                            temp["problem"] = "Next Generation Firewall (NGFW) monitoring is enabled in Microsoft Azure Security Center for subscription {}".format(
                                subscription['subscriptionId'])
                    else:
                        temp["status"] = "Fail"
                        temp["resource_name"] = subscription["displayName"]
                        temp["resource_id"] = subscription['subscriptionId']
                        temp["problem"] = "Next Generation Firewall (NGFW) monitoring is not enabled in Microsoft Azure Security Center for subscription {}".format(
                            subscription['subscriptionId'])
                else:
                    temp["status"] = "Fail"
                    temp["resource_name"] = subscription["displayName"]
                    temp["resource_id"] = subscription['subscriptionId']
                    temp["problem"] = "Next Generation Firewall (NGFW) monitoring is not enabled in Microsoft Azure Security Center for subscription {}".format(
                        subscription['subscriptionId'])
                issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def enable_sql_audit_monitor(self):
        issues = []
        try:
            token = get_auth_token(self.credentials)
            cs = CommonServices()
            subscription_list = cs.get_subscriptions_list(token)
            for subscription in subscription_list:
                temp = dict()
                temp["region"] = ""
                url = policy_assignments_url.format(subscription['subscriptionId'])
                response = rest_api_call(token, url, api_version='2018-05-01')
                if response['properties']['parameters']:
                    if 'sqlAuditingMonitoringEffect' in response['properties']['parameters']:
                        if response['properties']['parameters']['sqlAuditingMonitoringEffect']['value'] == "Disabled":
                            temp["status"] = "Fail"
                            temp["resource_name"] = subscription["displayName"]
                            temp["resource_id"] = subscription['subscriptionId']
                            temp["problem"] = "SQL auditing monitoring is not enabled in Microsoft Azure Security Center for subscription {}".format(
                                subscription['subscriptionId'])
                        else:
                            temp["status"] = "Pass"
                            temp["resource_name"] = subscription["displayName"]
                            temp["resource_id"] = subscription['subscriptionId']
                            temp["problem"] = "SQL auditing monitoring is enabled in Microsoft Azure Security Center for subscription {}".format(
                                subscription['subscriptionId'])
                    else:
                        temp["status"] = "Fail"
                        temp["resource_name"] = subscription["displayName"]
                        temp["resource_id"] = subscription['subscriptionId']
                        temp["problem"] = "SQL auditing monitoring is not enabled in Microsoft Azure Security Center for subscription {}".format(
                            subscription['subscriptionId'])
                else:
                    temp["status"] = "Fail"
                    temp["resource_name"] = subscription["displayName"]
                    temp["resource_id"] = subscription['subscriptionId']
                    temp["problem"] = "SQL auditing monitoring is not enabled in Microsoft Azure Security Center for subscription {}".format(
                        subscription['subscriptionId'])
                issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def enable_sql_encryption_monitor(self):
        issues = []
        try:
            token = get_auth_token(self.credentials)
            cs = CommonServices()
            subscription_list = cs.get_subscriptions_list(token)
            for subscription in subscription_list:
                temp = dict()
                temp["region"] = ""
                url = policy_assignments_url.format(subscription['subscriptionId'])
                response = rest_api_call(token, url, api_version='2018-05-01')
                if response['properties']['parameters']:
                    if 'sqlEncryptionMonitoringEffect' in response['properties']['parameters']:
                        if response['properties']['parameters']['sqlEncryptionMonitoringEffect']['value'] == "Disabled":
                            temp["status"] = "Fail"
                            temp["resource_name"] = subscription["displayName"]
                            temp["resource_id"] = subscription['subscriptionId']
                            temp["problem"] = "SQL encryption monitoring is not enabled in Microsoft Azure Security Center for subscription {}".format(
                                subscription['subscriptionId'])
                        else:
                            temp["status"] = "Pass"
                            temp["resource_name"] = subscription["displayName"]
                            temp["resource_id"] = subscription['subscriptionId']
                            temp["problem"] = "SQL encryption monitoring is enabled in Microsoft Azure Security Center for subscription {}".format(
                                subscription['subscriptionId'])
                    else:
                        temp["status"] = "Fail"
                        temp["resource_name"] = subscription["displayName"]
                        temp["resource_id"] = subscription['subscriptionId']
                        temp["problem"] = "SQL encryption monitoring is not enabled in Microsoft Azure Security Center for subscription {}".format(
                            subscription['subscriptionId'])
                else:
                    temp["status"] = "Fail"
                    temp["resource_name"] = subscription["displayName"]
                    temp["resource_id"] = subscription['subscriptionId']
                    temp["problem"] = "SQL encryption monitoring is not enabled in Microsoft Azure Security Center for subscription {}".format(
                        subscription['subscriptionId'])
                issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def enable_storage_encryption_monitor(self):
        issues = []
        try:
            token = get_auth_token(self.credentials)
            cs = CommonServices()
            subscription_list = cs.get_subscriptions_list(token)
            for subscription in subscription_list:
                temp = dict()
                temp["region"] = ""
                url = policy_assignments_url.format(subscription['subscriptionId'])
                response = rest_api_call(token, url, api_version='2018-05-01')
                if response['properties']['parameters']:
                    if 'storageEncryptionMonitoringEffect' in response['properties']['parameters']:
                        if response['properties']['parameters']['storageEncryptionMonitoringEffect']['value'] == "Disabled":
                            temp["status"] = "Fail"
                            temp["resource_name"] = subscription["displayName"]
                            temp["resource_id"] = subscription['subscriptionId']
                            temp["problem"] = "Storage encryption monitoring is not enabled in Microsoft Azure Security Center for subscription {}".format(
                                subscription['subscriptionId'])
                        else:
                            temp["status"] = "Pass"
                            temp["resource_name"] = subscription["displayName"]
                            temp["resource_id"] = subscription['subscriptionId']
                            temp["problem"] = "Storage encryption monitoring is enabled in Microsoft Azure Security Center for subscription {}".format(
                                subscription['subscriptionId'])
                    else:
                        temp["status"] = "Fail"
                        temp["resource_name"] = subscription["displayName"]
                        temp["resource_id"] = subscription['subscriptionId']
                        temp["problem"] = "Storage encryption monitoring is not enabled in Microsoft Azure Security Center for subscription {}".format(
                            subscription['subscriptionId'])
                else:
                    temp["status"] = "Fail"
                    temp["resource_name"] = subscription["displayName"]
                    temp["resource_id"] = subscription['subscriptionId']
                    temp["problem"] = "Storage encryption monitoring is not enabled in Microsoft Azure Security Center for subscription {}".format(
                        subscription['subscriptionId'])
                issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def enable_system_updates_monitor(self):
        issues = []
        try:
            token = get_auth_token(self.credentials)
            cs = CommonServices()
            subscription_list = cs.get_subscriptions_list(token)
            for subscription in subscription_list:
                temp = dict()
                temp["region"] = ""
                url = policy_assignments_url.format(subscription['subscriptionId'])
                response = rest_api_call(token, url, api_version='2018-05-01')
                if response['properties']['parameters']:
                    if 'systemUpdatesMonitoringEffect' in response['properties']['parameters']:
                        if response['properties']['parameters']['systemUpdatesMonitoringEffect']['value'] == "Disabled":
                            temp["status"] = "Fail"
                            temp["resource_name"] = subscription["displayName"]
                            temp["resource_id"] = subscription['subscriptionId']
                            temp["problem"] = "Monitor System Updates is not enabled in Microsoft Azure Security Center for subscription {}".format(
                                subscription['subscriptionId'])
                        else:
                            temp["status"] = "Pass"
                            temp["resource_name"] = subscription["displayName"]
                            temp["resource_id"] = subscription['subscriptionId']
                            temp["problem"] = "Monitor System Updates is enabled in Microsoft Azure Security Center for subscription {}".format(
                                subscription['subscriptionId'])
                    else:
                        temp["status"] = "Fail"
                        temp["resource_name"] = subscription["displayName"]
                        temp["resource_id"] = subscription['subscriptionId']
                        temp["problem"] = "Monitor System Updates is not enabled in Microsoft Azure Security Center for subscription {}".format(
                            subscription['subscriptionId'])
                else:
                    temp["status"] = "Fail"
                    temp["resource_name"] = subscription["displayName"]
                    temp["resource_id"] = subscription['subscriptionId']
                    temp["problem"] = "Monitor System Updates is not enabled in Microsoft Azure Security Center for subscription {}".format(
                        subscription['subscriptionId'])
                issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def enable_web_app_firewall_monitor(self):
        issues = []
        try:
            token = get_auth_token(self.credentials)
            cs = CommonServices()
            subscription_list = cs.get_subscriptions_list(token)
            for subscription in subscription_list:
                temp = dict()
                temp["region"] = ""
                url = policy_assignments_url.format(subscription['subscriptionId'])
                response = rest_api_call(token, url, api_version='2018-05-01')
                if response['properties']['parameters']:
                    if 'webApplicationFirewallMonitoringEffect' in response['properties']['parameters']:
                        if response['properties']['parameters']['webApplicationFirewallMonitoringEffect']['value'] == "Disabled":
                            temp["status"] = "Fail"
                            temp["resource_name"] = subscription["displayName"]
                            temp["resource_id"] = subscription['subscriptionId']
                            temp["problem"] = "Web Application Firewall (WAF) monitoring is not enabled in Microsoft Azure Security Center for subscription {}".format(
                                subscription['subscriptionId'])
                        else:
                            temp["status"] = "Pass"
                            temp["resource_name"] = subscription["displayName"]
                            temp["resource_id"] = subscription['subscriptionId']
                            temp["problem"] = "Web Application Firewall (WAF) monitoring is enabled in Microsoft Azure Security Center for subscription {}".format(
                                subscription['subscriptionId'])
                    else:
                        temp["status"] = "Fail"
                        temp["resource_name"] = subscription["displayName"]
                        temp["resource_id"] = subscription['subscriptionId']
                        temp["problem"] = "Web Application Firewall (WAF) monitoring is not enabled in Microsoft Azure Security Center for subscription {}".format(
                            subscription['subscriptionId'])
                else:
                    temp["status"] = "Fail"
                    temp["resource_name"] = subscription["displayName"]
                    temp["resource_id"] = subscription['subscriptionId']
                    temp["problem"] = "Web Application Firewall (WAF) monitoring is not enabled in Microsoft Azure Security Center for subscription {}".format(
                        subscription['subscriptionId'])
                issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def check_security_email(self):
        issues = []
        try:
            token = get_auth_token(self.credentials)
            cs = CommonServices()
            subscription_list = cs.get_subscriptions_list(token)
            for subscription in subscription_list:
                temp = dict()
                temp["region"] = ""
                url = security_contacts_url.format(subscription['subscriptionId'])
                response = rest_api_call(token, url, api_version='2017-08-01-preview')
                if not response['value']:
                    temp["status"] = "Fail"
                    temp["resource_name"] = subscription['displayName']
                    temp["resource_id"] = subscription['subscriptionId']
                    temp["problem"] = "Security contact email addresses is not defined within Azure Security Center settings for Azure subscription {}".format(subscription['subscriptionId'])
                else:
                    for value in response['value']:
                        if len(value['properties']['email']) > 0:
                            temp["status"] = "Pass"
                            temp["resource_name"] = subscription['displayName']
                            temp["resource_id"] = subscription['subscriptionId']
                            temp["problem"] = "Security contact email addresses is defined within Azure Security Center settings for Azure subscription {}".format(
                                subscription['subscriptionId'])
                        else:
                            temp["status"] = "Fail"
                            temp["resource_name"] = subscription['displayName']
                            temp["resource_id"] = subscription['subscriptionId']
                            temp["problem"] = "Security contact email addresses is not defined within Azure Security Center settings for Azure subscription {}".format(
                                subscription['subscriptionId'])
                issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def check_security_phone_number(self):
        issues = []
        try:
            token = get_auth_token(self.credentials)
            cs = CommonServices()
            subscription_list = cs.get_subscriptions_list(token)
            for subscription in subscription_list:
                temp = dict()
                temp["region"] = ""
                url = security_contacts_url.format(subscription['subscriptionId'])
                response = rest_api_call(token, url, api_version='2017-08-01-preview')
                if not response['value']:
                    temp["status"] = "Fail"
                    temp["resource_name"] = subscription['displayName']
                    temp["resource_id"] = subscription['subscriptionId']
                    temp["problem"] = "Security contact phone number is not defined within Azure Security Center settings for Azure subscription {}".format(subscription['subscriptionId'])
                else:
                    for value in response['value']:
                        if len(value['properties']['phone']) > 0:
                            temp["status"] = "Pass"
                            temp["resource_name"] = subscription['displayName']
                            temp["resource_id"] = subscription['subscriptionId']
                            temp["problem"] = "Security contact phone number is defined within Azure Security Center settings for Azure subscription {}".format(
                                subscription['subscriptionId'])
                        else:
                            temp["status"] = "Fail"
                            temp["resource_name"] = subscription['displayName']
                            temp["resource_id"] = subscription['subscriptionId']
                            temp["problem"] = "Security contact phone number is not defined within Azure Security Center settings for Azure subscription {}".format(
                                subscription['subscriptionId'])
                issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def enable_standard_pricing(self):
        issues= []
        try:
            token = get_auth_token(self.credentials)
            cs = CommonServices()
            subscription_list = cs.get_subscriptions_list(token)
            for subscription in subscription_list:
                temp = dict()
                temp["region"] = ""
                url = pricing_url.format(subscription['subscriptionId'])
                response = rest_api_call(token, url, api_version='2017-08-01-preview')
                pricing_values = response['value']
                for price in pricing_values:
                    if price['name'] == "default":
                        if price['properties']['pricingTier'] == "Free":
                            temp["status"] = "Fail"
                            temp["resource_name"] = subscription['displayName']
                            temp["resource_id"] = subscription['subscriptionId']
                            temp["problem"] = "Standard pricing tier is not enabled within your Azure Storage account {}.".format(subscription['displayName'])
                        else:
                            temp["status"] = "Pass"
                            temp["resource_name"] = subscription['displayName']
                            temp["resource_id"] = subscription['subscriptionId']
                            temp["problem"] = "Standard pricing tier is enabled within your Azure Storage account {}.".format(subscription['displayName'])
                        issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

