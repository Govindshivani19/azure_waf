from helper_function import rest_api_call
from constants import vm_list_url, base_url, disk_list_url, public_ips_url, vm_scale_set_url, list_vaults_url
import requests
import json
import re


class VmService:
    def __init__(self, credentials, subscription_list):
        self.credentials = credentials
        self.subscription_list = subscription_list

    def unused_virtual_machines(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                instance_list = []
                url = vm_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(self.credentials, url, api_version='2019-07-01')
                for instance in response['value']:
                    instance_list.append(instance)
                for instance in instance_list:
                    temp = dict()
                    temp['region'] = instance["location"]
                    instance_view_url = base_url + instance["id"] + "/instanceView"
                    response = rest_api_call(self.credentials, instance_view_url, api_version='2019-07-01')
                    for status in response["statuses"]:
                        if status['code'] == "PowerState/deallocated":
                            temp["status"] = "Fail"
                            temp["resource_name"] = instance["name"]
                            temp["resource_id"] = instance["properties"]["vmId"]
                            temp["subscription_id"] = subscription['subscriptionId']
                            temp["subscription_name"] = subscription["displayName"]
                        else:
                            temp["status"] = "Pass"
                            temp["resource_name"] = instance["name"]
                            temp["resource_id"] = instance["id"]
                            temp["subscription_id"] = subscription['subscriptionId']
                            temp["subscription_name"] = subscription["displayName"]
                        issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def unused_volumes(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                disk_list = []
                url = disk_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(self.credentials, url, api_version='2019-07-01')
                for disk in response['value']:
                    disk_list.append(disk)

                for disk in disk_list:
                    temp = dict()
                    temp['region'] = disk["location"]
                    if disk["properties"]["diskState"] == "Unattached":
                        temp["status"] = "Fail"
                        temp["resource_name"] = disk["name"]
                        temp["resource_id"] = disk["id"]
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]
                    else:
                        temp["status"] = "Pass"
                        temp["resource_name"] = disk["name"]
                        temp["resource_id"] = disk["id"]
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]
                    issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def vm_with_no_managed_disks(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                instance_list = []
                url = vm_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(self.credentials, url, api_version='2019-07-01')
                for instance in response['value']:
                    instance_list.append(instance)
                for instance in instance_list:
                    temp = dict()
                    if 'managedDisk' in instance['properties']["storageProfile"]['osDisk']:
                        if len(instance['properties']["storageProfile"]['osDisk']['managedDisk']) > 1:
                            temp['region'] = instance["location"]
                            temp["status"] = "Pass"
                            temp["resource_name"] = instance["name"]
                            temp["resource_id"] = instance["properties"]["vmId"]
                            temp["subscription_id"] = subscription['subscriptionId']
                            temp["subscription_name"] = subscription["displayName"]
                    else:
                        temp['region'] = instance["location"]
                        temp["status"] = "Fail"
                        temp["resource_name"] = instance["name"]
                        temp["resource_id"] = instance["properties"]["vmId"]
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]
                    if temp:
                        issues.append(temp)
        except Exception as e:
            print(str(e))
        return issues

    def linux_vm_security_groups(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                instance_list = []
                url = vm_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(self.credentials, url, api_version='2019-07-01')
                for instance in response['value']:
                    instance_list.append(instance)
                for instance in instance_list:
                    x = re.findall("Linux", instance["properties"]["storageProfile"]["osDisk"]["osType"])
                    if x:
                        temp = dict()
                        network_interface_list = instance["properties"]["networkProfile"]["networkInterfaces"]
                        for network in network_interface_list:
                            sg_list = []
                            sg_url = base_url + network["id"] + "/effectiveNetworkSecurityGroups/"
                            headers = {'Authorization': 'Bearer ' + token['accessToken'],
                                       'Content-Type': 'application/json'}

                            params = {'api-version': '2019-11-01'}
                            sg_response = requests.post(sg_url, headers=headers, params=params)
                            if sg_response.status_code == 200:
                                temp["region"] = instance["location"]
                                temp["status"] = "Fail"
                                temp["resource_name"] = instance["name"]
                                temp["resource_id"] = instance["properties"]["vmId"]
                                temp["subscription_id"] = subscription['subscriptionId']
                                temp["subscription_name"] = subscription["displayName"]
                                sg_response = sg_response.json()
                                for sg in sg_response['value']:
                                    sg_list.append(sg)
                                for sg in sg_list:
                                    for sg_rule in sg["effectiveSecurityRules"]:
                                        if sg_rule["destinationPortRange"] == "22-22" and sg_rule["sourcePortRange"] == "0-65535" and sg_rule["direction"] == "Inbound":
                                            if sg_rule["access"] == "Deny":
                                                temp["status"] = "Pass"
                        if temp:
                            issues.append(temp)

        except Exception as e:
            print(str(e))
        finally:
            return issues

    def vm_disks_without_encryption(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                instance_list = []
                url = vm_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(self.credentials, url, api_version='2019-07-01')
                for instance in response['value']:
                    instance_list.append(instance)
                for instance in instance_list:
                    temp = dict()
                    temp["region"] = instance["location"]
                    temp["value_one"] = instance["name"]
                    temp["subscription_id"] = subscription['subscriptionId']
                    temp["subscription_name"] = subscription["displayName"]

                    if 'managedDisk' in instance["properties"]["storageProfile"]["osDisk"]:
                        disk_id = instance["properties"]["storageProfile"]["osDisk"]["managedDisk"]["id"]
                        disk_url = base_url + disk_id
                        disk_response = rest_api_call(self.credentials, disk_url, api_version='2019-07-01')
                        if "encryptionSettingsCollection" in disk_response["properties"]:
                            if disk_response["properties"]["encryptionSettingsCollection"]["enabled"]:
                                temp["status"] = "Pass"
                                temp["resource_name"] = disk_response["name"]
                            else:
                                temp["status"] = "Failed"
                                temp["resource_name"] = disk_response["name"]
                        else:
                            temp["status"] = "Fail"
                            temp["resource_name"] = disk_response["name"]

                        issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def encrypt_unattached_disks(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                disk_list = []
                url = disk_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(self.credentials, url, api_version='2019-07-01')
                for disk in response['value']:
                    disk_list.append(disk)

                for disk in disk_list:
                    temp = dict()
                    temp['region'] = disk["location"]
                    if disk["properties"]["diskState"] == "Unattached":
                        if "encryptionSettingsCollection" in disk["properties"]:
                            if disk["properties"]["encryptionSettingsCollection"]["enabled"]:
                                temp["status"] = "Pass"
                                temp["resource_name"] = disk["name"]
                                temp["subscription_id"] = subscription['subscriptionId']
                                temp["subscription_name"] = subscription["displayName"]
                                issues.append(temp)
                            else:
                                temp["status"] = "Fail"
                                temp["resource_name"] = disk["name"]
                                temp["subscription_id"] = subscription['subscriptionId']
                                temp["subscription_name"] = subscription["displayName"]
                                issues.append(temp)
                        else:
                            temp["status"] = "Fail"
                            temp["resource_name"] = disk["name"]
                            temp["subscription_id"] = subscription['subscriptionId']
                            temp["subscription_name"] = subscription["displayName"]
                            issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def check_tagging(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                instance_list = []
                url = vm_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(self.credentials, url, api_version='2019-07-01')
                for instance in response['value']:
                    instance_list.append(instance)
                for instance in instance_list:
                    temp = dict()
                    if "tags" in instance:
                        if instance["tags"]:
                            temp["region"] = instance["location"]
                            temp["status"] = "Pass"
                            temp["resource_name"] = instance["name"]
                            temp["resource_id"] = instance["properties"]["vmId"]
                            temp["subscription_id"] = subscription['subscriptionId']
                            temp["subscription_name"] = subscription["displayName"]
                        else:
                            temp["region"] = instance["location"]
                            temp["status"] = "Fail"
                            temp["resource_name"] = instance["name"]
                            temp["resource_id"] = instance["properties"]["vmId"]
                            temp["subscription_id"] = subscription['subscriptionId']
                            temp["subscription_name"] = subscription["displayName"]
                    else:
                        temp["region"] = instance["location"]
                        temp["status"] = "Fail"
                        temp["resource_name"] = instance["name"]
                        temp["resource_id"] = instance["properties"]["vmId"]
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]

                    issues.append(temp)

        except Exception as e:
            print(str(e))
        finally:
            return issues

    def check_unused_public_ips(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                ips_list = []
                url = public_ips_url.format(subscription['subscriptionId'])
                response = rest_api_call(self.credentials, url, api_version='2019-11-01')
                for ips in response['value']:
                    ips_list.append(ips)
                for ip in ips_list:
                    temp = dict()
                    temp["region"] = ip["location"]
                    temp["resource_name"] = ip["name"]
                    temp["subscription_id"] = subscription['subscriptionId']
                    temp["subscription_name"] = subscription["displayName"]
                    if "ipConfiguration" in ip["properties"]:
                        temp["status"] = "Pass"
                    else:
                        temp["status"] = "Fail"
                    issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def check_vm_backup_enabled(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                vault_list = []
                backed_up_vm = []
                instance_list = []
                url = list_vaults_url.format(subscription['subscriptionId'])
                response = rest_api_call(self.credentials, url, api_version='2016-06-01')
                for vault in response['value']:
                    vault_list.append(vault)
                for vault in vault_list:
                    recover_url = base_url + vault["id"] + "/backupProtectedItems"
                    recovery_response = rest_api_call(self.credentials, recover_url, api_version='2019-05-13')
                    for v in recovery_response["value"]:
                        if v["properties"]["protectedItemType"] == "Microsoft.Compute/virtualMachines":
                            if v["properties"]["protectionState"] != "ProtectionStopped":
                                backed_up_vm.append(v["properties"]["friendlyName"])

                vm_url = vm_list_url.format(subscription['subscriptionId'])
                vm_response = rest_api_call(self.credentials, vm_url, api_version='2019-07-01')
                for instance in vm_response['value']:
                    instance_list.append(instance)
                for instance in instance_list:
                    temp = dict()
                    if instance["name"] in backed_up_vm:
                        temp["region"] = instance["location"]
                        temp["status"] = "Pass"
                        temp["resource_name"] = instance["name"]
                        temp["resource_id"] = instance["properties"]["vmId"]
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]
                    else:
                        temp["region"] = instance["location"]
                        temp["status"] = "Fail"
                        temp["resource_name"] = instance["name"]
                        temp["resource_id"] = instance["properties"]["vmId"]
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]
                    issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def check_vm_disaster_recovery(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                instance_list = []
                url = vm_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(self.credentials, url, api_version='2019-07-01')
                for instance in response['value']:
                    instance_list.append(instance)
                for instance in instance_list:
                    temp = dict()
                    temp["region"] = instance["location"]
                    temp["status"] = "Fail"
                    temp["resource_name"] = instance["name"]
                    temp["resource_id"] = instance["properties"]["vmId"]
                    temp["subscription_id"] = subscription['subscriptionId']
                    temp["subscription_name"] = subscription["displayName"]
                    extension_list = []
                    extensions_url = base_url + instance["id"] + "/extensions"
                    ext_response = rest_api_call(self.credentials, extensions_url, api_version='2019-07-01')
                    for ext in ext_response['value']:
                        extension_list.append(ext)
                    for ext in extension_list:
                        x = re.findall("ASR-Protect-*", ext["name"])
                        if x :
                            temp["status"] = "Pass"
                    issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def check_time_zone(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                instance_list = []
                url = vm_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(self.credentials, url, api_version='2019-07-01')
                for instance in response['value']:
                    instance_list.append(instance)
                for instance in instance_list:
                    x = re.findall("Windows", instance["properties"]["storageProfile"]["osDisk"]["osType"])
                    if x:
                        temp = dict()
                        temp["region"] = instance["location"]
                        temp["status"] = "Fail"
                        temp["resource_name"] = instance["name"]
                        temp["resource_id"] = instance["properties"]["vmId"]
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]

                        guest_config_url = base_url + instance["id"] + "/providers/Microsoft.GuestConfiguration/guestConfigurationAssignments"
                        guest_config_response = rest_api_call(self.credentials, guest_config_url, api_version='2018-06-30-preview')
                        error = re.findall("No Assignment *", guest_config_response["Message"])
                        if error:
                            temp["status"] = "Fail" #No assignment
                        else:
                            for x in guest_config_response:
                                if x["name"] == "WindowsTimeZone" and x["properties"]["complianceStatus"] == "Compliant":
                                    temp["status"] = "Pass"

                        issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def check_windows_vm_audit_policy(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                instance_list = []
                url = vm_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(self.credentials, url, api_version='2019-07-01')
                for instance in response['value']:
                    instance_list.append(instance)
                for instance in instance_list:
                    x = re.findall("Windows", instance["properties"]["storageProfile"]["osDisk"]["osType"])
                    if x:
                        temp = dict()
                        temp["region"] = instance["location"]
                        temp["status"] = "Fail"
                        temp["resource_name"] = instance["name"]
                        temp["resource_id"] = instance["properties"]["vmId"]
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]

                        guest_config_url = base_url + instance["id"] + "/providers/Microsoft.GuestConfiguration/guestConfigurationAssignments"
                        guest_config_response = rest_api_call(self.credentials, guest_config_url, api_version='2018-06-30-preview')
                        error = re.findall("No Assignment *", guest_config_response["Message"])
                        if error:
                            temp["status"] = "Fail" #No assignment
                        else:
                            for x in guest_config_response:
                                if x["name"] == "AzureBaseline_SystemAuditPoliciesPrivilegeUse" and x["properties"]["complianceStatus"] == "Compliant":
                                    temp["status"] = "Pass"

                        issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def check_windows_service_status(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                instance_list = []
                url = vm_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(self.credentials, url, api_version='2019-07-01')
                for instance in response['value']:
                    instance_list.append(instance)
                for instance in instance_list:
                    x = re.findall("Windows", instance["properties"]["storageProfile"]["osDisk"]["osType"])
                    if x:
                        temp = dict()
                        temp["region"] = instance["location"]
                        temp["status"] = "Fail"
                        temp["resource_name"] = instance["name"]
                        temp["resource_id"] = instance["properties"]["vmId"]
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]

                        guest_config_url = base_url + instance["id"] + "/providers/Microsoft.GuestConfiguration/guestConfigurationAssignments"
                        guest_config_response = rest_api_call(self.credentials, guest_config_url, api_version='2018-06-30-preview')
                        error = re.findall("No Assignment *", guest_config_response["Message"])
                        if error:
                            temp["status"] = "Fail" #No assignment
                        else:
                            for x in guest_config_response:
                                if x["name"] == "WindowsServiceStatus" and x["properties"]["complianceStatus"] == "Compliant":
                                    temp["status"] = "Pass"

                        issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def check_windows_remote_connection(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                instance_list = []
                url = vm_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(self.credentials, url, api_version='2019-07-01')
                for instance in response['value']:
                    instance_list.append(instance)
                for instance in instance_list:
                    x = re.findall("Windows", instance["properties"]["storageProfile"]["osDisk"]["osType"])
                    if x:
                        temp = dict()
                        temp["region"] = instance["location"]
                        temp["status"] = "Fail"
                        temp["resource_name"] = instance["name"]
                        temp["resource_id"] = instance["properties"]["vmId"]
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]

                        guest_config_url = base_url + instance["id"] + "/providers/Microsoft.GuestConfiguration/guestConfigurationAssignments"
                        guest_config_response = rest_api_call(self.credentials, guest_config_url, api_version='2018-06-30-preview')
                        error = re.findall("No Assignment *", guest_config_response["Message"])
                        if error:
                            temp["status"] = "Fail" #No assignment
                        else:
                            for x in guest_config_response:
                                if x["name"] == "WindowsRemoteConnection" and x["properties"]["complianceStatus"] == "Compliant":
                                    temp["status"] = "Pass"

                        issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def check_windows_installed_powershell(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                instance_list = []
                url = vm_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(self.credentials, url, api_version='2019-07-01')
                for instance in response['value']:
                    instance_list.append(instance)
                for instance in instance_list:
                    x = re.findall("Windows", instance["properties"]["storageProfile"]["osDisk"]["osType"])
                    if x:
                        temp = dict()
                        temp["region"] = instance["location"]
                        temp["status"] = "Fail"
                        temp["resource_name"] = instance["name"]
                        temp["resource_id"] = instance["properties"]["vmId"]
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]

                        guest_config_url = base_url + instance["id"] + "/providers/Microsoft.GuestConfiguration/guestConfigurationAssignments"
                        guest_config_response = rest_api_call(self.credentials, guest_config_url, api_version='2018-06-30-preview')
                        error = re.findall("No Assignment *", guest_config_response["Message"])
                        if error:
                            temp["status"] = "Fail" #No assignment
                        else:
                            for x in guest_config_response:
                                if x["name"] == "WindowsPowerShellModules" and x["properties"]["complianceStatus"] == "Compliant":
                                    temp["status"] = "Pass"

                        issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def check_windows_vm_audit_security_policy(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                instance_list = []
                url = vm_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(self.credentials, url, api_version='2019-07-01')
                for instance in response['value']:
                    instance_list.append(instance)
                for instance in instance_list:
                    x = re.findall("Windows", instance["properties"]["storageProfile"]["osDisk"]["osType"])
                    if x:
                        temp = dict()
                        temp["region"] = instance["location"]
                        temp["status"] = "Fail"
                        temp["resource_name"] = instance["name"]
                        temp["resource_id"] = instance["properties"]["vmId"]
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]

                        guest_config_url = base_url + instance["id"] + "/providers/Microsoft.GuestConfiguration/guestConfigurationAssignments"
                        guest_config_response = rest_api_call(self.credentials, guest_config_url, api_version='2018-06-30-preview')
                        error = re.findall("No Assignment *", guest_config_response["Message"])
                        if error:
                            temp["status"] = "Fail" #No assignment
                        else:
                            for x in guest_config_response:
                                if x["name"] == "AzureBaseline_SecurityOptionsNetworkSecurity" and x["properties"]["complianceStatus"] == "Compliant":
                                    temp["status"] = "Pass"

                        issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def check_windows_vm_whitelisted_application(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                instance_list = []
                url = vm_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(self.credentials, url, api_version='2019-07-01')
                for instance in response['value']:
                    instance_list.append(instance)
                for instance in instance_list:
                    x = re.findall("Windows", instance["properties"]["storageProfile"]["osDisk"]["osType"])
                    if x:
                        temp = dict()
                        temp["region"] = instance["location"]
                        temp["status"] = "Fail"
                        temp["resource_name"] = instance["name"]
                        temp["resource_id"] = instance["properties"]["vmId"]
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]

                        guest_config_url = base_url + instance["id"] + "/providers/Microsoft.GuestConfiguration/guestConfigurationAssignments"
                        guest_config_response = rest_api_call(self.credentials, guest_config_url, api_version='2018-06-30-preview')
                        error = re.findall("No Assignment *", guest_config_response["Message"])
                        if error:
                            temp["status"] = "Fail" #No assignment
                        else:
                            for x in guest_config_response:
                                if x["name"] == "WhitelistedApplication" and x["properties"]["complianceStatus"] == "Compliant":
                                    temp["status"] = "Pass"

                        issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def check_windows_vm_audit_object_access_policy(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                instance_list = []
                url = vm_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(self.credentials, url, api_version='2019-07-01')
                for instance in response['value']:
                    instance_list.append(instance)
                for instance in instance_list:
                    x = re.findall("Windows", instance["properties"]["storageProfile"]["osDisk"]["osType"])
                    if x:
                        temp = dict()
                        temp["region"] = instance["location"]
                        temp["status"] = "Fail"
                        temp["resource_name"] = instance["name"]
                        temp["resource_id"] = instance["properties"]["vmId"]
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]

                        guest_config_url = base_url + instance["id"] + "/providers/Microsoft.GuestConfiguration/guestConfigurationAssignments"
                        guest_config_response = rest_api_call(self.credentials, guest_config_url, api_version='2018-06-30-preview')
                        error = re.findall("No Assignment *", guest_config_response["Message"])
                        if error:
                            temp["status"] = "Fail" #No assignment
                        else:
                            for x in guest_config_response:
                                if x["name"] == "AzureBaseline_SystemAuditPoliciesObjectAccess" and x["properties"]["complianceStatus"] == "Compliant":
                                    temp["status"] = "Pass"

                        issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def check_windows_vm_audit_security_system_objects(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                instance_list = []
                url = vm_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(self.credentials, url, api_version='2019-07-01')
                for instance in response['value']:
                    instance_list.append(instance)
                for instance in instance_list:
                    x = re.findall("Windows", instance["properties"]["storageProfile"]["osDisk"]["osType"])
                    if x:
                        temp = dict()
                        temp["region"] = instance["location"]
                        temp["status"] = "Fail"
                        temp["resource_name"] = instance["name"]
                        temp["resource_id"] = instance["properties"]["vmId"]
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]

                        guest_config_url = base_url + instance["id"] + "/providers/Microsoft.GuestConfiguration/guestConfigurationAssignments"
                        guest_config_response = rest_api_call(self.credentials, guest_config_url, api_version='2018-06-30-preview')
                        error = re.findall("No Assignment *", guest_config_response["Message"])
                        if error:
                            temp["status"] = "Fail" #No assignment
                        else:
                            for x in guest_config_response:
                                if x["name"] == "AzureBaseline_SecurityOptionsSystemobjects" and x["properties"]["complianceStatus"] == "Compliant":
                                    temp["status"] = "Pass"

                        issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def check_windows_vm_dsc_configuration(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                instance_list = []
                url = vm_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(self.credentials, url, api_version='2019-07-01')
                for instance in response['value']:
                    instance_list.append(instance)
                for instance in instance_list:
                    x = re.findall("Windows", instance["properties"]["storageProfile"]["osDisk"]["osType"])
                    if x:
                        temp = dict()
                        temp["region"] = instance["location"]
                        temp["status"] = "Fail"
                        temp["resource_name"] = instance["name"]
                        temp["resource_id"] = instance["properties"]["vmId"]
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]

                        guest_config_url = base_url + instance["id"] + "/providers/Microsoft.GuestConfiguration/guestConfigurationAssignments"
                        guest_config_response = rest_api_call(self.credentials, guest_config_url, api_version='2018-06-30-preview')
                        error = re.findall("No Assignment *", guest_config_response["Message"])
                        if error:
                            temp["status"] = "Fail" #No assignment
                        else:
                            for x in guest_config_response:
                                if x["name"] == "WindowsDscConfiguration" and x["properties"]["complianceStatus"] == "Compliant":
                                    temp["status"] = "Pass"

                        issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def check_windows_vm_security_setting_audit(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                instance_list = []
                url = vm_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(self.credentials, url, api_version='2019-07-01')
                for instance in response['value']:
                    instance_list.append(instance)
                for instance in instance_list:
                    x = re.findall("Windows", instance["properties"]["storageProfile"]["osDisk"]["osType"])
                    if x:
                        temp = dict()
                        temp["region"] = instance["location"]
                        temp["status"] = "Fail"
                        temp["resource_name"] = instance["name"]
                        temp["resource_id"] = instance["properties"]["vmId"]
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]

                        guest_config_url = base_url + instance["id"] + "/providers/Microsoft.GuestConfiguration/guestConfigurationAssignments"
                        guest_config_response = rest_api_call(self.credentials, guest_config_url, api_version='2018-06-30-preview')
                        error = re.findall("No Assignment *", guest_config_response["Message"])
                        if error:
                            temp["status"] = "Fail" #No assignment
                        else:
                            for x in guest_config_response:
                                if x["name"] == "AzureBaseline_SecurityOptionsSystemsettings" and x["properties"]["complianceStatus"] == "Compliant":
                                    temp["status"] = "Pass"

                        issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def check_windows_vm_components(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                instance_list = []
                url = vm_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(self.credentials, url, api_version='2019-07-01')
                for instance in response['value']:
                    instance_list.append(instance)
                for instance in instance_list:
                    x = re.findall("Windows", instance["properties"]["storageProfile"]["osDisk"]["osType"])
                    if x:
                        temp = dict()
                        temp["region"] = instance["location"]
                        temp["status"] = "Fail"
                        temp["resource_name"] = instance["name"]
                        temp["resource_id"] = instance["properties"]["vmId"]
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]

                        guest_config_url = base_url + instance["id"] + "/providers/Microsoft.GuestConfiguration/guestConfigurationAssignments"
                        guest_config_response = rest_api_call(self.credentials, guest_config_url, api_version='2018-06-30-preview')
                        error = re.findall("No Assignment *", guest_config_response["Message"])
                        if error:
                            temp["status"] = "Fail" #No assignment
                        else:
                            for x in guest_config_response:
                                if x["name"] == "AzureBaseline_WindowsComponents" and x["properties"]["complianceStatus"] == "Compliant":
                                    temp["status"] = "Pass"

                        issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def check_windows_vm_logoff_audit(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                instance_list = []
                url = vm_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(self.credentials, url, api_version='2019-07-01')
                for instance in response['value']:
                    instance_list.append(instance)
                for instance in instance_list:
                    x = re.findall("Windows", instance["properties"]["storageProfile"]["osDisk"]["osType"])
                    if x:
                        temp = dict()
                        temp["region"] = instance["location"]
                        temp["status"] = "Fail"
                        temp["resource_name"] = instance["name"]
                        temp["resource_id"] = instance["properties"]["vmId"]
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]

                        guest_config_url = base_url + instance["id"] + "/providers/Microsoft.GuestConfiguration/guestConfigurationAssignments"
                        guest_config_response = rest_api_call(self.credentials, guest_config_url, api_version='2018-06-30-preview')
                        error = re.findall("No Assignment *", guest_config_response["Message"])
                        if error:
                            temp["status"] = "Fail" #No assignment
                        else:
                            for x in guest_config_response:
                                if x["name"] == "AzureBaseline_SystemAuditPoliciesLogonLogoff" and x["properties"]["complianceStatus"] == "Compliant":
                                    temp["status"] = "Pass"

                        issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def check_windows_vm_audit_recovery_security(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                instance_list = []
                url = vm_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(self.credentials, url, api_version='2019-07-01')
                for instance in response['value']:
                    instance_list.append(instance)
                for instance in instance_list:
                    x = re.findall("Windows", instance["properties"]["storageProfile"]["osDisk"]["osType"])
                    if x:
                        temp = dict()
                        temp["region"] = instance["location"]
                        temp["status"] = "Fail"
                        temp["resource_name"] = instance["name"]
                        temp["resource_id"] = instance["properties"]["vmId"]
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]

                        guest_config_url = base_url + instance["id"] + "/providers/Microsoft.GuestConfiguration/guestConfigurationAssignments"
                        guest_config_response = rest_api_call(self.credentials, guest_config_url, api_version='2018-06-30-preview')
                        error = re.findall("No Assignment *", guest_config_response["Message"])
                        if error:
                            temp["status"] = "Fail" #No assignment
                        else:
                            for x in guest_config_response:
                                if x["name"] == "AzureBaseline_SecurityOptionsRecoveryconsole" and x["properties"]["complianceStatus"] == "Compliant":
                                    temp["status"] = "Pass"

                        issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def check_windows_vm_exclude_admin_members(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                instance_list = []
                url = vm_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(self.credentials, url, api_version='2019-07-01')
                for instance in response['value']:
                    instance_list.append(instance)
                for instance in instance_list:
                    x = re.findall("Windows", instance["properties"]["storageProfile"]["osDisk"]["osType"])
                    if x:
                        temp = dict()
                        temp["region"] = instance["location"]
                        temp["status"] = "Fail"
                        temp["resource_name"] = instance["name"]
                        temp["resource_id"] = instance["properties"]["vmId"]
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]

                        guest_config_url = base_url + instance["id"] + "/providers/Microsoft.GuestConfiguration/guestConfigurationAssignments"
                        guest_config_response = rest_api_call(self.credentials, guest_config_url, api_version='2018-06-30-preview')
                        error = re.findall("No Assignment *", guest_config_response["Message"])
                        if error:
                            temp["status"] = "Fail" #No assignment
                        else:
                            for x in guest_config_response:
                                if x["name"] == "AdministratorsGroupMembersToExclude" and x["properties"]["complianceStatus"] == "Compliant":
                                    temp["status"] = "Pass"

                        issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def check_windows_vm_password_history(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                instance_list = []
                url = vm_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(self.credentials, url, api_version='2019-07-01')
                for instance in response['value']:
                    instance_list.append(instance)
                for instance in instance_list:
                    x = re.findall("Windows", instance["properties"]["storageProfile"]["osDisk"]["osType"])
                    if x:
                        temp = dict()
                        temp["region"] = instance["location"]
                        temp["status"] = "Fail"
                        temp["resource_name"] = instance["name"]
                        temp["resource_id"] = instance["properties"]["vmId"]
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]

                        guest_config_url = base_url + instance["id"] + "/providers/Microsoft.GuestConfiguration/guestConfigurationAssignments"
                        guest_config_response = rest_api_call(self.credentials, guest_config_url, api_version='2018-06-30-preview')
                        error = re.findall("No Assignment *", guest_config_response["Message"])
                        if error:
                            temp["status"] = "Fail" #No assignment
                        else:
                            for x in guest_config_response:
                                if x["name"] == "EnforcePasswordHistory" and x["properties"]["complianceStatus"] == "Compliant":
                                    temp["status"] = "Pass"

                        issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def check_windows_vm_password_complexity(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                instance_list = []
                url = vm_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(self.credentials, url, api_version='2019-07-01')
                for instance in response['value']:
                    instance_list.append(instance)
                for instance in instance_list:
                    x = re.findall("Windows", instance["properties"]["storageProfile"]["osDisk"]["osType"])
                    if x:
                        temp = dict()
                        temp["region"] = instance["location"]
                        temp["status"] = "Fail"
                        temp["resource_name"] = instance["name"]
                        temp["resource_id"] = instance["properties"]["vmId"]
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]

                        guest_config_url = base_url + instance["id"] + "/providers/Microsoft.GuestConfiguration/guestConfigurationAssignments"
                        guest_config_response = rest_api_call(self.credentials, guest_config_url, api_version='2018-06-30-preview')
                        error = re.findall("No Assignment *", guest_config_response["Message"])
                        if error:
                            temp["status"] = "Fail" #No assignment
                        else:
                            for x in guest_config_response:
                                if x["name"] == "PasswordMustMeetComplexityRequirements" and x["properties"]["complianceStatus"] == "Compliant":
                                    temp["status"] = "Pass"

                        issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def check_windows_vm_powershell_execution_policy(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                instance_list = []
                url = vm_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(self.credentials, url, api_version='2019-07-01')
                for instance in response['value']:
                    instance_list.append(instance)
                for instance in instance_list:
                    x = re.findall("Windows", instance["properties"]["storageProfile"]["osDisk"]["osType"])
                    if x:
                        temp = dict()
                        temp["region"] = instance["location"]
                        temp["status"] = "Fail"
                        temp["resource_name"] = instance["name"]
                        temp["resource_id"] = instance["properties"]["vmId"]
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]

                        guest_config_url = base_url + instance["id"] + "/providers/Microsoft.GuestConfiguration/guestConfigurationAssignments"
                        guest_config_response = rest_api_call(self.credentials, guest_config_url, api_version='2018-06-30-preview')
                        error = re.findall("No Assignment *", guest_config_response["Message"])
                        if error:
                            temp["status"] = "Fail" #No assignment
                        else:
                            for x in guest_config_response:
                                if x["name"] == "WindowsPowerShellExecutionPolicy" and x["properties"]["complianceStatus"] == "Compliant":
                                    temp["status"] = "Pass"

                        issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def windows_vm_security_groups(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                instance_list = []
                url = vm_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(self.credentials, url, api_version='2019-07-01')
                for instance in response['value']:
                    instance_list.append(instance)
                for instance in instance_list:
                    x = re.findall("Windows", instance["properties"]["storageProfile"]["osDisk"]["osType"])
                    if x:
                        temp = dict()
                        network_interface_list = instance["properties"]["networkProfile"]["networkInterfaces"]
                        for network in network_interface_list:
                            sg_list = []
                            sg_url = base_url + network["id"] + "/effectiveNetworkSecurityGroups/"
                            headers = {'Authorization': 'Bearer ' + token['accessToken'],
                                       'Content-Type': 'application/json'}

                            params = {'api-version': '2019-11-01'}
                            sg_response = requests.post(sg_url, headers=headers, params=params)
                            if sg_response.status_code == 200:
                                temp["region"] = instance["location"]
                                temp["status"] = "Fail"
                                temp["resource_name"] = instance["name"]
                                temp["resource_id"] = instance["properties"]["vmId"]
                                temp["subscription_id"] = subscription['subscriptionId']
                                temp["subscription_name"] = subscription["displayName"]
                                sg_response = sg_response.json()
                                for sg in sg_response['value']:
                                    sg_list.append(sg)
                                for sg in sg_list:
                                    for sg_rule in sg["effectiveSecurityRules"]:
                                        if sg_rule["destinationPortRange"] == "3389-3389" and sg_rule["sourcePortRange"] == "0-65535" and sg_rule["direction"] == "Inbound":
                                            if sg_rule["access"] == "Deny":
                                                temp["status"] = "Pass"
                        if temp:
                            issues.append(temp)

        except Exception as e:
            print(str(e))
        finally:
            return issues

    def linux_vm_without_password(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                instance_list = []
                url = vm_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(self.credentials, url, api_version='2019-07-01')
                for instance in response['value']:
                    instance_list.append(instance)
                for instance in instance_list:
                    x = re.findall("Linux", instance["properties"]["storageProfile"]["osDisk"]["osType"])
                    if x:
                        temp = dict()
                        temp["region"] = instance["location"]
                        temp["status"] = "Fail"
                        temp["resource_name"] = instance["name"]
                        temp["resource_id"] = instance["properties"]["vmId"]
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]

                        guest_config_url = base_url + instance["id"] + "/providers/Microsoft.GuestConfiguration/guestConfigurationAssignments"
                        guest_config_response = rest_api_call(self.credentials, guest_config_url, api_version='2018-06-30-preview')
                        print(guest_config_response)
                        error = re.findall("No Assignment *", guest_config_response["Message"])
                        if error:
                            temp["status"] = "Fail"  # No assignment
                        else:
                            for x in guest_config_response:
                                if x["name"] == "PasswordPolicy_msid232" and x["properties"]["complianceStatus"] == "Compliant":
                                    temp["status"] = "Pass"

                        issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def linux_vm_specific_app_installation(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                instance_list = []
                url = vm_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(self.credentials, url, api_version='2019-07-01')
                for instance in response['value']:
                    instance_list.append(instance)
                for instance in instance_list:
                    x = re.findall("Linux", instance["properties"]["storageProfile"]["osDisk"]["osType"])
                    if x:
                        temp = dict()
                        temp["region"] = instance["location"]
                        temp["status"] = "Fail"
                        temp["resource_name"] = instance["name"]
                        temp["resource_id"] = instance["properties"]["vmId"]
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]

                        guest_config_url = base_url + instance["id"] + "/providers/Microsoft.GuestConfiguration/guestConfigurationAssignments"
                        guest_config_response = rest_api_call(self.credentials, guest_config_url, api_version='2018-06-30-preview')
                        print(guest_config_response)
                        error = re.findall("No Assignment *", guest_config_response["Message"])
                        if error:
                            temp["status"] = "Fail"  # No assignment
                        else:
                            for x in guest_config_response:
                                if x["name"] == "installed_application_linux" and x["properties"]["complianceStatus"] == "Compliant":
                                    temp["status"] = "Pass"

                        issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def automatic_os_patching(self):
        issues = []
        try:
            next_link_flag = 0
            next_link = ""
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                scale_sets = []
                url = vm_scale_set_url.format(subscription["subscriptionId"])
                response = rest_api_call(self.credentials, url, api_version='2019-07-01')
                if 'nextLink' in response:
                    next_link_flag = 1
                    next_link = response['nextLink'].split('skipToken=')[1]
                for i in response["value"]:
                    scale_sets.append(i)
                while next_link_flag == 1:
                    filters = "$skipToken={}".format(next_link)
                    url = vm_scale_set_url.format(subscription["subscriptionId"]) + "?$filter=" + filters + ""
                    response = rest_api_call(self.credentials, url, api_version='2019-07-01')
                    if 'nextLink' in response:
                        next_link_flag = 1
                        next_link = response['nextLink'].split('skipToken=')[1]
                    else:
                        next_link_flag = 0
                        next_link = ""
                    for i in response["value"]:
                        scale_sets.append(i)

                for i in scale_sets:
                    temp = dict()
                    temp["resource_name"] = i["name"]
                    temp["resource_id"] = ""
                    temp["region"] = i["location"]
                    temp["status"] = "Fail"
                    temp["subscription_id"] = subscription['subscriptionId']
                    temp["subscription_name"] = subscription["displayName"]
                    if "automaticOSUpgradePolicy" in i["properties"]["upgradePolicy"]:
                        if i["properties"]["upgradePolicy"]["automaticOSUpgradePolicy"]["enableAutomaticOSUpgrade"]:
                            temp["status"] = "Pass"
                    issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def vm_scale_set_diagnostic_logs(self):
        issues = []
        try:
            next_link_flag = 0
            next_link = ""
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                scale_sets = []
                url = vm_scale_set_url.format(subscription["subscriptionId"])
                response = rest_api_call(self.credentials, url, api_version='2019-07-01')
                if 'nextLink' in response:
                    next_link_flag = 1
                    next_link = response['nextLink'].split('skipToken=')[1]
                for i in response["value"]:
                    scale_sets.append(i)
                while next_link_flag == 1:
                    filters = "$skipToken={}".format(next_link)
                    url = vm_scale_set_url.format(subscription["subscriptionId"]) + "?$filter=" + filters + ""
                    response = rest_api_call(self.credentials, url, api_version='2019-07-01')
                    if 'nextLink' in response:
                        next_link_flag = 1
                        next_link = response['nextLink'].split('skipToken=')[1]
                    else:
                        next_link_flag = 0
                        next_link = ""
                    for i in response["value"]:
                        scale_sets.append(i)

                for i in scale_sets:
                    temp = dict()
                    temp["resource_name"] = i["name"]
                    temp["resource_id"] = ""
                    temp["region"] = i["location"]
                    temp["status"] = "Fail"
                    temp["subscription_id"] = subscription['subscriptionId']
                    temp["subscription_name"] = subscription["displayName"]
                    extensions = i["properties"]["virtualMachineProfile"]["extensionProfile"]["extensions"]
                    for extension in extensions:
                        if extension["properties"]["type"] == "IaaSDiagnostics" and extension["properties"]["publisher"] == "Microsoft.Azure.Diagnostics":
                            temp["status"] = "Pass"

                        if extension["properties"]["type"] == "LinuxDiagnostic":
                            if extension["properties"]["publisher"] == "Microsoft.OSTCExtensions" or extension["properties"]["publisher"] == "Microsoft.Azure.Diagnostics":
                                temp["status"] = "Pass"

                    issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def windows_antimalware_software(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                instance_list = []
                url = vm_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(self.credentials, url, api_version='2019-07-01')
                for instance in response['value']:
                    instance_list.append(instance)
                for i in instance_list:
                    x = re.findall("Windows", i["properties"]["storageProfile"]["osDisk"]["osType"])
                    if x:
                        temp = dict()
                        temp["region"] = i["location"]
                        temp["status"] = "Fail"
                        temp["resource_name"] = i["name"]
                        temp["resource_id"] = i["properties"]["vmId"]
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]
                        extension_list = []
                        extensions_url = base_url + i["id"] + "/extensions"
                        ext_response = rest_api_call(self.credentials, extensions_url, api_version='2019-07-01')
                        for ext in ext_response['value']:
                            extension_list.append(ext)
                        for ext in extension_list:
                            if ext["type"] == "IaaSAntimalware" and ext["publisher"] == "Microsoft.Azure.Security":
                                temp["status"] = "Pass"
                        issues.append(temp)

        except Exception as e:
            print(str(e))
        finally:
            return issues

    def windows_antimalware_autoupdate(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                instance_list = []
                url = vm_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(self.credentials, url, api_version='2019-07-01')
                for instance in response['value']:
                    instance_list.append(instance)
                for i in instance_list:
                    x = re.findall("Windows", i["properties"]["storageProfile"]["osDisk"]["osType"])
                    if x:
                        temp = dict()
                        temp["region"] = i["location"]
                        temp["status"] = "Fail"
                        temp["resource_name"] = i["name"]
                        temp["resource_id"] = i["properties"]["vmId"]
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]
                        extension_list = []
                        extensions_url = base_url + i["id"] + "/extensions"
                        ext_response = rest_api_call(self.credentials, extensions_url, api_version='2019-07-01')
                        for ext in ext_response['value']:
                            extension_list.append(ext)
                        for ext in extension_list:
                            if ext["type"] == "IaaSAntimalware" and ext["publisher"] == "Microsoft.Azure.Security":
                                if ext["properties"]["autoUpgradeMinorVersion"]:
                                    temp["status"] = "Pass"
                        issues.append(temp)

        except Exception as e:
            print(str(e))
        finally:
            return issues

    def classic_vms(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                instance_list = []
                url = vm_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(self.credentials, url, api_version='2019-07-01')
                for instance in response['value']:
                    instance_list.append(instance)
                for i in instance_list:
                    temp = dict()
                    temp["region"] = i["location"]
                    temp["status"] = "Pass"
                    temp["resource_name"] = i["name"]
                    temp["resource_id"] = i["properties"]["vmId"]
                    temp["subscription_id"] = subscription['subscriptionId']
                    temp["subscription_name"] = subscription["displayName"]

                    if i["type"] == "Microsoft.ClassicCompute/virtualMachines":
                        temp["status"] = "Fail"

                    issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

#Show audit results from Windows VMs that do not have a minimum password age of 1 day

    def check_windows_vm_min_password_age(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                instance_list = []
                url = vm_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(self.credentials, url, api_version='2019-07-01')
                for instance in response['value']:
                    instance_list.append(instance)
                for instance in instance_list:
                    x = re.findall("Windows", instance["properties"]["storageProfile"]["osDisk"]["osType"])
                    if x:
                        temp = dict()
                        temp["region"] = instance["location"]
                        temp["status"] = "Fail"
                        temp["resource_name"] = instance["name"]
                        temp["resource_id"] = instance["properties"]["vmId"]
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]

                        guest_config_url = base_url + instance["id"] + "/providers/Microsoft.GuestConfiguration/guestConfigurationAssignments"
                        guest_config_response = rest_api_call(self.credentials, guest_config_url, api_version='2018-06-30-preview')
                        if "Message" in guest_config_response.keys():
                           temp["status"] = "Fail"  # No assignment
                        else:
                            for x in guest_config_response['value']:
                                if x["name"] == "MinimumPasswordAge" and x["properties"]["complianceStatus"] == "Compliant":
                                    temp["status"] = "Pass"

                        #print(temp)
                        issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues


#Show audit results from Windows VMs that do not have a maximum password age of 70 day

    def check_windows_vm_max_password_age(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                instance_list = []
                url = vm_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(self.credentials, url, api_version='2019-07-01')
                for instance in response['value']:
                    instance_list.append(instance)
                for instance in instance_list:
                    x = re.findall("Windows", instance["properties"]["storageProfile"]["osDisk"]["osType"])
                    if x:
                        temp = dict()
                        temp["region"] = instance["location"]
                        temp["status"] = "Fail"
                        temp["resource_name"] = instance["name"]
                        temp["resource_id"] = instance["properties"]["vmId"]
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]

                        guest_config_url = base_url + instance["id"] + "/providers/Microsoft.GuestConfiguration/guestConfigurationAssignments"
                        guest_config_response = rest_api_call(self.credentials, guest_config_url, api_version='2018-06-30-preview')

                        if "Message" in guest_config_response.keys():
                           temp["status"] = "Fail"  # No assignment
                        else:
                            for x in guest_config_response['value']:
                                if x["name"] == "MaximumPasswordAge" and x["properties"]["complianceStatus"] == "Compliant":
                                    temp["status"] = "Pass"

                        #print(temp)
                        issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

#Show audit results from Windows VMs that do not restrict the minimum password length to 14 characters

    def check_windows_vm_min_password_len(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                instance_list = []
                url = vm_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(self.credentials, url, api_version='2019-07-01')
                for instance in response['value']:
                    instance_list.append(instance)
                for instance in instance_list:
                    x = re.findall("Windows", instance["properties"]["storageProfile"]["osDisk"]["osType"])
                    if x:
                        temp = dict()
                        temp["region"] = instance["location"]
                        temp["status"] = "Fail"
                        temp["resource_name"] = instance["name"]
                        temp["resource_id"] = instance["properties"]["vmId"]
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]

                        guest_config_url = base_url + instance["id"] + "/providers/Microsoft.GuestConfiguration/guestConfigurationAssignments"
                        guest_config_response = rest_api_call(self.credentials, guest_config_url, api_version='2018-06-30-preview')

                        if "Message" in guest_config_response.keys():
                           temp["status"] = "Fail"  # No assignment
                        else:
                            for x in guest_config_response['value']:
                                if x["name"] == "MinimumPasswordLength" and x["properties"]["complianceStatus"] == "Compliant":
                                    temp["status"] = "Pass"

                        #print(temp)
                        issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

#Show audit results from Windows VMs that do not store passwords using reversible encryption
    def check_windows_vm_store_password_rev_encryption(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                instance_list = []
                url = vm_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(self.credentials, url, api_version='2019-07-01')
                for instance in response['value']:
                    instance_list.append(instance)
                for instance in instance_list:
                    x = re.findall("Windows", instance["properties"]["storageProfile"]["osDisk"]["osType"])
                    if x:
                        temp = dict()
                        temp["region"] = instance["location"]
                        temp["status"] = "Fail"
                        temp["resource_name"] = instance["name"]
                        temp["resource_id"] = instance["properties"]["vmId"]
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]

                        guest_config_url = base_url + instance["id"] + "/providers/Microsoft.GuestConfiguration/guestConfigurationAssignments"
                        guest_config_response = rest_api_call(self.credentials, guest_config_url, api_version='2018-06-30-preview')

                        if "Message" in guest_config_response.keys():
                           temp["status"] = "Fail"  # No assignment
                        else:
                            for x in guest_config_response['value']:
                                if x["name"] == "StorePasswordsUsingReversibleEncryption" and x["properties"]["complianceStatus"] == "Compliant":
                                    temp["status"] = "Pass"

                        #print(temp)
                        issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

#Show audit results from Linux VMs that do not have the passwd file permissions set to 0644

    def check_vm_linux_password_permission_0644(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                instance_list = []
                url = vm_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(self.credentials, url, api_version='2019-07-01')
                for instance in response['value']:
                    instance_list.append(instance)
                for instance in instance_list:
                    x = re.findall("Linux", instance["properties"]["storageProfile"]["osDisk"]["osType"])
                    if x:
                        temp = dict()
                        temp["region"] = instance["location"]
                        temp["status"] = "Fail"
                        temp["resource_name"] = instance["name"]
                        temp["resource_id"] = instance["properties"]["vmId"]
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]

                        guest_config_url = base_url + instance["id"] + "/providers/Microsoft.GuestConfiguration/guestConfigurationAssignments"
                        guest_config_response = rest_api_call(self.credentials, guest_config_url, api_version='2018-06-30-preview')

                        if "Message" in guest_config_response.keys():
                           temp["status"] = "Fail"  # No assignment
                        else:
                            for x in guest_config_response['value']:
                                if x["name"] == "PasswordPolicy_msid121" and x["properties"]["complianceStatus"] == "Compliant":
                                    temp["status"] = "Pass"

                        #print(temp)
                        issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

#Show audit results from Linux VMs that allow remote connections from accounts without passwords

    def check_vm_linux_remote_connection_without_password(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                instance_list = []
                url = vm_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(self.credentials, url, api_version='2019-07-01')
                for instance in response['value']:
                    instance_list.append(instance)
                for instance in instance_list:
                    x = re.findall("Linux", instance["properties"]["storageProfile"]["osDisk"]["osType"])
                    if x:
                        temp = dict()
                        temp["region"] = instance["location"]
                        temp["status"] = "Fail"
                        temp["resource_name"] = instance["name"]
                        temp["resource_id"] = instance["properties"]["vmId"]
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]

                        guest_config_url = base_url + instance["id"] + "/providers/Microsoft.GuestConfiguration/guestConfigurationAssignments"
                        guest_config_response = rest_api_call(self.credentials, guest_config_url, api_version='2018-06-30-preview')

                        if "Message" in guest_config_response.keys():
                           temp["status"] = "Fail"  # No assignment
                        else:
                            for x in guest_config_response['value']:
                                if x["name"] == "PasswordPolicy_msid110" and x["properties"]["complianceStatus"] == "Compliant":
                                    temp["status"] = "Pass"

                        #print(temp)
                        issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

#Audit Log Analytics Agent Deployment in Virtual Machine Scale Sets - VM Image (OS) unlisted

    def check_vm_scale_set_audit_logs_vmImage_unlisted(self):
        issues = []
        try:
            next_link_flag = 0
            next_link = ""
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                scale_sets = []
                url = vm_scale_set_url.format(subscription["subscriptionId"])
                response = rest_api_call(self.credentials, url, api_version='2019-07-01')
                if 'nextLink' in response:
                    next_link_flag = 1
                    next_link = response['nextLink'].split('skipToken=')[1]
                for i in response["value"]:
                    scale_sets.append(i)
                while next_link_flag == 1:
                    filters = "$skipToken={}".format(next_link)
                    url = vm_scale_set_url.format(subscription["subscriptionId"]) + "?$filter=" + filters + ""
                    response = rest_api_call(self.credentials, url, api_version='2019-07-01')
                    if 'nextLink' in response:
                        next_link_flag = 1
                        next_link = response['nextLink'].split('skipToken=')[1]
                    else:
                        next_link_flag = 0
                        next_link = ""
                    for i in response["value"]:
                        scale_sets.append(i)

                for i in scale_sets:
                    temp = dict()
                    temp["resource_name"] = i["name"]
                    temp["resource_id"] = ""
                    temp["region"] = i["location"]
                    temp["status"] = "Fail"
                    temp["subscription_id"] = subscription['subscriptionId']
                    temp["subscription_name"] = subscription["displayName"]
                    extensions = i["properties"]["virtualMachineProfile"]["extensionProfile"]["extensions"]
                    for extension in extensions:
                        if extension["properties"]["publisher"] == "Microsoft.EnterpriseCloud.Monitoring":
                            temp["status"] = "Pass"

                    #print(temp)
                    issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

#Show audit results from Windows VMs in which the Administrators group does not contain all of the specified members

    def check_windows_vm_admin_not_contain_specified_member(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                instance_list = []
                url = vm_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(self.credentials, url, api_version='2019-07-01')
                for instance in response['value']:
                    instance_list.append(instance)
                for instance in instance_list:
                    x = re.findall("Windows", instance["properties"]["storageProfile"]["osDisk"]["osType"])
                    if x:
                        temp = dict()
                        temp["region"] = instance["location"]
                        temp["status"] = "Fail"
                        temp["resource_name"] = instance["name"]
                        temp["resource_id"] = instance["properties"]["vmId"]
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]

                        guest_config_url = base_url + instance["id"] + "/providers/Microsoft.GuestConfiguration/guestConfigurationAssignments"
                        guest_config_response = rest_api_call(self.credentials, guest_config_url, api_version='2018-06-30-preview')

                        if "Message" in guest_config_response.keys():
                           temp["status"] = "Fail"  # No assignment
                        else:
                            for x in guest_config_response['value']:
                                if x["name"] == "AdministratorsGroupMembersToInclude" and x["properties"]["complianceStatus"] == "Compliant":
                                    temp["status"] = "Pass"

                        #print(temp)
                        issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

#Show audit results from Windows web servers that are not using secure communication protocols

    def check_windows_web_server_not_secure(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                instance_list = []
                url = vm_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(self.credentials, url, api_version='2019-07-01')
                for instance in response['value']:
                    instance_list.append(instance)
                for instance in instance_list:
                    x = re.findall("Windows", instance["properties"]["storageProfile"]["osDisk"]["osType"])
                    if x:
                        temp = dict()
                        temp["region"] = instance["location"]
                        temp["status"] = "Fail"
                        temp["resource_name"] = instance["name"]
                        temp["resource_id"] = instance["properties"]["vmId"]
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]

                        guest_config_url = base_url + instance[
                            "id"] + "/providers/Microsoft.GuestConfiguration/guestConfigurationAssignments"
                        guest_config_response = rest_api_call(self.credentials, guest_config_url,api_version='2018-06-30-preview')

                        if "Message" in guest_config_response.keys():
                            temp["status"] = "Fail"  # No assignment
                        else:
                            for x in guest_config_response['value']:
                                if x["name"] == "AuditSecureProtocol" and x["properties"]["complianceStatus"] == "Compliant":
                                    temp["status"] = "Pass"

                        #print(temp)
                        issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

#Show audit results from Windows VMs configurations in 'Security Options - Network Access'

    def check_windows_vm_config_security_network_access(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                instance_list = []
                url = vm_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(self.credentials, url, api_version='2019-07-01')
                for instance in response['value']:
                    instance_list.append(instance)
                for instance in instance_list:
                    x = re.findall("Windows", instance["properties"]["storageProfile"]["osDisk"]["osType"])
                    if x:
                        temp = dict()
                        temp["region"] = instance["location"]
                        temp["status"] = "Fail"
                        temp["resource_name"] = instance["name"]
                        temp["resource_id"] = instance["properties"]["vmId"]
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]

                        guest_config_url = base_url + instance["id"] + "/providers/Microsoft.GuestConfiguration/guestConfigurationAssignments"
                        guest_config_response = rest_api_call(self.credentials, guest_config_url, api_version='2018-06-30-preview')

                        if "Message" in guest_config_response.keys():
                           temp["status"] = "Fail"  # No assignment
                        else:
                            for x in guest_config_response['value']:
                                if x["name"] == "AzureBaseline_SecurityOptionsNetworkAccess" and x["properties"]["complianceStatus"] == "Compliant":
                                    temp["status"] = "Pass"

                        print(temp)
                        issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

#Show audit results from Windows VMs configurations in 'Security Options - System settings'

    def check_windows_vm_config_security_system_settings(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                instance_list = []
                url = vm_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(self.credentials, url, api_version='2019-07-01')
                for instance in response['value']:
                    instance_list.append(instance)
                for instance in instance_list:
                    x = re.findall("Windows", instance["properties"]["storageProfile"]["osDisk"]["osType"])
                    if x:
                        temp = dict()
                        temp["region"] = instance["location"]
                        temp["status"] = "Fail"
                        temp["resource_name"] = instance["name"]
                        temp["resource_id"] = instance["properties"]["vmId"]
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]

                        guest_config_url = base_url + instance["id"] + "/providers/Microsoft.GuestConfiguration/guestConfigurationAssignments"
                        guest_config_response = rest_api_call(self.credentials, guest_config_url, api_version='2018-06-30-preview')

                        if "Message" in guest_config_response.keys():
                           temp["status"] = "Fail"  # No assignment
                        else:
                            for x in guest_config_response['value']:
                                if x["name"] == "AzureBaseline_SecurityOptionsSystemsettings" and x["properties"]["complianceStatus"] == "Compliant":
                                    temp["status"] = "Pass"

                        print(temp)
                        issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

#Show audit results from Windows VMs configurations in 'Windows Firewall Properties'

    def check_windows_vm_config_windows_firewall_properties(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                instance_list = []
                url = vm_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(self.credentials, url, api_version='2019-07-01')
                for instance in response['value']:
                    instance_list.append(instance)
                for instance in instance_list:
                    x = re.findall("Windows", instance["properties"]["storageProfile"]["osDisk"]["osType"])
                    if x:
                        temp = dict()
                        temp["region"] = instance["location"]
                        temp["status"] = "Fail"
                        temp["resource_name"] = instance["name"]
                        temp["resource_id"] = instance["properties"]["vmId"]
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]

                        guest_config_url = base_url + instance["id"] + "/providers/Microsoft.GuestConfiguration/guestConfigurationAssignments"
                        guest_config_response = rest_api_call(self.credentials, guest_config_url, api_version='2018-06-30-preview')

                        if "Message" in guest_config_response.keys():
                           temp["status"] = "Fail"  # No assignment
                        else:
                            for x in guest_config_response['value']:
                                if x["name"] == "AzureBaseline_WindowsFirewallProperties" and x["properties"]["complianceStatus"] == "Compliant":
                                    temp["status"] = "Pass"

                        print(temp)
                        issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

#Show audit results from Windows VMs that contain certificates expiring within the specified number of days

    def check_windows_vm_contain_certificates_expiration(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                instance_list = []
                url = vm_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(self.credentials, url, api_version='2019-07-01')
                for instance in response['value']:
                    instance_list.append(instance)
                for instance in instance_list:
                    x = re.findall("Windows", instance["properties"]["storageProfile"]["osDisk"]["osType"])
                    if x:
                        temp = dict()
                        temp["region"] = instance["location"]
                        temp["status"] = "Fail"
                        temp["resource_name"] = instance["name"]
                        temp["resource_id"] = instance["properties"]["vmId"]
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]

                        guest_config_url = base_url + instance["id"] + "/providers/Microsoft.GuestConfiguration/guestConfigurationAssignments"
                        guest_config_response = rest_api_call(self.credentials, guest_config_url, api_version='2018-06-30-preview')

                        if "Message" in guest_config_response.keys():
                           temp["status"] = "Fail"  # No assignment
                        else:
                            for x in guest_config_response['value']:
                                if x["name"] == "CertificateExpiration" and x["properties"]["complianceStatus"] == "Compliant":
                                    temp["status"] = "Pass"

                        print(temp)
                        issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

#Show audit results from Windows VMs configurations in 'Security Options - Accounts'

    def check_windows_vm_config_security_accounts(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                instance_list = []
                url = vm_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(self.credentials, url, api_version='2019-07-01')
                for instance in response['value']:
                    instance_list.append(instance)
                for instance in instance_list:
                    x = re.findall("Windows", instance["properties"]["storageProfile"]["osDisk"]["osType"])
                    if x:
                        temp = dict()
                        temp["region"] = instance["location"]
                        temp["status"] = "Fail"
                        temp["resource_name"] = instance["name"]
                        temp["resource_id"] = instance["properties"]["vmId"]
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]

                        guest_config_url = base_url + instance["id"] + "/providers/Microsoft.GuestConfiguration/guestConfigurationAssignments"
                        guest_config_response = rest_api_call(self.credentials, guest_config_url, api_version='2018-06-30-preview')

                        if "Message" in guest_config_response.keys():
                           temp["status"] = "Fail"  # No assignment
                        else:
                            for x in guest_config_response['value']:
                                if x["name"] == "AzureBaseline_SecurityOptionsAccounts" and x["properties"]["complianceStatus"] == "Compliant":
                                    temp["status"] = "Pass"

                        print(temp)
                        issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

#Show audit results from Windows VMs configurations in 'Security Options - Recovery console'

    def check_windows_vm_config_security_recovery_console(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                instance_list = []
                url = vm_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(self.credentials, url, api_version='2019-07-01')
                for instance in response['value']:
                    instance_list.append(instance)
                for instance in instance_list:
                    x = re.findall("Windows", instance["properties"]["storageProfile"]["osDisk"]["osType"])
                    if x:
                        temp = dict()
                        temp["region"] = instance["location"]
                        temp["status"] = "Fail"
                        temp["resource_name"] = instance["name"]
                        temp["resource_id"] = instance["properties"]["vmId"]
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]

                        guest_config_url = base_url + instance["id"] + "/providers/Microsoft.GuestConfiguration/guestConfigurationAssignments"
                        guest_config_response = rest_api_call(self.credentials, guest_config_url, api_version='2018-06-30-preview')

                        if "Message" in guest_config_response.keys():
                           temp["status"] = "Fail"  # No assignment
                        else:
                            for x in guest_config_response['value']:
                                if x["name"] == "AzureBaseline_SecurityOptionsRecoveryconsole" and x["properties"]["complianceStatus"] == "Compliant":
                                    temp["status"] = "Pass"

                        print(temp)
                        issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

#Show audit results from Windows VMs configurations in 'User Rights Assignment'

    def check_windows_vm_config_user_rights_assignment(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                instance_list = []
                url = vm_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(self.credentials, url, api_version='2019-07-01')
                for instance in response['value']:
                    instance_list.append(instance)
                for instance in instance_list:
                    x = re.findall("Windows", instance["properties"]["storageProfile"]["osDisk"]["osType"])
                    if x:
                        temp = dict()
                        temp["region"] = instance["location"]
                        temp["status"] = "Fail"
                        temp["resource_name"] = instance["name"]
                        temp["resource_id"] = instance["properties"]["vmId"]
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]

                        guest_config_url = base_url + instance["id"] + "/providers/Microsoft.GuestConfiguration/guestConfigurationAssignments"
                        guest_config_response = rest_api_call(self.credentials, guest_config_url, api_version='2018-06-30-preview')

                        if "Message" in guest_config_response.keys():
                           temp["status"] = "Fail"  # No assignment
                        else:
                            for x in guest_config_response['value']:
                                if x["name"] == "AzureBaseline_UserRightsAssignment" and x["properties"]["complianceStatus"] == "Compliant":
                                    temp["status"] = "Pass"

                        print(temp)
                        issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

#Show audit results from Windows VMs that do not contain the specified certificates in Trusted Root

    def check_windows_vm_certificate_in_trusted_root(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                instance_list = []
                url = vm_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(self.credentials, url, api_version='2019-07-01')
                for instance in response['value']:
                    instance_list.append(instance)
                for instance in instance_list:
                    x = re.findall("Windows", instance["properties"]["storageProfile"]["osDisk"]["osType"])
                    if x:
                        temp = dict()
                        temp["region"] = instance["location"]
                        temp["status"] = "Fail"
                        temp["resource_name"] = instance["name"]
                        temp["resource_id"] = instance["properties"]["vmId"]
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]

                        guest_config_url = base_url + instance["id"] + "/providers/Microsoft.GuestConfiguration/guestConfigurationAssignments"
                        guest_config_response = rest_api_call(self.credentials, guest_config_url, api_version='2018-06-30-preview')

                        if "Message" in guest_config_response.keys():
                           temp["status"] = "Fail"  # No assignment
                        else:
                            for x in guest_config_response['value']:
                                if x["name"] == "WindowsCertificateInTrustedRoot" and x["properties"]["complianceStatus"] == "Compliant":
                                    temp["status"] = "Pass"

                        print(temp)
                        issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

#Show audit results from Windows VMs configurations in 'Security Options - Microsoft Network Client'

    def check_windows_vm_config_security_network_client(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                instance_list = []
                url = vm_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(self.credentials, url, api_version='2019-07-01')
                for instance in response['value']:
                    instance_list.append(instance)
                for instance in instance_list:
                    x = re.findall("Windows", instance["properties"]["storageProfile"]["osDisk"]["osType"])
                    if x:
                        temp = dict()
                        temp["region"] = instance["location"]
                        temp["status"] = "Fail"
                        temp["resource_name"] = instance["name"]
                        temp["resource_id"] = instance["properties"]["vmId"]
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]

                        guest_config_url = base_url + instance["id"] + "/providers/Microsoft.GuestConfiguration/guestConfigurationAssignments"
                        guest_config_response = rest_api_call(self.credentials, guest_config_url, api_version='2018-06-30-preview')

                        if "Message" in guest_config_response.keys():
                           temp["status"] = "Fail"  # No assignment
                        else:
                            for x in guest_config_response['value']:
                                if x["name"] == "AzureBaseline_SecurityOptionsMicrosoftNetworkClient" and x["properties"]["complianceStatus"] == "Compliant":
                                    temp["status"] = "Pass"

                        print(temp)
                        issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

#Show audit results from Linux VMs that do not have the specified applications installed

    def check_linux_vm_installed_application(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                instance_list = []
                url = vm_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(self.credentials, url, api_version='2019-07-01')
                for instance in response['value']:
                    instance_list.append(instance)
                for instance in instance_list:
                    x = re.findall("Linux", instance["properties"]["storageProfile"]["osDisk"]["osType"])
                    if x:
                        temp = dict()
                        temp["region"] = instance["location"]
                        temp["status"] = "Fail"
                        temp["resource_name"] = instance["name"]
                        temp["resource_id"] = instance["properties"]["vmId"]
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]

                        guest_config_url = base_url + instance["id"] + "/providers/Microsoft.GuestConfiguration/guestConfigurationAssignments"
                        guest_config_response = rest_api_call(self.credentials, guest_config_url, api_version='2018-06-30-preview')

                        if "Message" in guest_config_response.keys():
                           temp["status"] = "Fail"  # No assignment
                        else:
                            for x in guest_config_response['value']:
                                if x["name"] == "installed_application_linux" and x["properties"]["complianceStatus"] == "Compliant":
                                    temp["status"] = "Pass"

                        print(temp)
                        issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues



