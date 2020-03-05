from checks.common_services import CommonServices
from helper_function import get_auth_token, rest_api_call
from contants import vm_list_url, base_url, disk_list_url


class VmService:
    def __init__(self, credentials):
        self.credentials = credentials

    def unused_virtual_machines(self):
        issues = []
        try:
            token = get_auth_token(self.credentials)
            cs = CommonServices()
            subscription_list = cs.get_subscriptions_list(token)
            for subscription in subscription_list:
                instance_list = []
                url = vm_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(token, url, api_version='2019-07-01')
                for instance in response['value']:
                    instance_list.append(instance)
                for instance in instance_list:
                    temp = dict()
                    temp['region'] = instance["location"]
                    instance_view_url = base_url + instance["id"] + "/instanceView"
                    response = rest_api_call(token, instance_view_url, api_version='2019-07-01')
                    for status in response["statuses"]:
                        if status['code'] == "PowerState/deallocated":
                            temp["status"] = "Fail"
                            temp["resource_name"] = instance["name"]
                            temp["resource_id"] = instance["properties"]["vmId"]
                            temp["problem"] = "Virtual Machine {} in subscription {} is in stopped state.".format(
                                instance["name"], subscription['subscriptionId']
                            )
                        else:
                            temp["status"] = "Pass"
                            temp["resource_name"] = instance["name"]
                            temp["resource_id"] = instance["id"]
                            temp["problem"] = "Virtual Machine {} in subscription {} is in running state.".format(
                                instance["name"], subscription['subscriptionId']
                            )
                        issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def unused_volumes(self):
        issues = []
        try:
            token = get_auth_token(self.credentials)
            cs = CommonServices()
            subscription_list = cs.get_subscriptions_list(token)
            for subscription in subscription_list:
                disk_list = []
                url = disk_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(token, url, api_version='2019-07-01')
                for disk in response['value']:
                    disk_list.append(disk)

                for disk in disk_list:
                    temp = dict()
                    temp['region'] = disk["location"]
                    if disk["properties"]["diskState"] == "Unattached":
                        temp["status"] = "Fail"
                        temp["resource_name"] = disk["name"]
                        temp["resource_id"] = disk["id"]
                        temp["problem"] = "Disk {} in subscription {} is unattached.".format(
                            disk["name"], subscription['subscriptionId']
                        )
                    else:
                        temp["status"] = "Pass"
                        temp["resource_name"] = disk["name"]
                        temp["resource_id"] = disk["id"]
                        temp["problem"] = "Disk {} in subscription {} is attached.".format(
                            disk["name"], subscription['subscriptionId']
                        )
                    issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def vm_with_no_managed_disks(self):
        issues = []
        try:
            token = get_auth_token(self.credentials)
            cs = CommonServices()
            subscription_list = cs.get_subscriptions_list(token)
            for subscription in subscription_list:
                instance_list = []
                url = vm_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(token, url, api_version='2019-07-01')
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
                            temp["problem"] = "Virtual Machine {} under subscription {} use managed disk.".format(
                                instance["name"], subscription['subscriptionId']
                            )
                    else:
                        temp['region'] = instance["location"]
                        temp["status"] = "Fail"
                        temp["resource_name"] = instance["name"]
                        temp["resource_id"] = instance["properties"]["vmId"]
                        temp["problem"] = "Virtual Machine {} under subscription {} do not use managed disk.".format(
                            instance["name"], subscription['subscriptionId']
                        )
                    if temp:
                        issues.append(temp)
        except Exception as e:
            print(str(e))
        return issues

    def vm_security_groups(self):
        issues = []
        try:
            token = get_auth_token(self.credentials)
            cs = CommonServices()
            subscription_list = cs.get_subscriptions_list(token)
            for subscription in subscription_list:
                instance_list = []
                url = vm_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(token, url, api_version='2019-07-01')
                for instance in response['value']:
                    instance_list.append(instance)
                for instance in instance_list:
                    for network_interface in instance['properties']['networkProfile']['networkInterfaces']:
                        # print(network_interface['id'])
                        network_url = base_url + network_interface['id']
                        response = rest_api_call(token, network_url, api_version='2019-11-01')
                        for ip in response['properties']['ipConfigurations']:
                            subnet_id = ip['properties']['subnet']['id']
                            subnet_url = base_url + subnet_id
                            subnet_response = rest_api_call(token, subnet_url, api_version='2019-11-01')
                            print(subnet_response)

        except Exception as e:
            print(str(e))