from contants import (base_url, service_bus_list_url, network_sg_list_url, app_list_url, network_list_url,
                      storage_accounts_list_url, network_interface_list_url, sql_server_list_url,
                      resource_group_list_url, container_registry_list_url)
from helper_function import get_auth_token, rest_api_call
import re


class NetworkService:
    def __init__(self, credentials, subscription_list):
        self.credentials = credentials
        self.subscription_list = subscription_list

    def service_endpoint_servicebus(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                url = service_bus_list_url.format(subscription['subscriptionId'])
                token = get_auth_token(self.credentials)
                response = rest_api_call(token, url, api_version="2017-04-01")
                for service_bus in response["value"]:
                    temp = dict()
                    temp["region"] = service_bus["location"]
                    temp["status"] = "Fail"
                    temp["resource_id"] = ""
                    temp["resource_name"] = service_bus["name"]
                    temp["subscription_id"] = subscription['subscriptionId']
                    temp["subscription_name"] = subscription["displayName"]
                    network_url = base_url + service_bus["id"] + "/networkRuleSets"
                    token = get_auth_token(self.credentials)
                    network_response = rest_api_call(token, network_url, api_version="2017-04-01")
                    for network in network_response["value"]:
                        print(network)
                        if network["properties"]["virtualNetworkRules"]:
                            for vnetwork in network["properties"]["virtualNetworkRules"]:
                                if len(vnetwork["subnet"]["id"]) > 1:
                                    temp["status"] = "Pass"
                    issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def deny_ssh_over_interent(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                url = network_sg_list_url.format(subscription['subscriptionId'])
                token = get_auth_token(self.credentials)
                response = rest_api_call(token, url, api_version="2019-11-01")
                for network in response["value"]:
                    temp = dict()
                    temp["status"] = "Pass"
                    temp["region"] = network["location"]
                    temp["resource_id"] = ""
                    temp["resource_name"] = network["name"]
                    temp["subscription_id"] = subscription['subscriptionId']
                    temp["subscription_name"] = subscription["displayName"]
                    sg_url = base_url + network["id"]
                    token = get_auth_token(self.credentials)
                    resp = rest_api_call(token, sg_url, api_version="2019-11-01")
                    for rule in resp["properties"]["securityRules"]:
                        if rule["properties"]["destinationPortRange"] == "22" \
                           and rule["properties"]["access"] == "Allow" \
                                and rule["properties"]["direction"] == "Inbound":
                            if rule["properties"]["sourcePortRange"] == "*" or \
                                    rule["properties"]["sourcePortRange"] == "Internet":
                                temp["status"] = "Fail"
                    issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def app_service_service_endpoint(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                url = app_list_url.format(subscription["subscriptionId"])
                token = get_auth_token(self.credentials)
                response = rest_api_call(token, url, '2019-08-01')
                for app in response["value"]:
                    x = re.findall("app*", app["kind"])
                    if x:
                        temp = dict()
                        temp["region"] = app["location"]
                        temp["status"] = "Fail"
                        temp['resource_name'] = app['name']
                        temp['resource_id'] = ""
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]
                        vnetworks_url = base_url + app["id"] + "/virtualNetworkConnections"
                        token = get_auth_token(self.credentials)
                        vnet_response = rest_api_call(token, vnetworks_url, '2019-08-01')
                        for vnet in vnet_response:
                            if "vnetResourceId" in vnet["properties"]:
                                temp["status"] = "Pass"
                        issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def disable_gateway_nsg(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                url = network_list_url.format(subscription["subscriptionId"])
                token = get_auth_token(self.credentials)
                response = rest_api_call(token, url, '2019-11-01')
                for vnet in response["value"]:
                    subnet_url = base_url+vnet["id"]+"/subnets"
                    token = get_auth_token(self.credentials)
                    subnet_response = rest_api_call(token, subnet_url, '2019-11-01')
                    for subnet in subnet_response["value"]:
                        temp = dict()
                        temp["region"] = ""
                        temp["status"] = "Pass"
                        temp['resource_name'] = subnet['name']
                        temp['resource_id'] = ""
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]
                        if subnet["type"] == "Microsoft.Network/virtualNetworks/subnets" and subnet["name"] == "GatewaySubnet":
                            if subnet["properties"]["networkSecurityGroup"]["id"] is not None:
                                temp["status"] = "Fail"
                        issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def storage_account_service_network(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                url = storage_accounts_list_url.format(subscription['subscriptionId'])
                token = get_auth_token(self.credentials)
                response = rest_api_call(token, url)
                storage_accounts = response['value']
                for account in storage_accounts:
                    temp = dict()
                    temp["region"] = account["location"]
                    temp["status"] = "Fail"
                    temp["resource_name"] = account["name"]
                    temp["resource_id"] = ""
                    temp["subscription_id"] = subscription['subscriptionId']
                    temp["subscription_name"] = subscription["displayName"]
                    if account["properties"]["networkAcls"]["defaultAction"] == "Allow":
                        temp["status"] = "Pass"
                    for i in account["properties"]["networkAcls"]["virtualNetworkRules"]:
                        if "id" in i.keys():
                            temp["status"] = "Pass"
                    issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def network_interface_deny_public_ips(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                url = network_interface_list_url.format(subscription['subscriptionId'])
                token = get_auth_token(self.credentials)
                response = rest_api_call(token, url, api_version="2019-11-01")
                for ni in response["value"]:
                    temp = dict()
                    temp["region"] = ni["location"]
                    temp["status"] = "Pass"
                    temp["resource_name"] = ni["name"]
                    temp["resource_id"] = ""
                    temp["subscription_id"] = subscription['subscriptionId']
                    temp["subscription_name"] = subscription["displayName"]
                    for ipconfig in ni['properties']['ipConfigurations']:
                        if "publicIPAddress" in ipconfig["properties"].keys():
                            if "*" in ipconfig["properties"]["publicIPAddress"]:
                                temp["status"] = "Fail"
                    issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def disable_ip_forwading(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                url = network_interface_list_url.format(subscription["subscriptionId"])
                token = get_auth_token(self.credentials)
                response = rest_api_call(token, url, '2019-11-01')
                for vnet in response["value"]:
                    temp = dict()
                    temp["region"] = vnet["location"]
                    temp["status"] = "Pass"
                    temp["resource_name"] = vnet["name"]
                    temp["resource_id"] = ""
                    temp["subscription_id"] = subscription['subscriptionId']
                    temp["subscription_name"] = subscription["displayName"]
                    if vnet["properties"]["enableIPForwarding"] is True:
                        temp["status"] = "Fail"

                    issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def service_endpoint_sql_server(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                url = sql_server_list_url.format(subscription["subscriptionId"])
                token = get_auth_token(self.credentials)
                response = rest_api_call(token, url, api_version='2015-05-01-preview')
                for server in response["value"]:
                    temp = dict()
                    temp["region"] = server["location"]
                    temp["subscription_id"] = subscription['subscriptionId']
                    temp["subscription_name"] = subscription["displayName"]
                    temp["resource_name"] = server['name']
                    temp["resource_id"] = ""
                    temp["status"] = "Fail"
                    virutal_network_url = base_url + server["id"] + "/virtualNetworkRules"
                    token = get_auth_token(self.credentials)
                    network_response = rest_api_call(token, virutal_network_url, api_version='2015-05-01-preview')
                    print(network_response)
                    for network in network_response["value"]:
                        print(network["properties"])
                        if "virtualNetworkSubnetId" in network["properties"].keys():
                            temp["status"] = "Pass"
                    issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def deny_rdp_over_interent(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                url = network_sg_list_url.format(subscription['subscriptionId'])
                token = get_auth_token(self.credentials)
                response = rest_api_call(token, url, api_version="2019-11-01")
                for network in response["value"]:
                    temp = dict()
                    temp["status"] = "Pass"
                    temp["region"] = network["location"]
                    temp["resource_id"] = ""
                    temp["resource_name"] = network["name"]
                    temp["subscription_id"] = subscription['subscriptionId']
                    temp["subscription_name"] = subscription["displayName"]
                    sg_url = base_url + network["id"]
                    token = get_auth_token(self.credentials)
                    resp = rest_api_call(token, sg_url, api_version="2019-11-01")
                    for rule in resp["properties"]["securityRules"]:
                        if rule["properties"]["destinationPortRange"] == "3389" \
                           and rule["properties"]["access"] == "Allow" \
                                and rule["properties"]["direction"] == "Inbound":
                            if rule["properties"]["sourcePortRange"] == "*" or \
                                    rule["properties"]["sourcePortRange"] == "Internet":
                                temp["status"] = "Fail"
                    issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def vpn_gateway_sku(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                url = resource_group_list_url.format(subscription['subscriptionId'])
                token = get_auth_token(self.credentials)
                response = rest_api_call(token, url)
                for resource_group in response["value"]:
                    network_gateway_url = base_url + resource_group["id"] + "/providers/Microsoft.Network/virtualNetworkGateways"
                    token = get_auth_token(self.credentials)
                    network_response = rest_api_call(token, network_gateway_url)
                    for network in network_response["value"]:
                        print(network)
                        temp = dict()
                        temp["region"] = network["location"]
                        temp["status"] = "Pass"
                        temp["resource_name"] = network["name"]
                        temp["resource_id"] = ""
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]
                        if network["properties"]["gatewayType"] == "Vpn" and network["properties"]["sku"]["name"] == "Basic":
                            temp["status"] = "Fail"

        except Exception as e:
            print(str(e))
        finally:
            return issues

    def service_endpoint_container_registry(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                url = container_registry_list_url.format(subscription['subscriptionId'])
                token = get_auth_token(self.credentials)
                response = rest_api_call(token, url)
                for container in response["value"]:
                    temp = dict()
                    temp["region"] = container["location"]
                    temp["status"] = "Fail"
                    temp["resource_name"] = container["name"]
                    temp["resource_id"] = ""
                    temp["subscription_id"] = subscription['subscriptionId']
                    temp["subscription_name"] = subscription["displayName"]
                    if "networkRuleSet" in container["properties"].keys():
                        if container["properties"]["networkRuleSet"]["defaultAction"] == "Allow":
                            temp["status"] = "Pass"
                    issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues




