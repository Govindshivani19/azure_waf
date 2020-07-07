from helper_function import rest_api_call
from constants import appconfiguration_list_url
import re
import logging as logger
from checks.common_services import CommonServices


class AppConfigurationService:
    def __init__(self, credentials, subscription_list):
        self.credentials = credentials
        self.subscription_list = subscription_list

    def app_config_customer_managed_key(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                temp = dict()
                resource_groups = CommonServices().get_resource_groups(self.credentials, subscription['subscriptionId'])
                for resource in resource_groups:
                    url = appconfiguration_list_url.format(resource['id'])
                    response = rest_api_call(self.credentials, url, '2020-06-01')['value']
                    for resp in response:
                        encryption_property = resp['properties']['encryption']
                        if len(encryption_property['keyVaultProperties']['keyIdentifier']) > 1:
                            temp['status'] = 'Pass'
                            temp['keyId'] = encryption_property['keyVaultProperties']['keyIdentifier']
                            temp['appConfiguration_name'] = resp['name']
                            temp['resource_name'] = resource['name']
                            temp['subscription'] = subscription['subscriptionId']
                        else:
                            temp['status'] = 'Fail'
                            temp['appConfiguration_name'] = resp['name']
                            temp['resource_name'] = resource['name']
                            temp['subscription'] = subscription['subscriptionId']
                        issues.append(temp)
                        print(temp)
        except Exception as e:
            logger.error(e);
        finally:
            return issues