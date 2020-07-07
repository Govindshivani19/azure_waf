from helper_function import rest_api_call
from constants import base_url,datalake_store_accounts_list_url,resource_group_list_url
import re
import logging as logger
from checks.common_services import CommonServices


class DatalakeService:
    def __init__(self, credentials, subscription_list):
        self.credentials = credentials
        self.subscription_list = subscription_list

    def encryption_on_datalake_store(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                resource_group_url = resource_group_list_url.format(subscription['subscriptionId'])
                resources = rest_api_call(self.credentials, resource_group_url, "2016-06-01")
                list_resources = resources['value']
                for resource in list_resources:
                    #print(resource)
                    rid = resource['id']
                    list_datalake_store = datalake_store_accounts_list_url.format(rid)
                    accounts = rest_api_call(self.credentials, list_datalake_store, '2016-11-01')['value']
                    for acc in accounts:
                        #print(acc)
                        temp = dict()
                        aid = acc['id']
                        url = base_url + aid +'?'
                        data = rest_api_call(self.credentials, url, '2016-11-01')
                        if data['properties']['encryptionState'] == 'Enabled':
                            temp['status'] = "Enabled"
                            temp['account name'] = acc['name']
                            temp['resource_group'] = resource['name']
                            temp['subscription'] = subscription['subscriptionId']
                        else:
                            temp['status'] = "Disabled"
                            temp['account name'] = acc['name']
                            temp['resource_group'] = resource['name']
                            temp['subscription'] = subscription['subscriptionId']
                        issues.append(temp)

        except Exception as e:
            logger.error(e)
        finally:
            return issues




