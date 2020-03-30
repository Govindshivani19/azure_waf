from helper_function import rest_api_call
from constants import subscriptions_list_url, resource_group_list_url


class CommonServices:
    def get_subscriptions_list(self, token):
        subscriptions = list()
        try:
            url = subscriptions_list_url
            response = rest_api_call(token, url)
            subscriptions = response['value']
        except Exception as e:
            print(str(e))
        finally:
            return subscriptions

    def get_resource_groups(self, token, subscription_id):
        resource_groups = list()
        try:
            url = resource_group_list_url.format(subscription_id)
            response = rest_api_call(token, url)
            resource_groups = response['value']
        except Exception as e:
            print(str(e))
        finally:
            return resource_groups
