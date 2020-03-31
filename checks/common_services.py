from helper_function import rest_api_call
from constants import subscriptions_list_url, resource_group_list_url


class CommonServices:
    def get_subscriptions_list(self, credentials):

        subscriptions = list()

        try:
            response = rest_api_call(
                credentials=credentials,
                url=subscriptions_list_url
            )
            subscriptions = response.get("value", [])

        except Exception as e:
            print(str(e))
        finally:
            return subscriptions

    def get_resource_groups(self, credentials):

        resource_groups = list()

        try:

            response = rest_api_call(
                credentials=credentials,
                url=resource_group_list_url.format(subscription_id)
            )
            resource_groups = response.get("value", [])

        except Exception as e:
            print(str(e))
        finally:
            return resource_groups
