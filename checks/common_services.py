from helper_function import rest_api_call, get_auth_token
from contants import subscriptions_list_url, resource_group_list_url


class CommonServices:
    def get_subscriptions_list(self, credentials):
        subscriptions = list()
        try:
            pagination = 0
            token = get_auth_token(credentials)
            url = subscriptions_list_url
            response = rest_api_call(token, url)
            for subscription in response["value"]:
                subscriptions.append(subscription)
            if "nextLink" in response:
                pagination = 1

            while pagination == 1:
                filters = "$skipToken={} ".format(response['nextLink'].split('skipToken=')[1])
                token = get_auth_token(credentials)
                url = subscriptions_list_url + "?$filter=" + filters
                response = rest_api_call(token, url)
                for subscription in response["value"]:
                    subscriptions.append(subscription)
                if "nextLink" in response:
                    pagination = 1
                else:
                    pagination = 0
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
