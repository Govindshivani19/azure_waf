from helper_function import rest_api_call
from constants import managed_clusters_url, base_url


class KubernetesService:
    def __init__(self, credentials, subscription_list):
        self.credentials = credentials
        self.subscription_list = subscription_list

    def rbac_on_aks(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                url = managed_clusters_url.format(subscription['subscriptionId'])
                response = rest_api_call(self.credentials, url)
                managed_cluster_list = response['value']
                for managed_cluster in managed_cluster_list:
                    url = base_url + managed_cluster["id"]
                    managed_cluster_response = rest_api_call(self.credentials, url)
                    temp = dict()
                    temp["status"] = "Fail"
                    temp["region"] = managed_cluster["location"]
                    temp["resource_id"] = ""
                    temp["resource_name"] = managed_cluster["name"]
                    temp["subscription_id"] = subscription['subscriptionId']
                    temp["subscription_name"] = subscription["displayName"]

                    if (managed_cluster_response["properties"])["enableRBAC"] is True:
                        temp["status"] = "Pass"
                    issues.append(temp)

        except Exception as e:
            print(str(e))
        finally:
            return issues
