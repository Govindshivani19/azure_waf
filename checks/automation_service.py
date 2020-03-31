from helper_function import rest_api_call, get_adal_token
from constants import automation_accounts_url, base_url


class AutomationService:
    def __init__(self, credentials, subscription_list):
        self.credentials = credentials
        self.subscription_list = subscription_list

    def check_variable_encryption(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                url = automation_accounts_url.format(subscription["subscriptionId"])
                response = rest_api_call(self.credentials, url, api_version="2015-10-31")
                for account in response["value"]:
                    temp = dict()
                    temp["status"] = "Fail"
                    temp["resource_name"] = account["name"]
                    temp["resource_id"] = ""
                    temp["subscription_id"] = subscription['subscriptionId']
                    temp["subscription_name"] = subscription["displayName"]
                    temp["region"] = account["location"]
                    variable_url = base_url + account["id"] + "/variables"
                    variable_response = rest_api_call(self.credentials, variable_url, api_version="2015-10-31")
                    for x in variable_response["value"]:
                        if x["properties"]["isEncrypted"]:
                            temp["status"] = "Pass"
                    issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues