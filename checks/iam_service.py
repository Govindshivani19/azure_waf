from azure.common.credentials import ServicePrincipalCredentials
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.mgmt.resource import SubscriptionClient, ResourceManagementClient
import os


class IamServices:
    def __init__(self, client):
        self.client = client

    def get_roles(self):
        issues = []
        try:
            subscription_id = ""
            credentials = ServicePrincipalCredentials(
                client_id=os.environ['AZURE_CLIENT_ID'],
                secret=os.environ['AZURE_CLIENT_SECRET'],
                tenant=os.environ['AZURE_TENANT_ID']
            )
            subscription_client = SubscriptionClient(credentials)
            subscription_list = subscription_client.subscriptions.list()

            for i in subscription_list:
                subscription_id = i.subscription_id
                resource_client = ResourceManagementClient(credentials, subscription_id)
                for resource in resource_client.resource_groups.list():
                    role_definition_client = AuthorizationManagementClient(credentials, subscription_id)
                    scope = "/subscriptions/{}/resourceGroups/{}".format(subscription_id, resource.name)
                    roles = role_definition_client.role_definitions.list(scope=scope, filter="type eq 'CustomRole'")
                    roles_list = roles.advance_page()
                    scope_reg_exp = '/subscriptions/{}'.format(subscription_id)
                    for role in roles_list:
                        temp = dict()
                        temp["region"] = ""

                        selected_roles = role_definition_client.role_definitions.list(scope=scope, filter="roleName eq '{}'".format(role.role_name))
                        sel_roles_list = selected_roles.advance_page()
                        scope_flag = 0
                        permission_flag = 0
                        for opt in sel_roles_list:
                            for scope in opt.assignable_scopes:
                                if scope == '/' or scope == scope_reg_exp:
                                    scope_flag = 1
                            for per in opt.permissions:
                                for action in per.actions:
                                    if action == "*":
                                        permission_flag = 1
                        if scope_flag == 1 and permission_flag == 1:
                            temp["status"] = "Fail"
                            temp["resource_name"] = role.name
                            temp["resource_id"] = role.id
                            temp["problem"] = "{} is a custom owner role". format(role.role_name)
                        else:
                            temp["status"] = "Pass"
                            temp["resource_name"] = role.name
                            temp["resource_id"] = role.id
                            temp["problem"] = "{} is not a custom owner role".format(role.role_name)
                        issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues
