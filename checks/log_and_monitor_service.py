from azure.common.credentials import ServicePrincipalCredentials
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.mgmt.resource import SubscriptionClient, ResourceManagementClient
from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.mgmt.monitor import *
from checks.storage_service import StorageServices
import os


class LogAndMonitorServices:
    def __init__(self, client):
        self.client = client

    def get_log_profiles(self):
        issues = []
        try:
            os.environ['AZURE_CLIENT_ID'] = "90b95777-e9bb-4220-bcd1-cf0acfe2396d"
            os.environ['AZURE_CLIENT_SECRET'] = "oRFP0UZYo?:HzGuk-S=U2Ebn53l/2[Ln"
            os.environ['AZURE_TENANT_ID'] = "3e53c24a-181d-4e1a-8a6b-93327212e0e6"

            #os.environ['AZURE_CLIENT_ID'] = "400fca98-15f2-47c6-971d-47c1e24759e3"
            #os.environ['AZURE_CLIENT_SECRET'] = "mP/Lu/w-vbiJBes4Rv2]YLsbi3GvkQX8"
            #os.environ['AZURE_TENANT_ID'] = "3e53c24a-181d-4e1a-8a6b-93327212e0e6"


            subscription_id = ""
            credentials = ServicePrincipalCredentials(
                client_id=os.environ['AZURE_CLIENT_ID'],
                secret=os.environ['AZURE_CLIENT_SECRET'],
                tenant=os.environ['AZURE_TENANT_ID']
            )
            subscription_client = SubscriptionClient(credentials)
            subscription_list = subscription_client.subscriptions.list()
            print(subscription_list)
            for i in subscription_list:
                subscription_id = i.subscription_id
                print("---------------")
                print(subscription_id)
                monitor_client = MonitorManagementClient(credentials, subscription_id)
                log_profiles = monitor_client.log_profiles.list()
                for profile in log_profiles:
                    print(profile)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    # -- Pending
    def is_exported_activity_log_publically_accessible(self):
        issues = []
        try:
            os.environ['AZURE_CLIENT_ID'] = "90b95777-e9bb-4220-bcd1-cf0acfe2396d"
            os.environ['AZURE_CLIENT_SECRET'] = "oRFP0UZYo?:HzGuk-S=U2Ebn53l/2[Ln"
            os.environ['AZURE_TENANT_ID'] = "3e53c24a-181d-4e1a-8a6b-93327212e0e6"

            #os.environ['AZURE_CLIENT_ID'] = "400fca98-15f2-47c6-971d-47c1e24759e3"
            #os.environ['AZURE_CLIENT_SECRET'] = "mP/Lu/w-vbiJBes4Rv2]YLsbi3GvkQX8"
            #os.environ['AZURE_TENANT_ID'] = "3e53c24a-181d-4e1a-8a6b-93327212e0e6"

            storage_service = StorageServices('abc')

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
                resource_group_client = ResourceManagementClient(credentials,subscription_id)
                for resource_group in resource_group_client.resource_groups.list():
                    resource_group_name = resource_group.id.split("/")
                    monitor_client = MonitorManagementClient(credentials, subscription_id)
                    log_profiles = monitor_client.log_profiles.list()
                    for profile in log_profiles:
                        storageAccountId = profile.storage_account_id.split("/")[8]
                        print(storage_service.get_storage_container_access_status(storageAccountId,subscription_id,resource_group_name[4]))
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def get_log_retention_period(self):
        issues = []
        try:
            os.environ['AZURE_CLIENT_ID'] = "90b95777-e9bb-4220-bcd1-cf0acfe2396d"
            os.environ['AZURE_CLIENT_SECRET'] = "oRFP0UZYo?:HzGuk-S=U2Ebn53l/2[Ln"
            os.environ['AZURE_TENANT_ID'] = "3e53c24a-181d-4e1a-8a6b-93327212e0e6"

            #os.environ['AZURE_CLIENT_ID'] = "400fca98-15f2-47c6-971d-47c1e24759e3"
            #os.environ['AZURE_CLIENT_SECRET'] = "mP/Lu/w-vbiJBes4Rv2]YLsbi3GvkQX8"
            #os.environ['AZURE_TENANT_ID'] = "3e53c24a-181d-4e1a-8a6b-93327212e0e6"

            storage_service = StorageServices('abc')

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
                monitor_client = MonitorManagementClient(credentials, subscription_id)
                log_profiles = monitor_client.log_profiles.list()
                for profile in log_profiles:
                    retention_period = profile.retention_policy.days
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def get_total_region_export_count(self):
        issues = []
        try:
            os.environ['AZURE_CLIENT_ID'] = "90b95777-e9bb-4220-bcd1-cf0acfe2396d"
            os.environ['AZURE_CLIENT_SECRET'] = "oRFP0UZYo?:HzGuk-S=U2Ebn53l/2[Ln"
            os.environ['AZURE_TENANT_ID'] = "3e53c24a-181d-4e1a-8a6b-93327212e0e6"

            #os.environ['AZURE_CLIENT_ID'] = "400fca98-15f2-47c6-971d-47c1e24759e3"
            #os.environ['AZURE_CLIENT_SECRET'] = "mP/Lu/w-vbiJBes4Rv2]YLsbi3GvkQX8"
            #os.environ['AZURE_TENANT_ID'] = "3e53c24a-181d-4e1a-8a6b-93327212e0e6"

            storage_service = StorageServices('abc')

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
                monitor_client = MonitorManagementClient(credentials, subscription_id)
                log_profiles = monitor_client.log_profiles.list()
                for profile in log_profiles:
                    locations_count = len(profile.locations)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def get_log_profile_export_activities(self):
        issues = []
        try:
            os.environ['AZURE_CLIENT_ID'] = "90b95777-e9bb-4220-bcd1-cf0acfe2396d"
            os.environ['AZURE_CLIENT_SECRET'] = "oRFP0UZYo?:HzGuk-S=U2Ebn53l/2[Ln"
            os.environ['AZURE_TENANT_ID'] = "3e53c24a-181d-4e1a-8a6b-93327212e0e6"

            #os.environ['AZURE_CLIENT_ID'] = "400fca98-15f2-47c6-971d-47c1e24759e3"
            #os.environ['AZURE_CLIENT_SECRET'] = "mP/Lu/w-vbiJBes4Rv2]YLsbi3GvkQX8"
            #os.environ['AZURE_TENANT_ID'] = "3e53c24a-181d-4e1a-8a6b-93327212e0e6"

            storage_service = StorageServices('abc')

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
                monitor_client = MonitorManagementClient(credentials, subscription_id)
                log_profiles = monitor_client.log_profiles.list()
                for profile in log_profiles:
                    categories_count = len(profile.categories)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def check_auditevent_enable_for_keyvault(self):
        try:
            os.environ['AZURE_CLIENT_ID'] = "90b95777-e9bb-4220-bcd1-cf0acfe2396d"
            os.environ['AZURE_CLIENT_SECRET'] = "oRFP0UZYo?:HzGuk-S=U2Ebn53l/2[Ln"
            os.environ['AZURE_TENANT_ID'] = "3e53c24a-181d-4e1a-8a6b-93327212e0e6"

            credentials = ServicePrincipalCredentials(
                client_id=os.environ['AZURE_CLIENT_ID'],
                secret=os.environ['AZURE_CLIENT_SECRET'],
                tenant=os.environ['AZURE_TENANT_ID']
            )

            subscription_client = SubscriptionClient(credentials)
            subscription_list = subscription_client.subscriptions.list()
            for i in subscription_list:
                subscription_id = i.subscription_id
                keyVault_client = KeyVaultManagementClient(credentials, subscription_id)
                vaultList = keyVault_client.vaults.list()
                monitor_client = MonitorManagementClient(credentials, subscription_id)
                for vault in vaultList:
                    print(vault.id)
                    d_settings = monitor_client.diagnostic_settings.list(vault.id)
                    for d_setting in d_settings.value:
                        logs = d_setting.logs
                        for log in logs:
                            print(log.enabled) # if it is true then AuditEvent enabled for the following KeyVault
        except Exception as e:
            raise

    def is_activity_log_storage_encrypted(self):
        issues = []
        try:
            os.environ['AZURE_CLIENT_ID'] = "90b95777-e9bb-4220-bcd1-cf0acfe2396d"
            os.environ['AZURE_CLIENT_SECRET'] = "oRFP0UZYo?:HzGuk-S=U2Ebn53l/2[Ln"
            os.environ['AZURE_TENANT_ID'] = "3e53c24a-181d-4e1a-8a6b-93327212e0e6"

            #os.environ['AZURE_CLIENT_ID'] = "400fca98-15f2-47c6-971d-47c1e24759e3"
            #os.environ['AZURE_CLIENT_SECRET'] = "mP/Lu/w-vbiJBes4Rv2]YLsbi3GvkQX8"
            #os.environ['AZURE_TENANT_ID'] = "3e53c24a-181d-4e1a-8a6b-93327212e0e6"

            storage_service = StorageServices('abc')

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
                resource_group_client = ResourceManagementClient(credentials,subscription_id)
                for resource_group in resource_group_client.resource_groups.list():
                    resource_group_name = resource_group.id.split("/")
                    monitor_client = MonitorManagementClient(credentials, subscription_id)
                    log_profiles = monitor_client.log_profiles.list()
                    for profile in log_profiles:
                        storageAccountId = profile.storage_account_id.split("/")[8]
                        print(storage_service.get_storage_container_access_status(storageAccountId,subscription_id,resource_group_name[4]))
        except Exception as e:
            print(str(e))
        finally:
            return issues
