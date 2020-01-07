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
                    temp = dict()
                    temp["region"] = ""
                    if not profile:
                        temp["status"] = "Fail"
                        temp["resource_name"] = i.display_name
                        temp["resource_id"] = i.subscription_id
                        temp["problem"] = "Log Profile not created for subscription {} ".format(i.display_name)
                    else:
                        temp["status"] = "Pass"
                        temp["resource_name"] = i.display_name
                        temp["resource_id"] = i.subscription_id
                        temp["problem"] = "Log Profile created for subscription {} ".format(i.display_name)
                    issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    # -- Pending
    def is_exported_activity_log_publically_accessible(self):
        issues = []
        try:
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
                    temp = dict()
                    if profile.location is not None:
                        temp['region'] = profile.location
                    else:
                        temp['region'] = ''
                    retention_period = profile.retention_policy.days
                    if retention_period == 0:
                        temp["status"] = "Pass"
                        temp["resource_name"] = profile.name
                        temp["resource_id"] = profile.id
                        temp["problem"] = "Log Profile {} for subcription {} have a sufficient activity log data retention period configured. "\
                                            .format(profile.name, i.display_name)
                    elif retention_period < 365:
                        temp["status"] = "Fail"
                        temp["resource_name"] = profile.name
                        temp["resource_id"] = profile.id
                        temp["problem"] = "Log Profile {} for subscription {} does not have a sufficient activity log data retention period configured. "\
                                        .format(profile.name, i.display_name)
                    else:
                        temp["status"] = "Pass"
                        temp["resource_name"] = profile.name
                        temp["resource_id"] = profile.id
                        temp["problem"] = "Log Profile {} for subscription {} have a sufficient activity log data retention period configured. " \
                            .format(profile.name, i.display_name)
                    issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def get_total_region_export_count(self):
        issues = []
        try:
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
                    temp = dict()
                    if profile.location is not None:
                        temp['region'] = profile.location
                    else:
                        temp['region'] = ''
                    locations_count = len(profile.locations)
                    if locations_count < 35:
                        temp["status"] = "Fail"
                        temp["resource_name"] = profile.name
                        temp["resource_id"] = profile.id
                        temp["problem"] = "Log Profile {} for the subscription {} is  not configured to export activities from all supported Azure regions/locations." \
                            .format(profile.name, i.display_name)
                    else:
                        temp["status"] = "Pass"
                        temp["resource_name"] = profile.name
                        temp["resource_id"] = profile.id
                        temp["problem"] = "Log Profile {} for the subscription {} is configured to export activities from all supported Azure regions/locations." \
                            .format(profile.name, i.display_name)
                    issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def get_log_profile_export_activities(self):
        issues = []
        try:
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
                    temp = dict()
                    if profile.location is not None:
                        temp['region'] = profile.location
                    else:
                        temp['region'] = ''
                    categories_count = len(profile.categories)
                    if categories_count < 3:
                        temp["status"] = "Fail"
                        temp["resource_name"] = profile.name
                        temp["resource_id"] = profile.id
                        temp["problem"] = "Log Profile {} for the subscription {} is  not configured to export Write, Delete and Action events. " \
                            .format(profile.name, i.display_name)
                    else:
                        temp["status"] = "Pass"
                        temp["resource_name"] = profile.name
                        temp["resource_id"] = profile.id
                        temp["problem"] = "Log Profile {} for the subscription {} is  configured to export Write, Delete and Action events. " \
                            .format(profile.name, i.display_name)
                    issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def check_auditevent_enable_for_keyvault(self):
        issues = []
        try:
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
                    temp = dict()
                    d_settings = monitor_client.diagnostic_settings.list(vault.id)
                    for d_setting in d_settings.value:
                        logs = d_setting.logs
                        for log in logs:
                            if log.enabled : # if it is true then AuditEvent enabled for the following KeyVault
                                temp["status"] = "Pass"
                                temp["resource_name"] = vault.name
                                temp["resource_id"] = vault.id
                                temp["region"] = vault.location
                                temp["problem"] = "AuditEvent logging enabled for Azure Key Vault {} " \
                                    .format(vault.name)
                            else:
                                temp["status"] = "Fail"
                                temp["resource_name"] = vault.name
                                temp["resource_id"] = vault.id
                                temp["region"] = vault.location
                                temp["problem"] = "AuditEvent logging not enabled for Azure Key Vault {} " \
                                    .format(vault.name)
                        issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def is_activity_log_storage_encrypted(self):
        issues = []
        try:

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
                        temp = dict()
                        storageAccountId = profile.storage_account_id.split("/")[8]
                        key_source = storage_service.get_storage_container_access_status(storageAccountId,subscription_id,resource_group_name[4])
                        if key_source == 'Microsoft.Storage':
                            temp["status"] = "Fail"
                            temp["resource_name"] = profile.name
                            temp["resource_id"] = profile.id
                            temp["region"] = profile.location
                            temp["problem"] = "Microsoft Azure storage  {} container that contains  activity log files is encrypted using a service-managed key instead of a customer-managed key." \
                                .format(storageAccountId)
                        else:
                            temp["status"] = "Pass"
                            temp["resource_name"] = profile.name
                            temp["resource_id"] = profile.id
                            temp["region"] = profile.location
                            temp["problem"] = "Microsoft Azure storage  {} container that contains  activity log files is encrypted using a customer-managed key." \
                                .format(storageAccountId)
                        issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues
