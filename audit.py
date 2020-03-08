from checks.storage_service import StorageService
from checks.iam_service import IamServices
from checks.monitor_log_service import MonitorLogService
from checks.security_service import SecurityService
from checks.database_service import DatabaseService
from checks.other_services import AzureServices
from checks.vm_service import VmService
from db_helper import fetch_accounts, update_execution
from helper_function import get_application_key, get_auth_token, rest_api_call
from execute_checks import (
    execute_log_monitor_checks, execute_storage_checks, execute_iam_checks,
    execute_security_centre_checks, execute_database_checks, execute_vm_checks, execute_disk_checks, execute_az_services_checks
)
from checks.common_services import CommonServices
import os


def __start_audit__():
    print("start audit")
    try:
        credentials = dict()
        accounts = []
        az_account_hash = os.environ["az_account_hash"]
        if len(az_account_hash) > 1:
            accounts = fetch_accounts(az_account_hash)
        else:
            accounts = fetch_accounts()

        for account in accounts:
            '''client_secret = get_application_key(account['account_hash'])
            credentials['AZURE_TENANT_ID'] = account["tenant_id"]
            credentials['AZURE_CLIENT_ID'] = account["client_id"]
            credentials['AZURE_CLIENT_SECRET'] = client_secret
            # execution_hash = create_execution(account['account_hash'])'''

            credentials['AZURE_TENANT_ID'] = os.environ["AZURE_TENANT_ID"]
            credentials['AZURE_CLIENT_ID'] = os.environ["AZURE_CLIENT_ID"]
            credentials['AZURE_CLIENT_SECRET'] = os.environ["AZURE_CLIENT_SECRET"]

            token = get_auth_token(credentials)
            cs = CommonServices()
            subscription_list = cs.get_subscriptions_list(token)

            execution_hash = os.environ["execution_hash"]
            storage_service = StorageService(credentials, subscription_list)
            iam_service = IamServices(credentials, subscription_list)
            monitor_service = MonitorLogService(credentials, subscription_list)
            security_service = SecurityService(credentials, subscription_list)
            db_service = DatabaseService(credentials, subscription_list)
            vm_service = VmService(credentials, subscription_list)
            az_service = AzureServices(credentials, subscription_list)

            execute_log_monitor_checks(execution_hash, monitor_service)
            execute_iam_checks(execution_hash, iam_service)
            execute_security_centre_checks(execution_hash, security_service)
            execute_database_checks(execution_hash, db_service)
            execute_vm_checks(execution_hash, vm_service)
            execute_disk_checks(execution_hash, vm_service)
            execute_az_services_checks(execution_hash, az_service)
            execute_storage_checks(execution_hash, storage_service)
            update_execution(execution_hash, 2)

    except Exception as e:
        print(str(e))


__start_audit__()