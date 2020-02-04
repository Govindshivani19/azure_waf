from checks.storage_service import StorageService
from checks.iam_service import IamServices
from checks.monitor_log_service import MonitorLogService
from checks.security_service import SecurityService
from checks.database_service import DatabaseService
from db_helper import fetch_accounts, create_execution, update_execution
from helper_function import get_application_key
from execute_checks import (
    execute_log_monitor_checks, execute_storage_checks, execute_iam_checks,
    execute_security_centre_checks, execute_database_checks
)
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
            client_secret = get_application_key(account['account_hash'])
            credentials['AZURE_TENANT_ID'] = account["tenant_id"]
            credentials['AZURE_CLIENT_ID'] = account["client_id"]
            credentials['AZURE_CLIENT_SECRET'] = client_secret
            execution_hash = create_execution(account['account_hash'])
            storage_service = StorageService(credentials)
            iam_service = IamServices(credentials)
            monitor_service = MonitorLogService(credentials)
            security_service = SecurityService(credentials)
            db_service = DatabaseService(credentials)
            execute_storage_checks(execution_hash, storage_service)
            execute_log_monitor_checks(execution_hash, monitor_service)
            execute_iam_checks(execution_hash, iam_service)
            execute_security_centre_checks(execution_hash, security_service)
            execute_database_checks(execution_hash, db_service)
            update_execution(execution_hash,2)
    except Exception as e:
        print(str(e))

    #insert_checks('CEN_AZ_8','Storage Accounts - Restrict Default Network Access', 'Deny access from all trafic to Storage Accounts')

__start_audit__()