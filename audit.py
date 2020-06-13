from checks.storage_service import StorageService
from checks.iam_service import IamServices
from checks.monitor_log_service import MonitorLogService
from checks.database_service import DatabaseService
from checks.other_services import AzureServices
from checks.vm_service import VmService
from checks.automation_service import AutomationService
from checks.security_service import SecurityService
from db_helper import fetch_accounts, update_execution
from helper_function import get_application_key, rest_api_call
from execute_checks import *
from checks.common_services import CommonServices
from checks.kubernetes_service import KubernetesService
from checks.app_service import AppService
from checks.network_service import NetworkService
import os
import logging.config
import logging as logger


def __start_audit__():
    try:
        credentials = dict()
        accounts = []
        az_account_hash = os.environ["account_hash"]
        task_id = int(os.environ["task_id"])

        if len(az_account_hash) > 1:
             accounts = fetch_accounts(az_account_hash)
        else:
             accounts = fetch_accounts()

        #if True:
        for account in accounts:
            # client_secret = get_application_key(account['account_hash'])
            # credentials['AZURE_TENANT_ID'] = account["tenant_id"]
            # credentials['AZURE_CLIENT_ID'] = account["client_id"]
            # credentials['AZURE_CLIENT_SECRET'] = client_secret

            logger_msg = "azure_waa_2_" + az_account_hash +"_task_id_" +task_id
            logging.basicConfig(level=logging.INFO,
                                format='Execution {} : %(levelname)s  %(message)s'.format(logger_msg),
                                datefmt='%Y-%m-%d %H:%M:%S')

            credentials['AZURE_TENANT_ID'] = os.environ["AZURE_TENANT_ID"]
            credentials['AZURE_CLIENT_ID'] = os.environ["AZURE_CLIENT_ID"]
            credentials['AZURE_CLIENT_SECRET'] = os.environ["AZURE_CLIENT_SECRET"]

            cs = CommonServices()
            subscription_list = cs.get_subscriptions_list(credentials)


            storage_service = StorageService(credentials, subscription_list)
            iam_service = IamServices(credentials, subscription_list)
            monitor_service = MonitorLogService(credentials, subscription_list)
            security_service = SecurityService(credentials, subscription_list)
            db_service = DatabaseService(credentials, subscription_list)
            vm_service = VmService(credentials, subscription_list)
            az_service = AzureServices(credentials, subscription_list)
            automation_service = AutomationService(credentials, subscription_list)
            kubernetes_service = KubernetesService(credentials, subscription_list)
            app_service = AppService(credentials, subscription_list)
            network_service = NetworkService(credentials, subscription_list)

            execute_log_monitor_checks(task_id, monitor_service)
            execute_iam_checks(task_id, iam_service)
            execute_security_centre_checks(task_id, security_service)
            execute_database_checks(task_id, db_service)
            execute_vm_checks(task_id, vm_service)
            execute_disk_checks(task_id, vm_service)
            execute_az_services_checks(task_id, az_service)
            execute_storage_checks(task_id, storage_service)
            execute_automation_services_checks(task_id, automation_service)
            execute_network_checks(task_id, network_service)
            execute_app_service_checks(task_id, app_service)
            execute_kubernetes_service_checks(task_id, kubernetes_service)

            update_execution(task_id, "completed")

    except Exception as e:
        logger.error("error", e);


__start_audit__()