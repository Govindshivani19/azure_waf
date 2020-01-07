from checks.storage_service import StorageServices
from checks.iam_service import IamServices
from checks.log_and_monitor_service import LogAndMonitorServices
from db_helper import insert_checks, insert_audit_records


def __start_audit__():
    print("start audit");
    s3_service = StorageServices('abc');
    #s3_service.regenerate_storage_account_keys()
    #issues = s3_service.restrict_default_network_access()
    #logging = LogAndMonitorServices('abc')
    #issues = logging.is_activity_log_storage_encrypted()
    iam = IamServices('abc')
    #iam.test()
    issues = iam.get_custom_roles()
    #insert_audit_records('12345', issues, 'CEN_AZ_16')



    #insert_checks('CEN_AZ_8','Storage Accounts - Restrict Default Network Access', 'Deny access from all trafic to Storage Accounts')

__start_audit__()
