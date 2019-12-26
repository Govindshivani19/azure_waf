from checks.storage_service import StorageServices
from checks.iam_service import IamServices
from db_helper import insert_checks, insert_audit_records

def __start_audit__():
    print("start audit");
    storage_service = StorageServices('abc');
    #issues = storage_service.restrict_default_network_access()
    #insert_audit_records('12345', issues, 'CEN_AZ_8')

    #iam_service = IamServices('abc');
    #iam_service.get_roles()

    #insert_checks('CEN_AZ_8','Storage Accounts - Restrict Default Network Access', 'Deny access from all trafic to Storage Accounts')

__start_audit__()