import datetime
import decimal
import uuid
from db_connect import Session
from model.db_models import AzAccount, AZChecks, AzAudit, AzExecutionDetails
from sqlalchemy import delete, update


def insert_checks(check_id, check_name, rule):
    session = Session(expire_on_commit=False)
    try:
        checks = AZChecks()
        checks.az_check_id = check_id
        checks.az_check_name = check_name
        checks.az_rule = rule
        session.add(checks)
        session.commit()
    except Exception as e:
        print(str(e))
    finally:
        session.close()


def insert_audit_records(execution_hash, issues, check_id):
    session = Session(expire_on_commit=False)
    try:
        if issues :
            print("issue")
            print(check_id)
            for issue in issues:
                audit_record = AzAudit()
                audit_record.check_id = check_id
                audit_record.az_execution_hash = execution_hash
                audit_record.region = issue["region"]
                audit_record.resource_id = issue["resource_id"]
                audit_record.resource_name = issue["resource_name"]
                audit_record.problem = issue["problem"]
                audit_record.status = issue["status"]
                session.add(audit_record)
                session.commit()
            print("inserted to db")
    except Exception as e:
        print(str(e))
    finally:
        session.close()


def fetch_accounts(account_hash=None):
    session = Session(expire_on_commit=False)
    accounts = []
    try:
        if account_hash is None:
            accounts_list = session.query(AzAccount).filter(AzAccount.is_active != '0').all();
            for account in accounts_list:
                temp = dict()
                tenant_id = account.tenant_id
                application_id = account.application_id
                account_hash = account.az_account_hash
                temp = {
                    "account_hash": account_hash,
                    "tenant_id": tenant_id,
                    "client_id": application_id
                }
                accounts.append(temp)
        else:
            accounts_list = session.query(AzAccount).filter(AzAccount.is_active != '0')\
                            .filter(AzAccount.az_account_hash == account_hash).all();
            for account in accounts_list:
                temp = dict()
                tenant_id = account.tenant_id
                application_id = account.application_id
                account_hash = account.az_account_hash
                temp = {
                    "account_hash": account_hash,
                    "tenant_id": tenant_id,
                    "client_id": application_id
                }
                accounts.append(temp)
    except Exception as e:
        print(str(e))
    finally:
        session.close()
        return accounts


def create_execution(account_hash):
    execution_hash = ""
    session = Session(expire_on_commit=False)
    try:
        execution_detail = AzExecutionDetails()
        execution_detail.az_execution_hash = uuid.uuid4().hex
        execution_hash = execution_detail.az_execution_hash
        execution_detail.status = 0
        execution_detail.completed_checks = 0
        execution_detail.failed_checks = 0
        execution_detail.az_account_hash_exe = account_hash
        session.add(execution_detail)
        session.commit()
    except Exception as e:
        print(str(e))
    finally:
        session.close()
        return execution_hash


def update_execution(execution_hash, staus):
    session = Session(expire_on_commit=False)
    try:
        account = session.query(AzExecutionDetails).filter(
            AzExecutionDetails.az_execution_hash == execution_hash).first()
        account.status = staus
        session.commit()
    except Exception as e:
        print(str(e))
    finally:
        session.close()