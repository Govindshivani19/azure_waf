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
        checks.check_id = check_id
        checks.check_name = check_name
        checks.rule = rule
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
                audit_record.__dict__["check_id"] = check_id
                audit_record.__dict__["execution_hash"] = execution_hash
                for key, value in issue.items():
                    audit_record.__dict__[key] = value
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
                account_hash = account.account_hash
                temp = {
                    "account_hash": account_hash,
                    "tenant_id": tenant_id,
                    "client_id": application_id
                }
                accounts.append(temp)
        else:
            accounts_list = session.query(AzAccount).filter(AzAccount.is_active != '0')\
                            .filter(AzAccount.account_hash == account_hash).all();
            for account in accounts_list:
                temp = dict()
                tenant_id = account.tenant_id
                application_id = account.application_id
                account_hash = account.account_hash
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


def update_execution(execution_hash, staus):
    session = Session(expire_on_commit=False)
    try:
        account = session.query(AzExecutionDetails).filter(
            AzExecutionDetails.execution_hash == execution_hash).first()
        account.status = staus
        session.commit()
    except Exception as e:
        print(str(e))
    finally:
        session.close()