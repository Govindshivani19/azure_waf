import datetime
import decimal
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
            for issue in issues:
                audit_record = AzAudit()
                audit_record.az_check_id = check_id
                audit_record.az_execution_hash = execution_hash
                audit_record.az_region = issue["region"]
                audit_record.az_resource_id = issue["resource_id"]
                audit_record.az_resource_name = issue["resource_name"]
                audit_record.az_problem = issue["problem"]
                audit_record.status = issue["status"]
                session.add(audit_record)
                session.commit()
    except Exception as e:
        print(str(e))
    finally:
        session.close()