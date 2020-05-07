import datetime
import decimal
import uuid
import json
from db_connect import Session
from model.db_models import AzAccount, AZChecks, AzAudit, AzExecutionDetails
from sqlalchemy import delete, update
import os
from base64 import b64decode
import hashlib
from Cryptodome.Cipher import AES



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
                tenant_id = account.tenant_id
                application_id = account.application_id
                encrypted_string = json.loads(account.encrypted_string)
                client_secret = decryption(encrypted_string)
                temp = {
                    "client_secret": client_secret,
                    "tenant_id": tenant_id,
                    "client_id": application_id
                }
                accounts.append(temp)
        else:
            accounts_list = session.query(AzAccount).filter(AzAccount.is_active != '0')\
                            .filter(AzAccount.account_hash == account_hash).all();
            for account in accounts_list:
                tenant_id = account.tenant_id
                application_id = account.application_id
                encrypted_string = json.loads(account.encrypted_string)
                client_secret = decryption(encrypted_string)
                temp = {
                    "client_secret": client_secret,
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


def decryption(encrypted_string):
    encryption_key = os.environ["encryption_key"]
    salt = b64decode(encrypted_string['salt'])
    cipher_text = b64decode(encrypted_string['cipher_text'])
    nonce = b64decode(encrypted_string['nonce'])
    tag = b64decode(encrypted_string['tag'])
    private_key = hashlib.scrypt(
        encryption_key.encode(), salt=salt, n=2 ** 14, r=8, p=1, dklen=32)
    cipher = AES.new(private_key, AES.MODE_GCM, nonce=nonce)
    decrypted = cipher.decrypt_and_verify(cipher_text, tag)
    return decrypted
