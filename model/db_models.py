# coding: utf-8
from sqlalchemy import BigInteger, Boolean, Column, Date, DateTime, Integer, Numeric, SmallInteger, String, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.dialects.mysql import LONGTEXT

Base = declarative_base()
metadata = Base.metadata


class Account(Base):
    __tablename__ = 'account'
    __table_args__ = {"schema": "chanak"}

    id = Column(Integer, nullable=False, primary_key=True, server_default=text("nextval('account_id_seq'::regclass)"))
    aws_account_id = Column(String(50), nullable=False)
    account_name = Column(String(100), nullable=False)
    account_hash = Column(String(100), nullable=False)
    is_active = Column(Boolean, nullable=False)
    account_type_id = Column(Integer, nullable=False)
    master_account_hash = Column(String(100))
    billing_bucket_name = Column(String(500))
    customer_hash = Column(String(100), nullable=False)
    created_at = Column(DateTime, nullable=False, server_default=text("CURRENT_TIMESTAMP"))
    updated_at = Column(DateTime, nullable=False, server_default=text("CURRENT_TIMESTAMP"))
    is_role_added = Column(Boolean, nullable=False, server_default=text("false"))
    is_deleted = Column(Boolean)
    encrypted_string = Column(String(1000))


class AccountType(Base):
    __tablename__ = 'account_type'
    __table_args__ = {"schema": "chanak"}

    id = Column(Integer, nullable=False, primary_key=True, server_default=text("nextval('account_type_id_seq'::regclass)"))
    account_type = Column(String(100), nullable=False)

class Customer(Base):
    __tablename__ = 'customer'
    __table_args__ = {"schema": "chanak"}

    id = Column(Integer, primary_key=True, nullable=False, server_default=text("nextval('customer_id_seq'::regclass)"))
    customer_name = Column(String(100), nullable=False)
    default_timezone = Column(String(10), nullable=False, server_default=text("'+00:00'::character varying"))
    customer_hash = Column(String(100), nullable=False)
    is_active = Column(Boolean, nullable=False)
    creator_user_hash = Column(String(100))
    created_at = Column(DateTime, nullable=False, server_default=text("CURRENT_TIMESTAMP"))
    updated_at = Column(DateTime, nullable=False, server_default=text("CURRENT_TIMESTAMP"))
    is_deleted = Column(Boolean, server_default=text("false"))

class User(Base):
    __tablename__ = 'user'
    __table_args__ = {"schema": "chanak"}

    id = Column(Integer, primary_key=True, nullable=False, server_default=text("nextval('user_id_seq'::regclass)"))
    user_hash = Column(String(100), nullable=False)
    email = Column(String(100), nullable=False)
    name = Column(String(100), nullable=False)
    password = Column(String(200), nullable=False)
    phone = Column(String(20))
    access_level = Column(Integer, nullable=False, server_default=text("0"))
    is_email_verified = Column(Boolean, nullable=False, server_default=text("false"))
    is_active = Column(Boolean, nullable=False, server_default=text("false"))
    last_login = Column(DateTime, nullable=False)
    customer_hash = Column(String(100), nullable=False)
    created_at = Column(DateTime, nullable=False, server_default=text("CURRENT_TIMESTAMP"))
    updated_at = Column(DateTime, nullable=False, server_default=text("CURRENT_TIMESTAMP"))
    is_deleted = Column(Boolean, server_default=text("false"))

class UserAccountMap(Base):
    __tablename__ = 'user_account_map'
    __table_args__ = {"schema": "chanak"}

    id = Column(Integer, primary_key=True, nullable=False, server_default=text("nextval('user_account_map_id_seq'::regclass)"))
    user_hash = Column(String(100), nullable=False)
    account_hash = Column(String(100), nullable=False)
    created_at = Column(DateTime, nullable=False, server_default=text("CURRENT_TIMESTAMP"))
    updated_at = Column(DateTime, nullable=False, server_default=text("CURRENT_TIMESTAMP"))
    is_deleted = Column(Boolean, server_default=text("false"))


class AzAccount(Base):
    __tablename__ = 'az_account'
    __table_args__ = {"schema": "chanak"}

    id = Column(Integer, primary_key=True, nullable=False, server_default=text("nextval('az_account_id_seq'::regclass)"))
    application_id = Column(String(100), nullable=False)
    application_name = Column(String(250), nullable=False)
    domain_id = Column(String(100), nullable=False)
    tenant_id = Column(String(100), nullable=False)
    customer_hash = Column(String(100), nullable=False)
    is_active = Column(Boolean, nullable=False)
    account_hash = Column(String(100))
    created_at = Column(DateTime, nullable=False, server_default=text("CURRENT_TIMESTAMP"))
    updated_at = Column(DateTime, nullable=False, server_default=text("CURRENT_TIMESTAMP"))
    is_deleted = Column(Boolean, server_default=text("false"))
    encrypted_string = Column(String(1000))

class AzAccountSubscriptions(Base):
    __tablename__ = 'az_account_subscriptions'
    __table_args__ = {"schema": "chanak"}

    id = Column(Integer, primary_key=True, nullable=False, server_default=text("nextval('az_account_subscriptions_id_seq'::regclass)"))
    account_hash = Column(String(100), nullable=False)
    subscription_id = Column(String(100), nullable=False)
    subscription_name = Column(String(200))
    subscription_type = Column(String(100))
    offer_code = Column(String(200))
    subscription_hash = Column(String(100))
    created_at = Column(DateTime, nullable=False, server_default=text("CURRENT_TIMESTAMP"))
    updated_at = Column(DateTime, nullable=False, server_default=text("CURRENT_TIMESTAMP"))




class AZChecks(Base):
    __tablename__ = 'az_checks'
    __table_args__ = {"schema": "chanak"}

    id = Column(Integer, primary_key=True, nullable=False, server_default=text("nextval('az_checks_id_seq'::regclass)"))
    check_id = Column(String(100), nullable=False)
    check_name = Column(String(250))
    rule = Column(String(5000))
    service = Column(String(1000), nullable=False)
    severity = Column(String(75), nullable=False)
    is_global = Column(SmallInteger, nullable=False, server_default=text("0"))
    is_active = Column(SmallInteger, nullable=False, server_default=text("1"))
    problem_statement_fail = Column(String(1000))
    problem_statement_pass = Column(String(1000))
    problem_statement_info = Column(String(1000))
    weight = Column(Integer)
    console_remediation_steps = Column(String(5000))
    cli_remediation_steps = Column(String(5000))


class AzExecutionDetails(Base):
    __tablename__ = 'az_execution_details'
    __table_args__ = {"schema": "chanak"}

    id = Column(Integer, primary_key=True, nullable=False, server_default=text("nextval('az_execution_details_id_seq'::regclass)"))
    account_hash = Column(String(100), nullable=False)
    group_hash = Column(String(100))
    subscription_hash = Column(String(100))
    execution_hash = Column(String(100))
    status = Column(SmallInteger, nullable=False)
    failed_checks = Column(Integer, nullable=False, server_default=text("0"))
    completed_checks = Column(Integer, nullable=False, server_default=text("1"))
    created_at = Column(DateTime, nullable=False, server_default=text("CURRENT_TIMESTAMP"))
    updated_at = Column(DateTime, nullable=False, server_default=text("CURRENT_TIMESTAMP"))



class AzAudit(Base):
    __tablename__ = 'az_audit_report'
    __table_args__ = {"schema": "chanak"}

    id = Column(Integer, primary_key=True, nullable=False, server_default=text("nextval('az_audit_report_id_seq'::regclass)"))
    execution_hash = Column(String(100), nullable=False)
    check_id = Column(String(100))
    region = Column(String(100))
    resource_name = Column(String(100))
    resource_id = Column(String(1000))
    problem = Column(String(100))
    subscription_id = Column(String(100))
    subscription_name = Column(String(100))
    value_one = Column(String(100))
    value_two = Column(String(100))
    status = Column(String(45), nullable=False)
    created_at = Column(DateTime, nullable=False, server_default=text("CURRENT_TIMESTAMP"))
