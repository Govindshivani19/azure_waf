# coding: utf-8
from sqlalchemy import Column, DECIMAL, Date, DateTime, ForeignKey, String, TIMESTAMP, Text, text
from sqlalchemy.dialects.mysql import BIGINT, DATETIME, INTEGER, LONGTEXT, TINYINT
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()
metadata = Base.metadata


class Account(Base):
    __tablename__ = 'account'

    id = Column(INTEGER(11), primary_key=True)
    aws_account_id = Column(String(50), nullable=False)
    account_name = Column(String(100), nullable=False)
    account_hash = Column(String(100), nullable=False, unique=True)
    is_active = Column(TINYINT(1), nullable=False)
    account_type_id = Column(ForeignKey('account_type.id'), nullable=False, index=True)
    master_account_hash = Column(String(100), index=True)
    billing_bucket_name = Column(String(500))
    customer_hash = Column(ForeignKey('customer.customer_hash'), nullable=False, index=True)
    created_at = Column(TIMESTAMP, nullable=False, server_default=text("CURRENT_TIMESTAMP"))
    updated_at = Column(TIMESTAMP, nullable=False, server_default=text("CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP"))
    is_role_added = Column(TINYINT(1), nullable=False, server_default=text("'0'"))

    account_type = relationship('AccountType')
    customer = relationship('Customer')


class AccountType(Base):
    __tablename__ = 'account_type'

    id = Column(INTEGER(11), primary_key=True)
    account_type = Column(String(100), nullable=False)


class Customer(Base):
    __tablename__ = 'customer'

    id = Column(INTEGER(11), primary_key=True)
    customer_name = Column(String(100), nullable=False)
    default_timezone = Column(String(10), nullable=False, server_default=text("'+00:00'"))
    customer_hash = Column(String(100), nullable=False, unique=True)
    is_active = Column(TINYINT(1), nullable=False)
    creator_user_hash = Column(ForeignKey('user.user_hash'), index=True)
    created_at = Column(TIMESTAMP, nullable=False, server_default=text("CURRENT_TIMESTAMP"))
    updated_at = Column(TIMESTAMP, nullable=False, server_default=text("CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP"))

    user = relationship('User', primaryjoin='Customer.creator_user_hash == User.user_hash')


class User(Base):
    __tablename__ = 'user'

    id = Column(INTEGER(11), primary_key=True)
    user_hash = Column(String(100), nullable=False, unique=True)
    email = Column(String(100), nullable=False, unique=True)
    name = Column(String(100), nullable=False)
    password = Column(String(200), nullable=False)
    phone = Column(String(20))
    access_level = Column(INTEGER(11), nullable=False, server_default=text("'0'"))
    is_email_verified = Column(TINYINT(1), nullable=False, server_default=text("'0'"))
    is_active = Column(TINYINT(1), nullable=False, server_default=text("'0'"))
    last_login = Column(DateTime, nullable=False, server_default=text("CURRENT_TIMESTAMP"))
    customer_hash = Column(ForeignKey('customer.customer_hash'), nullable=False, index=True)
    created_at = Column(TIMESTAMP, nullable=False, server_default=text("CURRENT_TIMESTAMP"))
    updated_at = Column(TIMESTAMP, nullable=False, server_default=text("CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP"))

    customer = relationship('Customer', primaryjoin='User.customer_hash == Customer.customer_hash')


class UserAccountMap(Base):
    __tablename__ = 'user_account_map'

    id = Column(BIGINT(20), primary_key=True)
    user_hash = Column(ForeignKey('user.user_hash'), nullable=False, index=True)
    account_hash = Column(ForeignKey('account.account_hash'), nullable=False, index=True)
    created_at = Column(TIMESTAMP, nullable=False, server_default=text("CURRENT_TIMESTAMP"))
    updated_at = Column(TIMESTAMP, nullable=False, server_default=text("CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP"))

    account = relationship('Account')
    user = relationship('User')


class AzAccount(Base):
    __tablename__ = 'az_account'

    id = Column(INTEGER(11), primary_key=True)
    application_id = Column(String(100), nullable=False)
    domain_id = Column(String(100), nullable=False)
    tenant_id = Column(String(100), nullable=False)
    az_customer_hash = Column(ForeignKey('customer.customer_hash'), nullable=False, index=True)
    is_active = Column(TINYINT(2), nullable=False)
    az_account_hash = Column(String(100), nullable=False, unique=True)
    created_at = Column(TIMESTAMP, nullable=False, server_default=text("CURRENT_TIMESTAMP"))
    updated_at = Column(TIMESTAMP, nullable=False, server_default=text("CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP"))

    customer = relationship('Customer')


class AzAccountSubscriptions(Base):
    __tablename__ = 'az_account_subscriptions'

    id = Column(INTEGER(11), primary_key=True)
    az_account_hash = Column(ForeignKey('az_account.az_account_hash'), nullable=False)
    subscription_id = Column(String(100), nullable=False)
    subscription_type = Column(String(100))
    offer_code = Column(String(200))
    az_subscription_hash = Column(String(100), nullable=False, unique=True)
    created_at = Column(TIMESTAMP, nullable=False, server_default=text("CURRENT_TIMESTAMP"))
    updated_at = Column(TIMESTAMP, nullable=False, server_default=text("CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP"))

    az_account = relationship(AzAccount)


class AZChecks(Base):
    __tablename__ = 'az_checks'

    id = Column(INTEGER(11), primary_key=True)
    az_check_id = Column(String(100), nullable=False, unique=True)
    az_check_name = Column(String(250))
    az_rule = Column(String(5000))


class AzExecutionDetails(Base):
    __tablename__ = 'az_execution_details'

    id = Column(INTEGER(11), primary_key=True)
    az_account_hash_exe = Column(ForeignKey('az_account.az_account_hash'), nullable=False)
    az_subscription_hash_exe = Column(ForeignKey('az_account_subscriptions.az_subscription_hash'))
    az_execution_hash = Column(String(100), nullable=False, unique=True)
    status = Column(TINYINT(2), nullable=False)
    failed_checks = Column(INTEGER(11), nullable=False, server_default=text("'0'"))
    completed_checks = Column(INTEGER(11), nullable=False, server_default=text("'1'"))
    created_at = Column(TIMESTAMP, nullable=False, server_default=text("CURRENT_TIMESTAMP"))
    updated_at = Column(TIMESTAMP, nullable=False, server_default=text("CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP"))

    az_account = relationship(AzAccount)
    az_account_subscriptions = relationship(AzAccountSubscriptions)


class AzAudit(Base):
    __tablename__ = 'az_audit_report'

    id = Column(INTEGER(11), primary_key=True)
    az_execution_hash = Column(String(100))
    check_id = Column(String(100))
    region = Column(String(2000))
    resource_name = Column(String(2000))
    resource_id = Column(String(2000))
    problem = Column(String(2000))
    subscription_id = Column(String(1000))
    subscription_name = Column(String(1000))
    status = Column(String(45), nullable=False)
    created_at = Column(TIMESTAMP, nullable=False, server_default=text("CURRENT_TIMESTAMP"))
