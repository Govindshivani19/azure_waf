from db_helper import insert_audit_records


def CEN_AZ_2(execution_hash, storage_service):
    try:
        insert_audit_records(execution_hash, storage_service.check_access_to_anonymous_users(),'CEN_AZ_2')
    except Exception as e:
        print(str(e))


def CEN_AZ_4(execution_hash, storage_service):
    try:
        insert_audit_records(execution_hash, storage_service.enable_secure_transfer(),'CEN_AZ_4')
    except Exception as e:
        print(str(e))


def CEN_AZ_5(execution_hash, storage_service):
    try:
        insert_audit_records(execution_hash, storage_service.check_trusted_services_access(),'CEN_AZ_5')
    except Exception as e:
        print(str(e))


def CEN_AZ_8(execution_hash, storage_service):
    try:
        insert_audit_records(execution_hash, storage_service.restrict_default_network_access(),'CEN_AZ_7')
    except Exception as e:
        print(str(e))


def CEN_AZ_9(execution_hash, monitor_service):
    try:
        insert_audit_records(execution_hash, monitor_service.get_log_profiles(),'CEN_AZ_9')
    except Exception as e:
        print(str(e))


def CEN_AZ_10(execution_hash, monitor_service):
    try:
        insert_audit_records(execution_hash, monitor_service.check_public_accessible_log_storage_accounts(),'CEN_AZ_10')
    except Exception as e:
        print(str(e))


def CEN_AZ_11(execution_hash, monitor_service):
    try:
        insert_audit_records(execution_hash, monitor_service.get_log_retention_period(),'CEN_AZ_11')
    except Exception as e:
        print(str(e))


def CEN_AZ_12(execution_hash, monitor_service):
    try:
        insert_audit_records(execution_hash, monitor_service.get_total_region_export_count(),'CEN_AZ_12')
    except Exception as e:
        print(str(e))


def CEN_AZ_13(execution_hash, monitor_service):
    try:
        insert_audit_records(execution_hash, monitor_service.get_log_profile_export_activities(),'CEN_AZ_13')
    except Exception as e:
        print(str(e))


def CEN_AZ_14(execution_hash, monitor_service):
    try:
        insert_audit_records(execution_hash, monitor_service.check_auditevent_enable_for_keyvault(),'CEN_AZ_14')
    except Exception as e:
        print(str(e))


def CEN_AZ_15(execution_hash, monitor_service):
    try:
        insert_audit_records(execution_hash, monitor_service.is_activity_log_storage_encrypted(),'CEN_AZ_15')
    except Exception as e:
        print(str(e))


def CEN_AZ_16(execution_hash, iam_service):
    try:
        insert_audit_records(execution_hash, iam_service.get_custom_roles(),'CEN_AZ_16')
    except Exception as e:
        print(str(e))


def CEN_AZ_20(execution_hash, iam_service):
    try:
        insert_audit_records(execution_hash, iam_service.guest_users(),'CEN_AZ_20')
    except Exception as e:
        print(str(e))


def CEN_AZ_40(execution_hash, security_service):
    try:
        insert_audit_records(execution_hash, security_service.enable_application_whitelisting_monitor(),'CEN_AZ_40')
    except Exception as e:
        print(str(e))


def CEN_AZ_41(execution_hash, security_service):
    try:
        insert_audit_records(execution_hash, security_service.enable_alert_subscription_owners(),'CEN_AZ_41')
    except Exception as e:
        print(str(e))


def CEN_AZ_42(execution_hash, security_service):
    try:
        insert_audit_records(execution_hash, security_service.enable_auto_provision_montioring_agent(),'CEN_AZ_42')
    except Exception as e:
        print(str(e))


def CEN_AZ_43(execution_hash, security_service):
    try:
        insert_audit_records(execution_hash, security_service.enable_disk_encryption_monitor(),'CEN_AZ_43')
    except Exception as e:
        print(str(e))


def CEN_AZ_44(execution_hash, security_service):
    try:
        insert_audit_records(execution_hash, security_service.enable_endpoint_protection_monitor(),'CEN_AZ_44')
    except Exception as e:
        print(str(e))


def CEN_AZ_45(execution_hash, security_service):
    try:
        insert_audit_records(execution_hash, security_service.enable_alert_serverity_notifications(),'CEN_AZ_45')
    except Exception as e:
        print(str(e))


def CEN_AZ_46(execution_hash, security_service):
    try:
        insert_audit_records(execution_hash, security_service.enable_jit_network_access_monitor(),'CEN_AZ_46')
    except Exception as e:
        print(str(e))


def CEN_AZ_47(execution_hash, security_service):
    try:
        insert_audit_records(execution_hash, security_service.enable_os_vulnerability_monitor(),'CEN_AZ_47')
    except Exception as e:
        print(str(e))


def CEN_AZ_48(execution_hash, security_service):
    try:
        insert_audit_records(execution_hash, security_service.enable_security_group_monitor(),'CEN_AZ_48')
    except Exception as e:
        print(str(e))


def CEN_AZ_49(execution_hash, security_service):
    try:
        insert_audit_records(execution_hash, security_service.enable_ngfw_monitor(),'CEN_AZ_49')
    except Exception as e:
        print(str(e))


def CEN_AZ_50(execution_hash, security_service):
    try:
        insert_audit_records(execution_hash, security_service.enable_sql_audit_monitor(),'CEN_AZ_50')
    except Exception as e:
        print(str(e))


def CEN_AZ_51(execution_hash, security_service):
    try:
        insert_audit_records(execution_hash, security_service.enable_sql_encryption_monitor(),'CEN_AZ_51')
    except Exception as e:
        print(str(e))


def CEN_AZ_52(execution_hash, security_service):
    try:
        insert_audit_records(execution_hash, security_service.enable_standard_pricing(),'CEN_AZ_52')
    except Exception as e:
        print(str(e))


def CEN_AZ_53(execution_hash, security_service):
    try:
        insert_audit_records(execution_hash, security_service.enable_storage_encryption_monitor(),'CEN_AZ_53')
    except Exception as e:
        print(str(e))


def CEN_AZ_54(execution_hash, security_service):
    try:
        insert_audit_records(execution_hash, security_service.enable_system_updates_monitor(),'CEN_AZ_54')
    except Exception as e:
        print(str(e))


def CEN_AZ_55(execution_hash, security_service):
    try:
        insert_audit_records(execution_hash, security_service.enable_vulnerability_assesment_monitor(),'CEN_AZ_55')
    except Exception as e:
        print(str(e))


def CEN_AZ_56(execution_hash, security_service):
    try:
        insert_audit_records(execution_hash, security_service.enable_web_app_firewall_monitor(),'CEN_AZ_56')
    except Exception as e:
        print(str(e))


def CEN_AZ_57(execution_hash, security_service):
    try:
        insert_audit_records(execution_hash, security_service.check_security_email(),'CEN_AZ_57')
    except Exception as e:
        print(str(e))


def CEN_AZ_58(execution_hash, security_service):
    try:
        insert_audit_records(execution_hash, security_service.check_security_phone_number(),'CEN_AZ_58')
    except Exception as e:
        print(str(e))


def CEN_AZ_59(execution_hash, db_service):
    try:
        insert_audit_records(execution_hash, db_service.psql_log_retension_period(),'CEN_AZ_59')
    except Exception as e:
        print(str(e))


def CEN_AZ_60(execution_hash, db_service):
    try:
        insert_audit_records(execution_hash, db_service.sql_audit_retension_priod(),'CEN_AZ_60')
    except Exception as e:
        print(str(e))


def CEN_AZ_61(execution_hash, db_service):
    try:
        insert_audit_records(execution_hash, db_service.sql_enable_audit_action_group(),'CEN_AZ_61')
    except Exception as e:
        print(str(e))


def CEN_AZ_62(execution_hash, db_service):
    try:
        insert_audit_records(execution_hash, db_service.enable_psql_connection_throttling(),'CEN_AZ_62')
    except Exception as e:
        print(str(e))


def CEN_AZ_63(execution_hash, db_service):
    try:
        insert_audit_records(execution_hash, db_service.enable_psql_log_checkpoints(),'CEN_AZ_63')
    except Exception as e:
        print(str(e))


def CEN_AZ_64(execution_hash, db_service):
    try:
        insert_audit_records(execution_hash, db_service.enable_psql_log_connections(),'CEN_AZ_64')
    except Exception as e:
        print(str(e))


def CEN_AZ_65(execution_hash, db_service):
    try:
        insert_audit_records(execution_hash, db_service.enable_psql_log_disconnections(),'CEN_AZ_65')
    except Exception as e:
        print(str(e))


def CEN_AZ_66(execution_hash, db_service):
    try:
        insert_audit_records(execution_hash, db_service.enable_psql_log_duration(),'CEN_AZ_66')
    except Exception as e:
        print(str(e))


def CEN_AZ_68(execution_hash, db_service):
    try:
        insert_audit_records(execution_hash, db_service.enable_sql_threat_detection(),'CEN_AZ_68')
    except Exception as e:
        print(str(e))


def CEN_AZ_69(execution_hash, db_service):
    try:
        insert_audit_records(execution_hash, db_service.sql_enable_auditing(),'CEN_AZ_69')
    except Exception as e:
        print(str(e))


def CEN_AZ_70(execution_hash, db_service):
    try:
        insert_audit_records(execution_hash, db_service.enable_sql_threat_email_notification_admins(),'CEN_AZ_70')
    except Exception as e:
        print(str(e))


def CEN_AZ_71(execution_hash, db_service):
    try:
        insert_audit_records(execution_hash, db_service.enable_sql_threat_email_notification(),'CEN_AZ_71')
    except Exception as e:
        print(str(e))


def CEN_AZ_72(execution_hash, db_service):
    try:
        insert_audit_records(execution_hash, db_service.mysql_encryption(),'CEN_AZ_72')
    except Exception as e:
        print(str(e))


def CEN_AZ_73(execution_hash, db_service):
    try:
        insert_audit_records(execution_hash, db_service.enable_psql_ssl_enforcement(),'CEN_AZ_73')
    except Exception as e:
        print(str(e))


def CEN_AZ_77(execution_hash, vm_service):
    try:
        insert_audit_records(execution_hash, vm_service.unused_virtual_machines(), 'CEN_AZ_77')
    except Exception as e:
        print(str(e))


def CEN_AZ_78(execution_hash, vm_service):
    try:
        insert_audit_records(execution_hash, vm_service.unused_volumes(), 'CEN_AZ_78')
    except Exception as e:
        print(str(e))


def CEN_AZ_79(execution_hash, vm_service):
    try:
        insert_audit_records(execution_hash, vm_service.vm_with_no_managed_disks(), 'CEN_AZ_79')
    except Exception as e:
        print(str(e))


def CEN_AZ_80(execution_hash, az_service):
    try:
        insert_audit_records(execution_hash, az_service.redis_secure_connection(), 'CEN_AZ_80')
    except Exception as e:
        print(str(e))


def execute_storage_checks(execution_hash, storage_service):
    CEN_AZ_2(execution_hash, storage_service)
    CEN_AZ_4(execution_hash, storage_service)
    CEN_AZ_5(execution_hash, storage_service)
    CEN_AZ_8(execution_hash, storage_service)


def execute_log_monitor_checks(execution_hash, monitor_service):
    CEN_AZ_9(execution_hash, monitor_service)
    CEN_AZ_10(execution_hash, monitor_service)
    CEN_AZ_11(execution_hash, monitor_service)
    CEN_AZ_12(execution_hash, monitor_service)
    CEN_AZ_13(execution_hash, monitor_service)
    CEN_AZ_14(execution_hash, monitor_service)
    CEN_AZ_15(execution_hash, monitor_service)


def execute_iam_checks(execution_hash, iam_service):
    CEN_AZ_16(execution_hash, iam_service)
    CEN_AZ_20(execution_hash, iam_service)


def execute_security_centre_checks(execution_hash, security_service):
    CEN_AZ_40(execution_hash, security_service)
    CEN_AZ_41(execution_hash, security_service)
    CEN_AZ_42(execution_hash, security_service)
    CEN_AZ_43(execution_hash, security_service)
    CEN_AZ_44(execution_hash, security_service)
    CEN_AZ_45(execution_hash, security_service)
    CEN_AZ_46(execution_hash, security_service)
    CEN_AZ_47(execution_hash, security_service)
    CEN_AZ_48(execution_hash, security_service)
    CEN_AZ_49(execution_hash, security_service)
    CEN_AZ_50(execution_hash, security_service)
    CEN_AZ_51(execution_hash, security_service)
    CEN_AZ_52(execution_hash, security_service)
    CEN_AZ_53(execution_hash, security_service)
    CEN_AZ_54(execution_hash, security_service)
    CEN_AZ_55(execution_hash, security_service)
    CEN_AZ_56(execution_hash, security_service)
    CEN_AZ_57(execution_hash, security_service)
    CEN_AZ_58(execution_hash, security_service)


def execute_database_checks(execution_hash, db_service):
    CEN_AZ_59(execution_hash, db_service)
    CEN_AZ_60(execution_hash, db_service)
    CEN_AZ_61(execution_hash, db_service)
    CEN_AZ_62(execution_hash, db_service)
    CEN_AZ_63(execution_hash, db_service)
    CEN_AZ_64(execution_hash, db_service)
    CEN_AZ_65(execution_hash, db_service)
    CEN_AZ_66(execution_hash, db_service)
    CEN_AZ_68(execution_hash, db_service)
    CEN_AZ_69(execution_hash, db_service)
    CEN_AZ_70(execution_hash, db_service)
    CEN_AZ_71(execution_hash, db_service)
    CEN_AZ_72(execution_hash, db_service)
    CEN_AZ_73(execution_hash, db_service)


def execute_vm_checks(execution_hash, vm_service):
    CEN_AZ_77(execution_hash, vm_service)
    CEN_AZ_79(execution_hash, vm_service)


def execute_disk_checks(execution_hash, vm_service):
    CEN_AZ_78(execution_hash, vm_service)


def execute_az_services_checks(execution_hash, az_service):
    CEN_AZ_80(execution_hash, az_service)