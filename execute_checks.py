from db_helper import insert_audit_records
import logging as logger

def CEN_AZ_2(task_id, storage_service):
    try:
        insert_audit_records(task_id, storage_service.check_access_to_anonymous_users(),'CEN_AZ_2')
    except Exception as e:
        logger.error(e);


def CEN_AZ_4(task_id, storage_service):
    try:
        insert_audit_records(task_id, storage_service.enable_secure_transfer(),'CEN_AZ_4')
    except Exception as e:
        logger.error(e);


def CEN_AZ_5(task_id, storage_service):
    try:
        insert_audit_records(task_id, storage_service.check_trusted_services_access(),'CEN_AZ_5')
    except Exception as e:
        logger.error(e);


def CEN_AZ_7(task_id, storage_service):
    try:
        insert_audit_records(task_id, storage_service.regenerate_storage_keys(),'CEN_AZ_7')
    except Exception as e:
        logger.error(e);


def CEN_AZ_8(task_id, storage_service):
    try:
        insert_audit_records(task_id, storage_service.restrict_default_network_access(),'CEN_AZ_8')
    except Exception as e:
        logger.error(e);


def CEN_AZ_9(task_id, monitor_service):
    try:
        insert_audit_records(task_id, monitor_service.get_log_profiles(),'CEN_AZ_9')
    except Exception as e:
        logger.error(e);


def CEN_AZ_10(task_id, monitor_service):
    try:
        insert_audit_records(task_id, monitor_service.check_public_accessible_log_storage_accounts(),'CEN_AZ_10')
    except Exception as e:
        logger.error(e);


def CEN_AZ_11(task_id, monitor_service):
    try:
        insert_audit_records(task_id, monitor_service.get_log_retention_period(),'CEN_AZ_11')
    except Exception as e:
        logger.error(e);


def CEN_AZ_12(task_id, monitor_service):
    try:
        insert_audit_records(task_id, monitor_service.get_total_region_export_count(),'CEN_AZ_12')
    except Exception as e:
        logger.error(e);


def CEN_AZ_13(task_id, monitor_service):
    try:
        insert_audit_records(task_id, monitor_service.get_log_profile_export_activities(),'CEN_AZ_13')
    except Exception as e:
        logger.error(e);


def CEN_AZ_14(task_id, monitor_service):
    try:
        insert_audit_records(task_id, monitor_service.check_auditevent_enable_for_keyvault(),'CEN_AZ_14')
    except Exception as e:
        logger.error(e);


def CEN_AZ_15(task_id, monitor_service):
    try:
        insert_audit_records(task_id, monitor_service.is_activity_log_storage_encrypted(),'CEN_AZ_15')
    except Exception as e:
        logger.error(e);


def CEN_AZ_16(task_id, iam_service):
    try:
        insert_audit_records(task_id, iam_service.get_custom_roles(),'CEN_AZ_16')
    except Exception as e:
        logger.error(e);


def CEN_AZ_20(task_id, iam_service):
    try:
        insert_audit_records(task_id, iam_service.guest_users(),'CEN_AZ_20')
    except Exception as e:
        logger.error(e);


def CEN_AZ_40(task_id, security_service):
    try:
        insert_audit_records(task_id, security_service.enable_application_whitelisting_monitor(),'CEN_AZ_40')
    except Exception as e:
        logger.error(e);


def CEN_AZ_41(task_id, security_service):
    try:
        insert_audit_records(task_id, security_service.enable_alert_subscription_owners(),'CEN_AZ_41')
    except Exception as e:
        logger.error(e);


def CEN_AZ_42(task_id, security_service):
    try:
        insert_audit_records(task_id, security_service.enable_auto_provision_montioring_agent(),'CEN_AZ_42')
    except Exception as e:
        logger.error(e);


def CEN_AZ_43(task_id, security_service):
    try:
        insert_audit_records(task_id, security_service.enable_disk_encryption_monitor(),'CEN_AZ_43')
    except Exception as e:
        logger.error(e);


def CEN_AZ_44(task_id, security_service):
    try:
        insert_audit_records(task_id, security_service.enable_endpoint_protection_monitor(),'CEN_AZ_44')
    except Exception as e:
        logger.error(e);


def CEN_AZ_45(task_id, security_service):
    try:
        insert_audit_records(task_id, security_service.enable_alert_serverity_notifications(),'CEN_AZ_45')
    except Exception as e:
        logger.error(e);


def CEN_AZ_46(task_id, security_service):
    try:
        insert_audit_records(task_id, security_service.enable_jit_network_access_monitor(),'CEN_AZ_46')
    except Exception as e:
        logger.error(e);


def CEN_AZ_47(task_id, security_service):
    try:
        insert_audit_records(task_id, security_service.enable_os_vulnerability_monitor(),'CEN_AZ_47')
    except Exception as e:
        logger.error(e);


def CEN_AZ_48(task_id, security_service):
    try:
        insert_audit_records(task_id, security_service.enable_security_group_monitor(),'CEN_AZ_48')
    except Exception as e:
        logger.error(e);


def CEN_AZ_49(task_id, security_service):
    try:
        insert_audit_records(task_id, security_service.enable_ngfw_monitor(),'CEN_AZ_49')
    except Exception as e:
        logger.error(e);


def CEN_AZ_50(task_id, security_service):
    try:
        insert_audit_records(task_id, security_service.enable_sql_audit_monitor(),'CEN_AZ_50')
    except Exception as e:
        logger.error(e);


def CEN_AZ_51(task_id, security_service):
    try:
        insert_audit_records(task_id, security_service.enable_sql_encryption_monitor(),'CEN_AZ_51')
    except Exception as e:
        logger.error(e);


def CEN_AZ_52(task_id, security_service):
    try:
        insert_audit_records(task_id, security_service.enable_standard_pricing(),'CEN_AZ_52')
    except Exception as e:
        logger.error(e);


def CEN_AZ_53(task_id, security_service):
    try:
        insert_audit_records(task_id, security_service.enable_storage_encryption_monitor(),'CEN_AZ_53')
    except Exception as e:
        logger.error(e);


def CEN_AZ_54(task_id, security_service):
    try:
        insert_audit_records(task_id, security_service.enable_system_updates_monitor(),'CEN_AZ_54')
    except Exception as e:
        logger.error(e);


def CEN_AZ_55(task_id, security_service):
    try:
        insert_audit_records(task_id, security_service.enable_vulnerability_assesment_monitor(),'CEN_AZ_55')
    except Exception as e:
        logger.error(e);


def CEN_AZ_56(task_id, security_service):
    try:
        insert_audit_records(task_id, security_service.enable_web_app_firewall_monitor(),'CEN_AZ_56')
    except Exception as e:
        logger.error(e);


def CEN_AZ_57(task_id, security_service):
    try:
        insert_audit_records(task_id, security_service.check_security_email(),'CEN_AZ_57')
    except Exception as e:
        logger.error(e);


def CEN_AZ_58(task_id, security_service):
    try:
        insert_audit_records(task_id, security_service.check_security_phone_number(),'CEN_AZ_58')
    except Exception as e:
        logger.error(e);


def CEN_AZ_59(task_id, db_service):
    try:
        insert_audit_records(task_id, db_service.psql_log_retension_period(),'CEN_AZ_59')
    except Exception as e:
        logger.error(e);


def CEN_AZ_60(task_id, db_service):
    try:
        insert_audit_records(task_id, db_service.sql_audit_retension_priod(),'CEN_AZ_60')
    except Exception as e:
        logger.error(e);


def CEN_AZ_61(task_id, db_service):
    try:
        insert_audit_records(task_id, db_service.sql_enable_audit_action_group(),'CEN_AZ_61')
    except Exception as e:
        logger.error(e);


def CEN_AZ_62(task_id, db_service):
    try:
        insert_audit_records(task_id, db_service.enable_psql_connection_throttling(),'CEN_AZ_62')
    except Exception as e:
        logger.error(e);


def CEN_AZ_63(task_id, db_service):
    try:
        insert_audit_records(task_id, db_service.enable_psql_log_checkpoints(),'CEN_AZ_63')
    except Exception as e:
        logger.error(e);


def CEN_AZ_64(task_id, db_service):
    try:
        insert_audit_records(task_id, db_service.enable_psql_log_connections(),'CEN_AZ_64')
    except Exception as e:
        logger.error(e);


def CEN_AZ_65(task_id, db_service):
    try:
        insert_audit_records(task_id, db_service.enable_psql_log_disconnections(),'CEN_AZ_65')
    except Exception as e:
        logger.error(e);


def CEN_AZ_66(task_id, db_service):
    try:
        insert_audit_records(task_id, db_service.enable_psql_log_duration(),'CEN_AZ_66')
    except Exception as e:
        logger.error(e);


def CEN_AZ_68(task_id, db_service):
    try:
        insert_audit_records(task_id, db_service.enable_sql_threat_detection(),'CEN_AZ_68')
    except Exception as e:
        logger.error(e);


def CEN_AZ_69(task_id, db_service):
    try:
        insert_audit_records(task_id, db_service.sql_enable_auditing(),'CEN_AZ_69')
    except Exception as e:
        logger.error(e);


def CEN_AZ_70(task_id, db_service):
    try:
        insert_audit_records(task_id, db_service.enable_sql_threat_email_notification_admins(),'CEN_AZ_70')
    except Exception as e:
        logger.error(e);


def CEN_AZ_71(task_id, db_service):
    try:
        insert_audit_records(task_id, db_service.enable_sql_threat_email_notification(),'CEN_AZ_71')
    except Exception as e:
        logger.error(e);


def CEN_AZ_72(task_id, db_service):
    try:
        insert_audit_records(task_id, db_service.mysql_encryption(),'CEN_AZ_72')
    except Exception as e:
        logger.error(e);


def CEN_AZ_73(task_id, db_service):
    try:
        insert_audit_records(task_id, db_service.enable_psql_ssl_enforcement(),'CEN_AZ_73')
    except Exception as e:
        logger.error(e);


def CEN_AZ_76(task_id, db_service):
    try:
        insert_audit_records(task_id,
                             db_service.sql_server_tde_byok(),
                             "CEN_AZ_76"
                             )
    except Exception as e:
        logger.error(e);


def CEN_AZ_77(task_id, vm_service):
    try:
        insert_audit_records(task_id, vm_service.unused_virtual_machines(), 'CEN_AZ_77')
    except Exception as e:
        logger.error(e);


def CEN_AZ_78(task_id, vm_service):
    try:
        insert_audit_records(task_id, vm_service.unused_volumes(), 'CEN_AZ_78')
    except Exception as e:
        logger.error(e);


def CEN_AZ_79(task_id, vm_service):
    try:
        insert_audit_records(task_id, vm_service.vm_with_no_managed_disks(), 'CEN_AZ_79')
    except Exception as e:
        logger.error(e);


def CEN_AZ_80(task_id, az_service):
    try:
        insert_audit_records(task_id, az_service.redis_secure_connection(), 'CEN_AZ_80')
    except Exception as e:
        logger.error(e);


def CEN_AZ_81(task_id, vm_service):
    try:
        insert_audit_records(task_id, vm_service.linux_vm_security_groups(), 'CEN_AZ_81')
    except Exception as e:
        logger.error(e);


def CEN_AZ_82(task_id, vm_service):
    try:
        insert_audit_records(task_id, vm_service.encrypt_unattached_disks(), 'CEN_AZ_82')
    except Exception as e:
        logger.error(e);


def CEN_AZ_83(task_id, vm_service):
    try:
        insert_audit_records(task_id, vm_service.vm_disks_without_encryption(), 'CEN_AZ_83')
    except Exception as e:
        logger.error(e);


def CEN_AZ_84(task_id, vm_service):
    try:
        insert_audit_records(task_id, vm_service.check_tagging(), 'CEN_AZ_84')
    except Exception as e:
        logger.error(e);


def CEN_AZ_85(task_id, vm_service):
    try:
        insert_audit_records(task_id, vm_service.check_unused_public_ips(), 'CEN_AZ_85')
    except Exception as e:
        logger.error(e);


def CEN_AZ_86(task_id, vm_service):
    try:
        insert_audit_records(task_id, vm_service.check_vm_backup_enabled(), 'CEN_AZ_86')
    except Exception as e:
        logger.error(e);


def CEN_AZ_87(task_id, vm_service):
    try:
        insert_audit_records(task_id, vm_service.check_vm_disaster_recovery(), 'CEN_AZ_87')
    except Exception as e:

        logger.error(e);


def CEN_AZ_88(task_id, vm_service):
    try:
        insert_audit_records(task_id, vm_service.check_time_zone(), 'CEN_AZ_88')
    except Exception as e:
        logger.error(e);


def CEN_AZ_89(task_id, vm_service):
    try:
        insert_audit_records(task_id, vm_service.check_windows_vm_audit_policy(), 'CEN_AZ_89')
    except Exception as e:
        logger.error(e);


def CEN_AZ_90(task_id, az_service):
    try:
        insert_audit_records(task_id, az_service.get_certificate_expiry(), 'CEN_AZ_90')
    except Exception as e:
        logger.error(e);


def CEN_AZ_91(task_id, az_service):
    try:
        insert_audit_records(task_id, az_service.get_RSA_key_size(), 'CEN_AZ_91')
    except Exception as e:
        logger.error(e);


def CEN_AZ_92(task_id, az_service):
    try:
        insert_audit_records(task_id, az_service.get_recoverable_objects(), 'CEN_AZ_92')
    except Exception as e:
        logger.error(e);


def CEN_AZ_93(task_id, az_service):
    try:
        insert_audit_records(task_id, az_service.check_event_hub_enable_for_keyvault(), 'CEN_AZ_93')
    except Exception as e:
        logger.error(e);


def CEN_AZ_94(task_id, az_service):
    try:
        insert_audit_records(task_id, az_service.get_validity_period(), 'CEN_AZ_94')
    except Exception as e:
        logger.error(e);


def CEN_AZ_95(task_id, az_service):
    try:
        insert_audit_records(task_id, az_service.get_certificate_key_types(), 'CEN_AZ_95')
    except Exception as e:
        logger.error(e);


def CEN_AZ_96(task_id, az_service):
    try:
        insert_audit_records(task_id, az_service.get_lifetime_action_triggers(), 'CEN_AZ_96')
    except Exception as e:
        logger.error(e);


def CEN_AZ_97(task_id, az_service):
    try:
        insert_audit_records(task_id, az_service.get_issuer(), 'CEN_AZ_97')
    except Exception as e:
        logger.error(e);


def CEN_AZ_98(task_id, az_service):
    try:
        insert_audit_records(task_id, az_service.get_curve_name(), 'CEN_AZ_98')
    except Exception as e:
        logger.error(e);


def CEN_AZ_100(task_id, vm_service):
    try:
        insert_audit_records(task_id, vm_service.check_windows_service_status(), 'CEN_AZ_100')
    except Exception as e:
        logger.error(e);


def CEN_AZ_101(task_id, vm_service):
    try:
        insert_audit_records(task_id, vm_service.check_windows_remote_connection(), 'CEN_AZ_101')
    except Exception as e:
        logger.error(e);


def CEN_AZ_102(task_id, vm_service):
    try:
        insert_audit_records(task_id, vm_service.check_windows_installed_powershell(), 'CEN_AZ_102')
    except Exception as e:
        logger.error(e);


def CEN_AZ_103(task_id, vm_service):
    try:
        insert_audit_records(task_id, vm_service.check_windows_vm_audit_security_policy(), 'CEN_AZ_103')
    except Exception as e:
        logger.error(e);


def CEN_AZ_104(task_id, vm_service):
    try:
        insert_audit_records(task_id, vm_service.check_windows_vm_audit_policy(), 'CEN_AZ_104')
    except Exception as e:
        logger.error(e);


def CEN_AZ_105(task_id, vm_service):
    try:
        insert_audit_records(task_id, vm_service.check_windows_vm_whitelisted_application(), 'CEN_AZ_105')
    except Exception as e:
        logger.error(e);


def CEN_AZ_106(task_id, vm_service):
    try:
        insert_audit_records(task_id, vm_service.check_windows_vm_audit_object_access_policy(), 'CEN_AZ_106')
    except Exception as e:
        logger.error(e);


def CEN_AZ_107(task_id, vm_service):
    try:
        insert_audit_records(task_id, vm_service.check_windows_vm_audit_security_system_objects(), 'CEN_AZ_107')
    except Exception as e:
        logger.error(e);


def CEN_AZ_108(task_id, vm_service):
    try:
        insert_audit_records(task_id, vm_service.check_windows_vm_dsc_configuration(), 'CEN_AZ_108')
    except Exception as e:
        logger.error(e);


def CEN_AZ_109(task_id, vm_service):
    try:
        insert_audit_records(task_id, vm_service.check_windows_vm_security_setting_audit(), 'CEN_AZ_109')
    except Exception as e:
        logger.error(e);


def CEN_AZ_110(task_id, vm_service):
    try:
        insert_audit_records(task_id, vm_service.check_windows_vm_components(), 'CEN_AZ_110')
    except Exception as e:
        logger.error(e);


def CEN_AZ_111(task_id, vm_service):
    try:
        insert_audit_records(task_id, vm_service.check_windows_vm_logoff_audit(), 'CEN_AZ_111')
    except Exception as e:
        logger.error(e);


def CEN_AZ_112(task_id, vm_service):
    try:
        insert_audit_records(task_id, vm_service.check_windows_vm_audit_recovery_security(), 'CEN_AZ_112')
    except Exception as e:
        logger.error(e);


def CEN_AZ_113(task_id, vm_service):
    try:
        insert_audit_records(task_id, vm_service.check_windows_vm_exclude_admin_members(), 'CEN_AZ_113')
    except Exception as e:
        logger.error(e);


def CEN_AZ_114(task_id, vm_service):
    try:
        insert_audit_records(task_id, vm_service.check_windows_vm_password_history(), 'CEN_AZ_114')
    except Exception as e:
        logger.error(e);


def CEN_AZ_115(task_id, vm_service):
    try:
        insert_audit_records(task_id, vm_service.check_windows_vm_password_complexity(), 'CEN_AZ_115')
    except Exception as e:
        logger.error(e);


def CEN_AZ_116(task_id, vm_service):
    try:
        insert_audit_records(task_id, vm_service.check_windows_vm_powershell_execution_policy(), 'CEN_AZ_116')
    except Exception as e:
        logger.error(e);


def CEN_AZ_117(task_id, vm_service):
    try:
        insert_audit_records(task_id, vm_service.windows_vm_security_groups(), 'CEN_AZ_117')
    except Exception as e:
        logger.error(e);


def CEN_AZ_118(task_id, vm_service):
    try:
        insert_audit_records(task_id, vm_service.linux_vm_without_password(), 'CEN_AZ_118')
    except Exception as e:
        logger.error(e);


def CEN_AZ_119(task_id, vm_service):
    try:
        insert_audit_records(task_id, vm_service.linux_vm_specific_app_installation(), 'CEN_AZ_119')
    except Exception as e:
        logger.error(e);


def CEN_AZ_120(task_id, automation_service):
    try:
        insert_audit_records(task_id, automation_service.check_variable_encryption(), 'CEN_AZ_120')
    except Exception as e:
        logger.error(e);


def CEN_AZ_121(task_id, vm_service):
    try:
        insert_audit_records(task_id, vm_service.classic_vms(), 'CEN_AZ_121')
    except Exception as e:
        logger.error(e);


def CEN_AZ_122(task_id, vm_service):
    try:
        insert_audit_records(task_id, vm_service.automatic_os_patching(), 'CEN_AZ_122')
    except Exception as e:
        logger.error(e);


def CEN_AZ_123(task_id, vm_service):
    try:
        insert_audit_records(task_id, vm_service.vm_scale_set_diagnostic_logs(), 'CEN_AZ_123')
    except Exception as e:
        logger.error(e);


def CEN_AZ_124(task_id, vm_service):
    try:
        insert_audit_records(task_id, vm_service.windows_antimalware_software(), 'CEN_AZ_124')
    except Exception as e:
        logger.error(e);


def CEN_AZ_125(task_id, vm_service):
    try:
        insert_audit_records(task_id, vm_service.windows_antimalware_autoupdate(), 'CEN_AZ_125')
    except Exception as e:
        logger.error(e);


def CEN_AZ_126(task_id, app_service):
    try:
        insert_audit_records(task_id, app_service.cors_function_app(), 'CEN_AZ_126')
    except Exception as e:
        logger.error(e);


def CEN_AZ_127(task_id, app_service):
    try:
        insert_audit_records(task_id, app_service.cors_function_api_app(), 'CEN_AZ_127')
    except Exception as e:
        logger.error(e);


def CEN_AZ_128(task_id, app_service):
    try:
        insert_audit_records(task_id, app_service.cors_function_web_app(), 'CEN_AZ_128')
    except Exception as e:
        logger.error(e);


def CEN_AZ_129(task_id, app_service):
    try:
        insert_audit_records(task_id, app_service.min_tls_version_function_app(), 'CEN_AZ_129')
    except Exception as e:
        logger.error(e);


def CEN_AZ_130(task_id, app_service):
    try:
        insert_audit_records(task_id, app_service.min_tls_version_web_app(), 'CEN_AZ_130')
    except Exception as e:
        logger.error(e);


def CEN_AZ_131(task_id, app_service):
    try:
        insert_audit_records(task_id, app_service.min_tls_version_api_app(), 'CEN_AZ_131')
    except Exception as e:
        logger.error(e);


def CEN_AZ_132(task_id, app_service):
    try:
        insert_audit_records(task_id, app_service.enable_client_certificates_apiapp(), 'CEN_AZ_132')
    except Exception as e:
        logger.error(e);


def CEN_AZ_133(task_id, app_service):
    try:
        insert_audit_records(task_id, app_service.enable_client_certificates_webapp(), 'CEN_AZ_133')
    except Exception as e:
        logger.error(e);


def CEN_AZ_134(task_id, app_service):
    try:
        insert_audit_records(task_id, app_service.enable_client_certificates_functionapp(), 'CEN_AZ_134')
    except Exception as e:
        logger.error(e);


def CEN_AZ_135(task_id, app_service):
    try:
        insert_audit_records(task_id, app_service.managed_identity_function_app(), 'CEN_AZ_135')
    except Exception as e:
        logger.error(e);


def CEN_AZ_136(task_id, app_service):
    try:
        insert_audit_records(task_id, app_service.managed_identity_web_app(), 'CEN_AZ_136')
    except Exception as e:
        logger.error(e);


def CEN_AZ_137(task_id, app_service):
    try:
        insert_audit_records(task_id, app_service.managed_identity_api_app(), 'CEN_AZ_137')
    except Exception as e:
        logger.error(e);


def CEN_AZ_138(task_id, app_service):
    try:
        insert_audit_records(task_id, app_service.remote_debugging_function_app(), 'CEN_AZ_138')
    except Exception as e:
        logger.error(e);


def CEN_AZ_139(task_id, app_service):
    try:
        insert_audit_records(task_id, app_service.remote_debugging_web_app(), 'CEN_AZ_139')
    except Exception as e:
        logger.error(e);


def CEN_AZ_140(task_id, app_service):
    try:
        insert_audit_records(task_id, app_service.remote_debugging_api_app(), 'CEN_AZ_140')
    except Exception as e:
        logger.error(e);


def CEN_AZ_141(task_id, app_service):
    try:
        insert_audit_records(task_id, app_service.check_dotnet_version_function_app(), 'CEN_AZ_141')
    except Exception as e:
        logger.error(e);


def CEN_AZ_142(task_id, app_service):
    try:
        insert_audit_records(task_id, app_service.check_dotnet_version_web_app(), 'CEN_AZ_142')
    except Exception as e:
        logger.error(e);


def CEN_AZ_143(task_id, app_service):
    try:
        insert_audit_records(task_id, app_service.check_dotnet_version_api_app(), 'CEN_AZ_143')
    except Exception as e:
        logger.error(e);


def CEN_AZ_144(task_id, app_service):
    try:
        insert_audit_records(task_id, app_service.enable_ftp_function_app(), 'CEN_AZ_144')
    except Exception as e:
        logger.error(e);


def CEN_AZ_145(task_id, app_service):
    try:
        insert_audit_records(task_id, app_service.enable_ftp_web_app(), 'CEN_AZ_145')
    except Exception as e:
        logger.error(e);


def CEN_AZ_146(task_id, app_service):
    try:
        insert_audit_records(task_id, app_service.enable_ftp_api_app(), 'CEN_AZ_146')
    except Exception as e:
        logger.error(e);


def CEN_AZ_147(task_id, app_service):
    try:
        insert_audit_records(task_id, app_service.enable_authentication_web_app(), 'CEN_AZ_147')
    except Exception as e:
        logger.error(e);


def CEN_AZ_148(task_id, app_service):
    try:
        insert_audit_records(task_id, app_service.enable_authentication_api_app(), 'CEN_AZ_148')
    except Exception as e:
        logger.error(e);


def CEN_AZ_149(task_id, app_service):
    try:
        insert_audit_records(task_id, app_service.enable_authentication_function_app(), 'CEN_AZ_149')
    except Exception as e:
        logger.error(e);


def CEN_AZ_150(task_id, app_service):
    try:
        insert_audit_records(task_id, app_service.enable_latest_httpversion_api_app(), 'CEN_AZ_150')
    except Exception as e:
        logger.error(e);


def CEN_AZ_151(task_id, app_service):
    try:
        insert_audit_records(task_id, app_service.enable_latest_httpversion_function_app(), 'CEN_AZ_151')
    except Exception as e:
        logger.error(e);


def CEN_AZ_152(task_id, app_service):
    try:
        insert_audit_records(task_id, app_service.enable_latest_httpversion_web_app(), 'CEN_AZ_152')
    except Exception as e:
        logger.error(e);


def CEN_AZ_153(task_id, app_service):
    try:
        insert_audit_records(task_id, app_service.remote_debugging_api_app(), 'CEN_AZ_153')
    except Exception as e:
        logger.error(e);


def CEN_AZ_154(task_id, app_service):
    try:
        insert_audit_records(task_id, app_service.remote_debugging_function_app(), 'CEN_AZ_154')
    except Exception as e:
        logger.error(e);


def CEN_AZ_155(task_id, app_service):
    try:
        insert_audit_records(task_id, app_service.remote_debugging_web_app(), 'CEN_AZ_155')
    except Exception as e:
        logger.error(e);


def CEN_AZ_156(task_id, app_service):
    try:
        insert_audit_records(task_id, app_service.enable_https_access_apiapp(), 'CEN_AZ_156')
    except Exception as e:
        logger.error(e);


def CEN_AZ_157(task_id, app_service):
    try:
        insert_audit_records(task_id, app_service.enable_https_access_functionapp(), 'CEN_AZ_157')
    except Exception as e:
        logger.error(e);


def CEN_AZ_158(task_id, app_service):
    try:
        insert_audit_records(task_id, app_service.enable_https_access_webapp(), 'CEN_AZ_158')
    except Exception as e:
        logger.error(e);


def CEN_AZ_159(task_id, app_service):
    try:
        insert_audit_records(task_id, app_service.enable_diagnostic_logs(), 'CEN_AZ_159')
    except Exception as e:
        logger.error(e);


def CEN_AZ_160(task_id, network_service):
    try:
        insert_audit_records(task_id, network_service.service_endpoint_servicebus(), 'CEN_AZ_160')
    except Exception as e:
        logger.error(e);


def CEN_AZ_161(task_id, network_service):
    try:
        insert_audit_records(task_id, network_service.deny_ssh_over_interent(), 'CEN_AZ_161')
    except Exception as e:
        logger.error(e);


def CEN_AZ_162(task_id, network_service):
    try:
        insert_audit_records(task_id, network_service.app_service_service_endpoint(), 'CEN_AZ_162')
    except Exception as e:
        logger.error(e);


def CEN_AZ_163(task_id, network_service):
    try:
        insert_audit_records(task_id, network_service.disable_gateway_nsg(), 'CEN_AZ_163')
    except Exception as e:
        logger.error(e);


def CEN_AZ_164(task_id, network_service):
    try:
        insert_audit_records(task_id, network_service.storage_account_service_network(), 'CEN_AZ_164')
    except Exception as e:
        logger.error(e);


def CEN_AZ_165(task_id, network_service):
    try:
        insert_audit_records(task_id, network_service.network_interface_deny_public_ips(), 'CEN_AZ_165')
    except Exception as e:
        logger.error(e);


def CEN_AZ_166(task_id, network_service):
    try:
        insert_audit_records(task_id, network_service.disable_ip_forwading(), 'CEN_AZ_166')
    except Exception as e:
        logger.error(e);


def CEN_AZ_167(task_id, network_service):
    try:
        insert_audit_records(task_id, network_service.service_endpoint_sql_server(), 'CEN_AZ_167')
    except Exception as e:
        logger.error(e);


def CEN_AZ_168(task_id, network_service):
    try:
        insert_audit_records(task_id, network_service.vpn_gateway_sku(), 'CEN_AZ_168')
    except Exception as e:
        logger.error(e);


def CEN_AZ_169(task_id, network_service):
    try:
        insert_audit_records(task_id, network_service.deny_rdp_over_interent(), 'CEN_AZ_169')
    except Exception as e:
        logger.error(e);


def CEN_AZ_170(task_id, db_service):
    try:
        insert_audit_records(task_id, db_service.sql_managed_instance_admin_email_available(),'CEN_AZ_170')
    except Exception as e:
        logger.error(e);


def CEN_AZ_172(task_id, db_service):
    try:
        insert_audit_records(task_id, db_service.data_security_managed_instance_status(),'CEN_AZ_172')
    except Exception as e:
        logger.error(e);


def CEN_AZ_173(task_id, db_service):
    try:
        insert_audit_records(task_id, db_service.data_security_sql_server_status(),'CEN_AZ_173')
    except Exception as e:
        logger.error(e);


def CEN_AZ_174(task_id, db_service):
    try:
        insert_audit_records(task_id, db_service.threat_protection_type_managed_instance(),'CEN_AZ_174')
    except Exception as e:
        logger.error(e);


def CEN_AZ_176(task_id, db_service):
    try:
        insert_audit_records(task_id, db_service.audit_sql_server(),'CEN_AZ_176')
    except Exception as e:
        logger.error(e);


def CEN_AZ_178(task_id, db_service):
    try:
        insert_audit_records(task_id, db_service.sql_managed_instance_admin_email_active(),'CEN_AZ_178')
    except Exception as e:
        logger.error(e);


def CEN_AZ_182(task_id, db_service):
    try:
        insert_audit_records(task_id, db_service.geo_redundant_backup_mariadb(),'CEN_AZ_182')
    except Exception as e:
        logger.error(e);


def CEN_AZ_183(task_id, db_service):
    try:
        insert_audit_records(task_id, db_service.geo_redundant_backup_mysql(),'CEN_AZ_183')
    except Exception as e:
        logger.error(e);


def CEN_AZ_184(task_id, db_service):
    try:
        insert_audit_records(task_id, db_service.geo_redundant_backup_postgresql(),'CEN_AZ_184')
    except Exception as e:
        logger.error(e);


def CEN_AZ_188(task_id, db_service):
    try:
        insert_audit_records(task_id, db_service.geo_redundant_backup_sql(),'CEN_AZ_188')
    except Exception as e:
        logger.error(e);


def CEN_AZ_189(task_id, db_service):
    try:
        insert_audit_records(task_id, db_service.mariadb_server_virtual_endpoint(),'CEN_AZ_189')
    except Exception as e:
        logger.error(e);


def CEN_AZ_190(task_id, db_service):
    try:
        insert_audit_records(task_id, db_service.sql_server_virtual_endpoint(),'CEN_AZ_190')
    except Exception as e:
        logger.error(e);


def CEN_AZ_191(task_id, db_service):
    try:
        insert_audit_records(task_id, db_service.postgresql_server_virtual_endpoint(),'CEN_AZ_191')
    except Exception as e:
        logger.error(e);


def CEN_AZ_192(task_id, db_service):
    try:
        insert_audit_records(task_id, db_service.sql_server_virtual_endpoint(),'CEN_AZ_192')
    except Exception as e:
        logger.error(e);


def CEN_AZ_193(task_id, db_service):
    try:
        insert_audit_records(task_id, db_service.mysql_private_endpoint(),'CEN_AZ_193')
    except Exception as e:
        logger.error(e);


def CEN_AZ_194(task_id, db_service):
    try:
        insert_audit_records(task_id, db_service.postgresql_private_endpoint(),'CEN_AZ_194')
    except Exception as e:
        logger.error(e);


def CEN_AZ_195(task_id, db_service):
    try:
        insert_audit_records(task_id, db_service.sql_managed_instance_tde_byok(),'CEN_AZ_195')
    except Exception as e:
        logger.error(e);


def CEN_AZ_199(task_id, db_service):
    try:
        insert_audit_records(task_id, db_service.sql_managed_instance_vulnerability_assessment(),'CEN_AZ_199')
    except Exception as e:
        logger.error(e);


def CEN_AZ_200(task_id, db_service):
    try:
        insert_audit_records(task_id, db_service.sql_server_vulnerability_assessment(),'CEN_AZ_200')
    except Exception as e:
        logger.error(e);


def CEN_AZ_201(task_id, security_service):
    try:
        insert_audit_records(task_id, security_service.network_hardening_recommendations(),'CEN_AZ_201')
    except Exception as e:
        logger.error(e);


def CEN_AZ_202(task_id, security_service):
    try:
        insert_audit_records(task_id, security_service.designate_subscription_owner(),'CEN_AZ_202')
    except Exception as e:
        logger.error(e);


def CEN_AZ_203(task_id, security_service):
    try:
        insert_audit_records(task_id, security_service.authorized_ip_ranges(),'CEN_AZ_203')
    except Exception as e:
        logger.error(e);


def CEN_AZ_204(task_id, security_service):
    try:
        insert_audit_records(task_id, security_service.open_managed_ports(),'CEN_AZ_204')
    except Exception as e:
        logger.error(e);


def CEN_AZ_205(task_id, security_service):
    try:
        insert_audit_records(task_id, security_service.endpoint_protection(),'CEN_AZ_205')
    except Exception as e:
        logger.error(e);


def CEN_AZ_206(task_id, security_service):
    try:
        insert_audit_records(task_id, security_service.pod_security_policy(),'CEN_AZ_206')
    except Exception as e:
        logger.error(e);


def CEN_AZ_207(task_id, security_service):
    try:
        insert_audit_records(task_id, security_service.os_vulnerabilities(),'CEN_AZ_207')
    except Exception as e:
        logger.error(e);


def CEN_AZ_208(task_id, security_service):
    try:
        insert_audit_records(task_id, security_service.adaptive_application_controls(),'CEN_AZ_208')
    except Exception as e:
        logger.error(e);


def CEN_AZ_209(task_id, security_service):
    try:
        insert_audit_records(task_id, security_service.no_of_owners(),'CEN_AZ_209')
    except Exception as e:
        logger.error(e);


def CEN_AZ_210(task_id, security_service):
    try:
        insert_audit_records(task_id, security_service.get_contact(),'CEN_AZ_210')
    except Exception as e:
        logger.error(e);


def CEN_AZ_211(task_id, security_service):
    try:
        insert_audit_records(task_id, security_service.is_emailing_security_alerts_enabled_to_the_security_contact(),'CEN_AZ_211')
    except Exception as e:
        logger.error(e);


def CEN_AZ_212(task_id, security_service):
    try:
        insert_audit_records(task_id, security_service.enable_system_updates_monitor(),'CEN_AZ_212')
    except Exception as e:
        logger.error(e);


def CEN_AZ_213(task_id, security_service):
    try:
        insert_audit_records(task_id, security_service.enable_standard_pricing(),'CEN_AZ_213')
    except Exception as e:
        logger.error(e);


def CEN_AZ_214(task_id, security_service):
    try:
        insert_audit_records(task_id, security_service.enable_security_center_for_subscription(),'CEN_AZ_214')
    except Exception as e:
        logger.error(e);


def CEN_AZ_215(task_id, kubernetes_service):
    try:
        insert_audit_records(task_id, kubernetes_service.rbac_on_kubernetes(),'CEN_AZ_215')
    except Exception as e:
        logger.error(e);


def CEN_AZ_216(task_id, security_service):
    try:
        insert_audit_records(task_id, security_service.disable_ip_forwarding_from_vm(),'CEN_AZ_216')
    except Exception as e:
        logger.error(e);

def CEN_AZ_217(execution_hash, app_service):
    try:
        insert_audit_records(execution_hash, app_service.api_app_php_version(), 'CEN_AZ_217')
    except Exception as e:
        logger.error(e);


def CEN_AZ_218(execution_hash, app_service):
    try:
        insert_audit_records(execution_hash, app_service.function_app_php_version(), 'CEN_AZ_218')
    except Exception as e:
        logger.error(e);


def CEN_AZ_219(execution_hash, app_service):
    try:
        insert_audit_records(execution_hash, app_service.web_app_php_version(), 'CEN_AZ_219')
    except Exception as e:
        logger.error(e);


def CEN_AZ_220(execution_hash, app_service):
    try:
        insert_audit_records(execution_hash, app_service.api_app_python_version(), 'CEN_AZ_220')
    except Exception as e:
        logger.error(e);


def CEN_AZ_221(execution_hash, app_service):
    try:
        insert_audit_records(execution_hash, app_service.function_app_python_version(), 'CEN_AZ_221')
    except Exception as e:
        logger.error(e);


def CEN_AZ_222(execution_hash, app_service):
    try:
        insert_audit_records(execution_hash, app_service.web_app_python_version(), 'CEN_AZ_222')
    except Exception as e:
        logger.error(e);


def CEN_AZ_223(execution_hash, app_service):
    try:
        insert_audit_records(execution_hash, app_service.api_app_java_version(), 'CEN_AZ_223')
    except Exception as e:
        logger.error(e);


def CEN_AZ_224(execution_hash, app_service):
    try:
        insert_audit_records(execution_hash, app_service.function_app_java_version(), 'CEN_AZ_224')
    except Exception as e:
        logger.error(e);


def CEN_AZ_225(execution_hash, app_service):
    try:
        insert_audit_records(execution_hash, app_service.web_app_java_version(), 'CEN_AZ_225')
    except Exception as e:
        logger.error(e);


def CEN_AZ_226(execution_hash, storage_service):
    try:
        insert_audit_records(execution_hash, storage_service.migrate_storage_to_new_rg(), 'CEN_AZ_226')
    except Exception as e:
        logger.error(e);

def CEN_AZ_227(task_id, monitor_service):
    try:
        insert_audit_records(task_id, monitor_service.audit_diagnostic_settings(),'CEN_AZ_227')
    except Exception as e:
        logger.error(e);

def CEN_AZ_228(task_id, monitor_service):
    try:
        insert_audit_records(task_id, monitor_service.audit_log_analytics_workspace_for_vm(),'CEN_AZ_228')
    except Exception as e:
        logger.error(e);


def CEN_AZ_229(task_id, app_configuration_service):
    try:
        insert_audit_records(task_id, app_configuration_service.app_config_customer_managed_key(), 'CEN_AZ_229')
    except Exception as e:
        logger.error(e);


def CEN_AZ_230(task_id, datalake_service):
    try:
        insert_audit_records(task_id, datalake_service.encryption_on_datalake_store, 'CEN_AZ_230')
    except Exception as e:
        logger.error(e);

def CEN_AZ_231(task_id, security_service):
    try:
        insert_audit_records(task_id, security_service.sensitive_data_in_sql_db(),'CEN_AZ_231')
    except Exception as e:
        logger.error(e);

def CEN_AZ_232(task_id, db_service):
    try:
        insert_audit_records(task_id, db_service.private_endpoint_should_be_enabled_Mariadb(),'CEN_AZ_232')
    except Exception as e:

        logger.error(e);
def CEN_AZ_233(task_id, monitor_service):
    try:
        insert_audit_records(task_id, monitor_service.create_alert_sql_server_firewall(),'CEN_AZ_233')
    except Exception as e:
        logger.error(e);


def execute_app_configuration_checks(task_id, app_configuration_service):
    CEN_AZ_229(task_id,app_configuration_service)

def execute_datalake_checks(task_id, datalake_service):
    CEN_AZ_230(task_id, datalake_service)


def execute_storage_checks(execution_hash, storage_service):
    CEN_AZ_4(execution_hash, storage_service)
    CEN_AZ_5(execution_hash, storage_service)
    CEN_AZ_7(execution_hash, storage_service)
    CEN_AZ_8(execution_hash, storage_service)
    CEN_AZ_2(execution_hash, storage_service)
    CEN_AZ_226(execution_hash, storage_service)


def execute_log_monitor_checks(task_id, monitor_service):
    CEN_AZ_9(task_id, monitor_service)
    CEN_AZ_10(task_id, monitor_service)
    CEN_AZ_11(task_id, monitor_service)
    CEN_AZ_12(task_id, monitor_service)
    CEN_AZ_13(task_id, monitor_service)
    CEN_AZ_14(task_id, monitor_service)
    CEN_AZ_15(task_id, monitor_service)
    CEN_AZ_227(task_id, monitor_service)
    CEN_AZ_228(task_id, monitor_service)
    CEN_AZ_233(task_id, monitor_service)


def execute_iam_checks(task_id, iam_service):
    CEN_AZ_16(task_id, iam_service)
    CEN_AZ_20(task_id, iam_service)


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
    CEN_AZ_201(execution_hash, security_service)
    CEN_AZ_202(execution_hash, security_service)
    CEN_AZ_203(execution_hash, security_service)
    CEN_AZ_204(execution_hash, security_service)
    CEN_AZ_205(execution_hash, security_service)
    CEN_AZ_206(execution_hash, security_service)
    CEN_AZ_207(execution_hash, security_service)
    CEN_AZ_208(execution_hash, security_service)
    CEN_AZ_209(execution_hash, security_service)
    CEN_AZ_210(execution_hash, security_service)
    CEN_AZ_211(execution_hash, security_service)
    CEN_AZ_212(execution_hash, security_service)
    CEN_AZ_213(execution_hash, security_service)
    CEN_AZ_214(execution_hash, security_service)
    CEN_AZ_215(execution_hash, security_service)
    CEN_AZ_216(execution_hash, security_service)
    CEN_AZ_231(execution_hash, security_service)


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
    CEN_AZ_170(execution_hash, db_service)
    CEN_AZ_172(execution_hash, db_service)
    CEN_AZ_173(execution_hash, db_service)
    CEN_AZ_174(execution_hash, db_service)
    CEN_AZ_176(execution_hash, db_service)
    CEN_AZ_178(execution_hash, db_service)
    CEN_AZ_182(execution_hash, db_service)
    CEN_AZ_183(execution_hash, db_service)
    CEN_AZ_184(execution_hash, db_service)
    CEN_AZ_188(execution_hash, db_service)
    CEN_AZ_189(execution_hash, db_service)
    CEN_AZ_190(execution_hash, db_service)
    CEN_AZ_191(execution_hash, db_service)
    CEN_AZ_192(execution_hash, db_service)
    CEN_AZ_193(execution_hash, db_service)
    CEN_AZ_194(execution_hash, db_service)
    CEN_AZ_195(execution_hash, db_service)
    CEN_AZ_199(execution_hash, db_service)
    CEN_AZ_200(execution_hash, db_service)
    CEN_AZ_232(execution_hash, db_service)


def execute_vm_checks(execution_hash, vm_service):
    CEN_AZ_77(execution_hash, vm_service)
    CEN_AZ_79(execution_hash, vm_service)
    CEN_AZ_81(execution_hash, vm_service)
    CEN_AZ_83(execution_hash, vm_service)
    CEN_AZ_84(execution_hash, vm_service)
    CEN_AZ_85(execution_hash, vm_service)
    CEN_AZ_86(execution_hash, vm_service)
    CEN_AZ_87(execution_hash, vm_service)
    CEN_AZ_88(execution_hash, vm_service)
    CEN_AZ_89(execution_hash, vm_service)
    CEN_AZ_100(execution_hash, vm_service)
    CEN_AZ_101(execution_hash, vm_service)
    CEN_AZ_102(execution_hash, vm_service)
    CEN_AZ_103(execution_hash, vm_service)
    CEN_AZ_104(execution_hash, vm_service)
    CEN_AZ_105(execution_hash, vm_service)
    CEN_AZ_106(execution_hash, vm_service)
    CEN_AZ_107(execution_hash, vm_service)
    CEN_AZ_108(execution_hash, vm_service)
    CEN_AZ_109(execution_hash, vm_service)
    CEN_AZ_110(execution_hash, vm_service)
    CEN_AZ_111(execution_hash, vm_service)
    CEN_AZ_112(execution_hash, vm_service)
    CEN_AZ_113(execution_hash, vm_service)
    CEN_AZ_114(execution_hash, vm_service)
    CEN_AZ_115(execution_hash, vm_service)
    CEN_AZ_116(execution_hash, vm_service)
    CEN_AZ_117(execution_hash, vm_service)
    CEN_AZ_118(execution_hash, vm_service)
    CEN_AZ_119(execution_hash, vm_service)
    CEN_AZ_121(execution_hash, vm_service)
    CEN_AZ_122(execution_hash, vm_service)
    CEN_AZ_123(execution_hash, vm_service)
    CEN_AZ_124(execution_hash, vm_service)
    CEN_AZ_125(execution_hash, vm_service)


def execute_disk_checks(execution_hash, vm_service):
    CEN_AZ_78(execution_hash, vm_service)
    CEN_AZ_82(execution_hash, vm_service)


def execute_az_services_checks(execution_hash, az_service):
    CEN_AZ_80(execution_hash, az_service)
    CEN_AZ_90(execution_hash, az_service)
    CEN_AZ_91(execution_hash, az_service)
    CEN_AZ_92(execution_hash, az_service)
    CEN_AZ_93(execution_hash, az_service)
    CEN_AZ_94(execution_hash, az_service)
    CEN_AZ_95(execution_hash, az_service)
    CEN_AZ_96(execution_hash, az_service)
    CEN_AZ_97(execution_hash, az_service)
    CEN_AZ_98(execution_hash, az_service)


def execute_automation_services_checks(execution_hash, automation_service):
    CEN_AZ_120(execution_hash, automation_service)


def execute_network_checks(execution_hash, network_service):
    CEN_AZ_160(execution_hash, network_service)
    CEN_AZ_161(execution_hash, network_service)
    CEN_AZ_162(execution_hash, network_service)
    CEN_AZ_163(execution_hash, network_service)
    CEN_AZ_164(execution_hash, network_service)
    CEN_AZ_165(execution_hash, network_service)
    CEN_AZ_166(execution_hash, network_service)
    CEN_AZ_167(execution_hash, network_service)
    CEN_AZ_168(execution_hash, network_service)
    CEN_AZ_169(execution_hash, network_service)


def execute_app_service_checks(execution_hash, app_service):
    CEN_AZ_126(execution_hash, app_service)
    CEN_AZ_127(execution_hash, app_service)
    CEN_AZ_128(execution_hash, app_service)
    CEN_AZ_129(execution_hash, app_service)
    CEN_AZ_130(execution_hash, app_service)
    CEN_AZ_131(execution_hash, app_service)
    CEN_AZ_132(execution_hash, app_service)
    CEN_AZ_133(execution_hash, app_service)
    CEN_AZ_134(execution_hash, app_service)
    CEN_AZ_135(execution_hash, app_service)
    CEN_AZ_136(execution_hash, app_service)
    CEN_AZ_137(execution_hash, app_service)
    CEN_AZ_138(execution_hash, app_service)
    CEN_AZ_139(execution_hash, app_service)
    CEN_AZ_140(execution_hash, app_service)
    CEN_AZ_141(execution_hash, app_service)
    CEN_AZ_142(execution_hash, app_service)
    CEN_AZ_143(execution_hash, app_service)
    CEN_AZ_144(execution_hash, app_service)
    CEN_AZ_145(execution_hash, app_service)
    CEN_AZ_146(execution_hash, app_service)
    CEN_AZ_147(execution_hash, app_service)
    CEN_AZ_148(execution_hash, app_service)
    CEN_AZ_149(execution_hash, app_service)
    CEN_AZ_150(execution_hash, app_service)
    CEN_AZ_151(execution_hash, app_service)
    CEN_AZ_152(execution_hash, app_service)
    CEN_AZ_153(execution_hash, app_service)
    CEN_AZ_154(execution_hash, app_service)
    CEN_AZ_155(execution_hash, app_service)
    CEN_AZ_156(execution_hash, app_service)
    CEN_AZ_157(execution_hash, app_service)
    CEN_AZ_158(execution_hash, app_service)
    CEN_AZ_159(execution_hash, app_service)
    CEN_AZ_217(execution_hash, app_service)
    CEN_AZ_218(execution_hash, app_service)
    CEN_AZ_219(execution_hash, app_service)
    CEN_AZ_220(execution_hash, app_service)
    CEN_AZ_221(execution_hash, app_service)
    CEN_AZ_222(execution_hash, app_service)
    CEN_AZ_223(execution_hash, app_service)
    CEN_AZ_224(execution_hash, app_service)
    CEN_AZ_225(execution_hash, app_service)

def execute_security_centre_checks(task_id, security_service):
    CEN_AZ_40(task_id, security_service)
    CEN_AZ_41(task_id, security_service)
    CEN_AZ_42(task_id, security_service)
    CEN_AZ_43(task_id, security_service)
    CEN_AZ_44(task_id, security_service)
    CEN_AZ_45(task_id, security_service)
    CEN_AZ_46(task_id, security_service)
    CEN_AZ_47(task_id, security_service)
    CEN_AZ_48(task_id, security_service)
    CEN_AZ_49(task_id, security_service)
    CEN_AZ_50(task_id, security_service)
    CEN_AZ_51(task_id, security_service)
    CEN_AZ_52(task_id, security_service)
    CEN_AZ_53(task_id, security_service)
    CEN_AZ_54(task_id, security_service)
    CEN_AZ_55(task_id, security_service)
    CEN_AZ_56(task_id, security_service)
    CEN_AZ_57(task_id, security_service)
    CEN_AZ_58(task_id, security_service)
    CEN_AZ_201(task_id, security_service)
    CEN_AZ_202(task_id, security_service)
    CEN_AZ_203(task_id, security_service)
    CEN_AZ_204(task_id, security_service)
    CEN_AZ_205(task_id, security_service)
    CEN_AZ_206(task_id, security_service)
    CEN_AZ_207(task_id, security_service)
    CEN_AZ_208(task_id, security_service)
    CEN_AZ_209(task_id, security_service)
    CEN_AZ_210(task_id, security_service)
    CEN_AZ_211(task_id, security_service)
    CEN_AZ_212(task_id, security_service)
    CEN_AZ_213(task_id, security_service)
    CEN_AZ_214(task_id, security_service)
    #CEN_AZ_215(task_id, security_service)
    CEN_AZ_216(task_id, security_service)


def execute_database_checks(task_id, db_service):
    CEN_AZ_59(task_id, db_service)
    CEN_AZ_60(task_id, db_service)
    CEN_AZ_61(task_id, db_service)
    CEN_AZ_62(task_id, db_service)
    CEN_AZ_63(task_id, db_service)
    CEN_AZ_64(task_id, db_service)
    CEN_AZ_65(task_id, db_service)
    CEN_AZ_66(task_id, db_service)
    CEN_AZ_68(task_id, db_service)
    CEN_AZ_69(task_id, db_service)
    CEN_AZ_70(task_id, db_service)
    CEN_AZ_71(task_id, db_service)
    CEN_AZ_72(task_id, db_service)
    CEN_AZ_73(task_id, db_service)
    CEN_AZ_170(task_id, db_service)
    CEN_AZ_172(task_id, db_service)
    CEN_AZ_173(task_id, db_service)
    CEN_AZ_174(task_id, db_service)
    CEN_AZ_176(task_id, db_service)
    CEN_AZ_178(task_id, db_service)
    CEN_AZ_182(task_id, db_service)
    CEN_AZ_183(task_id, db_service)
    CEN_AZ_184(task_id, db_service)
    CEN_AZ_188(task_id, db_service)
    CEN_AZ_189(task_id, db_service)
    CEN_AZ_190(task_id, db_service)
    CEN_AZ_191(task_id, db_service)
    CEN_AZ_192(task_id, db_service)
    CEN_AZ_193(task_id, db_service)
    CEN_AZ_194(task_id, db_service)
    CEN_AZ_195(task_id, db_service)
    CEN_AZ_199(task_id, db_service)
    CEN_AZ_200(task_id, db_service)


def execute_vm_checks(task_id, vm_service):
    CEN_AZ_77(task_id, vm_service)
    CEN_AZ_79(task_id, vm_service)
    CEN_AZ_81(task_id, vm_service)
    CEN_AZ_83(task_id, vm_service)
    CEN_AZ_84(task_id, vm_service)
    CEN_AZ_85(task_id, vm_service)
    CEN_AZ_86(task_id, vm_service)
    CEN_AZ_87(task_id, vm_service)
    CEN_AZ_88(task_id, vm_service)
    CEN_AZ_89(task_id, vm_service)
    CEN_AZ_100(task_id, vm_service)
    CEN_AZ_101(task_id, vm_service)
    CEN_AZ_102(task_id, vm_service)
    CEN_AZ_103(task_id, vm_service)
    CEN_AZ_104(task_id, vm_service)
    CEN_AZ_105(task_id, vm_service)
    CEN_AZ_106(task_id, vm_service)
    CEN_AZ_107(task_id, vm_service)
    CEN_AZ_108(task_id, vm_service)
    CEN_AZ_109(task_id, vm_service)
    CEN_AZ_110(task_id, vm_service)
    CEN_AZ_111(task_id, vm_service)
    CEN_AZ_112(task_id, vm_service)
    CEN_AZ_113(task_id, vm_service)
    CEN_AZ_114(task_id, vm_service)
    CEN_AZ_115(task_id, vm_service)
    CEN_AZ_116(task_id, vm_service)
    CEN_AZ_117(task_id, vm_service)
    CEN_AZ_118(task_id, vm_service)
    CEN_AZ_119(task_id, vm_service)
    CEN_AZ_121(task_id, vm_service)
    CEN_AZ_122(task_id, vm_service)
    CEN_AZ_123(task_id, vm_service)
    CEN_AZ_124(task_id, vm_service)
    CEN_AZ_125(task_id, vm_service)


def execute_disk_checks(task_id, vm_service):
    CEN_AZ_78(task_id, vm_service)
    CEN_AZ_82(task_id, vm_service)


def execute_az_services_checks(task_id, az_service):
    CEN_AZ_80(task_id, az_service)
    CEN_AZ_90(task_id, az_service)
    CEN_AZ_91(task_id, az_service)
    CEN_AZ_92(task_id, az_service)
    CEN_AZ_93(task_id, az_service)
    CEN_AZ_94(task_id, az_service)
    CEN_AZ_95(task_id, az_service)
    CEN_AZ_96(task_id, az_service)
    CEN_AZ_97(task_id, az_service)
    CEN_AZ_98(task_id, az_service)


def execute_automation_services_checks(task_id, automation_service):
    CEN_AZ_120(task_id, automation_service)


def execute_network_checks(task_id, network_service):
    CEN_AZ_160(task_id, network_service)
    CEN_AZ_161(task_id, network_service)
    CEN_AZ_162(task_id, network_service)
    CEN_AZ_163(task_id, network_service)
    CEN_AZ_164(task_id, network_service)
    CEN_AZ_165(task_id, network_service)
    CEN_AZ_166(task_id, network_service)
    CEN_AZ_167(task_id, network_service)
    CEN_AZ_168(task_id, network_service)
    CEN_AZ_169(task_id, network_service)


def execute_app_service_checks(task_id, app_service):
    CEN_AZ_126(task_id, app_service)
    CEN_AZ_127(task_id, app_service)
    CEN_AZ_128(task_id, app_service)
    CEN_AZ_129(task_id, app_service)
    CEN_AZ_130(task_id, app_service)
    CEN_AZ_131(task_id, app_service)
    CEN_AZ_132(task_id, app_service)
    CEN_AZ_133(task_id, app_service)
    CEN_AZ_134(task_id, app_service)
    CEN_AZ_135(task_id, app_service)
    CEN_AZ_136(task_id, app_service)
    CEN_AZ_137(task_id, app_service)
    CEN_AZ_138(task_id, app_service)
    CEN_AZ_139(task_id, app_service)
    CEN_AZ_140(task_id, app_service)
    CEN_AZ_141(task_id, app_service)
    CEN_AZ_142(task_id, app_service)
    CEN_AZ_143(task_id, app_service)
    CEN_AZ_144(task_id, app_service)
    CEN_AZ_145(task_id, app_service)
    CEN_AZ_146(task_id, app_service)
    CEN_AZ_147(task_id, app_service)
    CEN_AZ_148(task_id, app_service)
    CEN_AZ_149(task_id, app_service)
    CEN_AZ_150(task_id, app_service)
    CEN_AZ_151(task_id, app_service)
    CEN_AZ_152(task_id, app_service)
    CEN_AZ_153(task_id, app_service)
    CEN_AZ_154(task_id, app_service)
    CEN_AZ_155(task_id, app_service)
    CEN_AZ_156(task_id, app_service)
    CEN_AZ_157(task_id, app_service)
    CEN_AZ_158(task_id, app_service)
    CEN_AZ_159(task_id, app_service)


def execute_kubernetes_service_checks(task_id, kubernetes_service):
    CEN_AZ_215(task_id,kubernetes_service)

