from checks.common_services import CommonServices
from helper_function import get_auth_token, rest_api_call
from contants import postgres_server_list_url, base_url, sql_server_list_url, mysql_server_list_url


class DatabaseService:
    def __init__(self, credentials):
        self.credentials = credentials

    def psql_log_retension_period(self):
        issues=[]
        try:
            token = get_auth_token(self.credentials)
            cs = CommonServices()
            subscription_list = cs.get_subscriptions_list(token)
            for subscription in subscription_list:
                url = postgres_server_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(token, url, '2017-12-01')
                server_list = response['value']
                for server in server_list:
                    temp = dict()
                    temp["region"] = server['location']
                    id = server['id']
                    config_url = base_url + id + "/configurations"
                    config_response = rest_api_call(token, config_url, '2017-12-01')
                    properties_list = config_response['value']
                    for property in properties_list:
                        if property['name'] == "log_retention_days":
                            retension_days = property['properties']['value']
                            if retension_days <= 3:
                                temp['status'] = "Fail"
                                temp['resource_name'] = server['name']
                                temp['resource_id'] = server['id']
                                temp['problem'] = "Azure PostgreSQL database server {} does not have a sufficient log retention period currently configured.".format(server['name'])
                            else:
                                temp['status'] = "Pass"
                                temp['resource_name'] = server['name']
                                temp['resource_id'] = server['id']
                                temp['problem'] = "Azure PostgreSQL database server {} have a sufficient log retention period currently configured.".format(server['name'])
                            issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def enable_psql_connection_throttling(self):
        issues=[]
        try:
            token = get_auth_token(self.credentials)
            cs = CommonServices()
            subscription_list = cs.get_subscriptions_list(token)
            for subscription in subscription_list:
                url = postgres_server_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(token, url, '2017-12-01')
                server_list = response['value']
                for server in server_list:
                    temp = dict()
                    temp["region"] = server['location']
                    id = server['id']
                    config_url = base_url + id + "/configurations"
                    config_response = rest_api_call(token, config_url, '2017-12-01')
                    properties_list = config_response['value']
                    for property in properties_list:
                        if property['name'] == "connection_throttling":
                            if property['properties']['value'].lower() == "off":
                                temp['status'] = "Fail"
                                temp['resource_name'] = server['name']
                                temp['resource_id'] = server['id']
                                temp['problem'] = "Connection throttling parameter is not enabled for Azure PostgreSQL database server {}.".format(server['name'])
                            else:
                                temp['status'] = "Pass"
                                temp['resource_name'] = server['name']
                                temp['resource_id'] = server['id']
                                temp['problem'] = "Connection throttling parameter is enabled for Azure PostgreSQL database server {}.".format(server['name'])
                            issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def enable_psql_log_checkpoints(self):
        issues=[]
        try:
            token = get_auth_token(self.credentials)
            cs = CommonServices()
            subscription_list = cs.get_subscriptions_list(token)
            for subscription in subscription_list:
                url = postgres_server_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(token, url, '2017-12-01')
                server_list = response['value']
                for server in server_list:
                    temp = dict()
                    temp["region"] = server['location']
                    id = server['id']
                    config_url = base_url + id + "/configurations"
                    config_response = rest_api_call(token, config_url, '2017-12-01')
                    properties_list = config_response['value']
                    for property in properties_list:
                        if property['name'] == "log_checkpoints":
                            if property['properties']['value'].lower() == "off":
                                temp['status'] = "Fail"
                                temp['resource_name'] = server['name']
                                temp['resource_id'] = server['id']
                                temp['problem'] = "Log checkpoints parameter is not enabled for Azure PostgreSQL database server {}.".format(server['name'])
                            else:
                                temp['status'] = "Pass"
                                temp['resource_name'] = server['name']
                                temp['resource_id'] = server['id']
                                temp['problem'] = "Log checkpoints parameter is enabled for Azure PostgreSQL database server {}.".format(server['name'])
                            issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def enable_psql_log_connections(self):
        issues=[]
        try:
            token = get_auth_token(self.credentials)
            cs = CommonServices()
            subscription_list = cs.get_subscriptions_list(token)
            for subscription in subscription_list:
                url = postgres_server_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(token, url, '2017-12-01')
                server_list = response['value']
                for server in server_list:
                    temp = dict()
                    temp["region"] = server['location']
                    id = server['id']
                    config_url = base_url + id + "/configurations"
                    config_response = rest_api_call(token, config_url, '2017-12-01')
                    properties_list = config_response['value']
                    for property in properties_list:
                        if property['name'] == "log_connections":
                            if property['properties']['value'].lower() == "off":
                                temp['status'] = "Fail"
                                temp['resource_name'] = server['name']
                                temp['resource_id'] = server['id']
                                temp['problem'] = "Log connections parameter is not enabled for Azure PostgreSQL database server {}.".format(server['name'])
                            else:
                                temp['status'] = "Pass"
                                temp['resource_name'] = server['name']
                                temp['resource_id'] = server['id']
                                temp['problem'] = "Log connections parameter is enabled for Azure PostgreSQL database server {}.".format(server['name'])
                            issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def enable_psql_log_disconnections(self):
        issues=[]
        try:
            token = get_auth_token(self.credentials)
            cs = CommonServices()
            subscription_list = cs.get_subscriptions_list(token)
            for subscription in subscription_list:
                url = postgres_server_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(token, url, '2017-12-01')
                server_list = response['value']
                for server in server_list:
                    temp = dict()
                    temp["region"] = server['location']
                    id = server['id']
                    config_url = base_url + id + "/configurations"
                    config_response = rest_api_call(token, config_url, '2017-12-01')
                    properties_list = config_response['value']
                    for property in properties_list:
                        if property['name'] == "log_disconnections":
                            if property['properties']['value'].lower() == "off":
                                temp['status'] = "Fail"
                                temp['resource_name'] = server['name']
                                temp['resource_id'] = server['id']
                                temp['problem'] = "Log Disconnections parameter is not enabled for Azure PostgreSQL database server {}.".format(server['name'])
                            else:
                                temp['status'] = "Pass"
                                temp['resource_name'] = server['name']
                                temp['resource_id'] = server['id']
                                temp['problem'] = "Log Disconnections parameter is enabled for Azure PostgreSQL database server {}.".format(server['name'])
                            issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def enable_psql_log_duration(self):
        issues=[]
        try:
            token = get_auth_token(self.credentials)
            cs = CommonServices()
            subscription_list = cs.get_subscriptions_list(token)
            for subscription in subscription_list:
                url = postgres_server_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(token, url, '2017-12-01')
                server_list = response['value']
                for server in server_list:
                    temp = dict()
                    temp["region"] = server['location']
                    id = server['id']
                    config_url = base_url + id + "/configurations"
                    config_response = rest_api_call(token, config_url, '2017-12-01')
                    properties_list = config_response['value']
                    for property in properties_list:
                        if property['name'] == "log_duration":
                            if property['properties']['value'].lower() == "off":
                                temp['status'] = "Fail"
                                temp['resource_name'] = server['name']
                                temp['resource_id'] = server['id']
                                temp['problem'] = "Log duration parameter is not enabled for Azure PostgreSQL database server {}.".format(server['name'])
                            else:
                                temp['status'] = "Pass"
                                temp['resource_name'] = server['name']
                                temp['resource_id'] = server['id']
                                temp['problem'] = "Log duration parameter is enabled for Azure PostgreSQL database server {}.".format(server['name'])
                            issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def enable_psql_ssl_enforcement(self):
        issues=[]
        try:
            token = get_auth_token(self.credentials)
            cs = CommonServices()
            subscription_list = cs.get_subscriptions_list(token)
            for subscription in subscription_list:
                url = postgres_server_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(token, url, '2017-12-01')
                server_list = response['value']
                for server in server_list:
                    temp = dict()
                    temp["region"] = server['location']
                    if server["properties"]["sslEnforcement"] == "Enabled":
                        temp["status"] = "Pass"
                        temp["resource_name"] = server['name']
                        temp["resource_id"] = server['id']
                        temp["problem"] = "In-transit encryption with SSL is enabled for Azure PostgreSQL database server {}.".format(server['name'])
                    else:
                        temp["status"] = "Fail"
                        temp["resource_name"] = server['name']
                        temp["resource_id"] = server['id']
                        temp["problem"] = "In-transit encryption with SSL is not enabled for Azure PostgreSQL database server {}.".format(server['name'])
                    issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def sql_audit_retension_priod(self):
        issues = []
        try:
            token = get_auth_token(self.credentials)
            cs = CommonServices()
            subscription_list = cs.get_subscriptions_list(token)
            for subscription in subscription_list:
                url = sql_server_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(token, url, '2015-05-01-preview')
                server_list = response['value']
                for s   erver in server_list:
                    temp = dict()
                    temp["region"] = server["location"]
                    audit_url = base_url + server['id'] + "/auditingSettings/default"
                    audit_response = rest_api_call(token, audit_url, '2017-03-01-preview')
                    retension_days = audit_response['properties']['retentionDays']
                    if retension_days <= 0:
                        temp["status"] = "Fail"
                        temp["resource_name"] = server["name"]
                        temp["resource_id"] = server["id"]
                        temp["problem"] = "SQL database auditing policy for sql server {} does not have sufficient log data retention period. " .format(server["name"])
                    elif retension_days < 90:
                        temp["status"] = "Fail"
                        temp["resource_name"] = server["name"]
                        temp["resource_id"] = server["id"]
                        temp["problem"] = "SQL database auditing policy for sql server {} does not have sufficient log data retention period." \
                            .format(server["name"])
                    else:
                        temp["status"] = "Pass"
                        temp["resource_name"] = server["name"]
                        temp["resource_id"] = server["id"]
                        temp["problem"] = "SQL database auditing policy for sql server {} have sufficient log data retention period." \
                            .format(server["name"])
                    issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def sql_enable_audit_action_group(self):
        issues = []
        try:
            token = get_auth_token(self.credentials)
            cs = CommonServices()
            subscription_list = cs.get_subscriptions_list(token)
            for subscription in subscription_list:
                url = sql_server_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(token, url, '2015-05-01-preview')
                server_list = response['value']
                for server in server_list:
                    temp = dict()
                    temp["region"] = server['location']
                    audit_url = base_url + server['id'] + "/auditingSettings/default"
                    audit_response = rest_api_call(token, audit_url, '2017-03-01-preview')
                    flag = 0
                    if not audit_response['properties']['auditActionsAndGroups']:
                        flag = 1
                    else:
                        if 'SUCCESSFUL_DATABASE_AUTHENTICATION_GROUP' not in audit_response['properties']['auditActionsAndGroups']:
                            flag = 1
                        if 'FAILED_DATABASE_AUTHENTICATION_GROUP' not in audit_response['properties']['auditActionsAndGroups']:
                            flag = 1
                        if 'BATCH_COMPLETED_GROUP' not in audit_response['properties']['auditActionsAndGroups']:
                            flag = 1
                    if flag == 1:
                        temp["status"] = "Fail"
                        temp["resource_name"] = server["name"]
                        temp["resource_id"] = server["id"]
                        temp["problem"] = "AuditActionGroup is not enabled for Azure SQL server {}.".format(server["name"])
                    else:
                        temp["status"] = "Pass"
                        temp["resource_name"] = server["name"]
                        temp["resource_id"] = server["id"]
                        temp["problem"] = "AuditActionGroup is enabled for Azure SQL server {}.".format(server["name"])

                    issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def enable_sql_threat_detection(self):
        issues = []
        try:
            token = get_auth_token(self.credentials)
            cs = CommonServices()
            subscription_list = cs.get_subscriptions_list(token)
            for subscription in subscription_list:
                url = sql_server_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(token, url, '2019-06-01-preview')
                server_list = response['value']
                for server in server_list:
                    temp = dict()
                    temp["region"] = server['location']
                    audit_url = base_url + server['id'] + "/securityAlertPolicies/default"
                    audit_response = rest_api_call(token, audit_url, '2019-06-01-preview')
                    diabled_alerts = audit_response['properties']['disabledAlerts']
                    flag = 0
                    '''if len(diabled_alerts) <= 0:
                        flag = 1
                    else :'''
                    if 'Sql_Injection' not in diabled_alerts:
                        flag = 1
                    if 'Sql_Injection_Vulnerability' not in diabled_alerts:
                        flag = 1
                    if 'Access_Anomaly' not in diabled_alerts:
                        flag = 1
                    if 'Data_Exfiltration' not in diabled_alerts:
                        flag = 1
                    if 'Unsafe_Action' not in diabled_alerts:
                        flag =1

                    if flag == 0:
                        temp["status"] = "Pass"
                        temp["resource_name"] = server["name"]
                        temp["resource_id"] = server["id"]
                        temp["problem"] = "Advanced Threat Detection alerts for all types of threats enabled for Azure SQL server {}.".format(server['name'])
                    else:
                        temp["status"] = "Fail"
                        temp["resource_name"] = server["name"]
                        temp["resource_id"] = server["id"]
                        temp["problem"] = "Advanced Threat Detection alerts for all types of threats  not enabled for Azure SQL server {}.".format(server['name'])
                    issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def sql_enable_auditing(self):
        issues = []
        try:
            token = get_auth_token(self.credentials)
            cs = CommonServices()
            subscription_list = cs.get_subscriptions_list(token)
            for subscription in subscription_list:
                url = sql_server_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(token, url, '2015-05-01-preview')
                server_list = response['value']
                for server in server_list:
                    temp = dict()
                    temp["region"] = server['location']
                    audit_url = base_url + server['id'] + "/auditingSettings/AuditState"
                    audit_response = rest_api_call(token, audit_url, '2017-03-01-preview')
                    if audit_response['properties']['state'] == "Disabled":
                        temp["status"] = "Fail"
                        temp["resource_name"] = server["name"]
                        temp["resource_id"] = server["id"]
                        temp["problem"] = "Database auditing is not enabled for Azure SQL server {}.".format(server["name"])
                    else:
                        temp["status"] = "Pass"
                        temp["resource_name"] = server["name"]
                        temp["resource_id"] = server["id"]
                        temp["problem"] = "Database auditing is enabled for Azure SQL server {}.".format(server["name"])
                    issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def enable_sql_threat_email_notification_admins(self):
        issues = []
        try:
            token = get_auth_token(self.credentials)
            cs = CommonServices()
            subscription_list = cs.get_subscriptions_list(token)
            for subscription in subscription_list:
                url = sql_server_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(token, url, '2015-05-01-preview')
                server_list = response['value']
                for server in server_list:
                    temp = dict()
                    temp["region"] = server['location']
                    audit_url = base_url + server['id'] + "/securityAlertPolicies/default"
                    audit_response = rest_api_call(token, audit_url, '2019-06-01-preview')
                    if audit_response['properties']['emailAccountAdmins']:
                        temp["status"] = "Pass"
                        temp["resource_name"] = server["name"]
                        temp["resource_id"] = server["id"]
                        temp["problem"] = "Also Send email notification to admins and subscription owners for threat detection is enabled for Azure SQL server {}.".format(server["name"])
                    else:
                        temp["status"] = "Fail"
                        temp["resource_name"] = server["name"]
                        temp["resource_id"] = server["id"]
                        temp["problem"] = "Also Send email notification to admins and subscription owners for threat detection is not enabled for Azure SQL server {}.".format(
                            server["name"])
                    issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def enable_sql_threat_email_notification(self):
        issues = []
        try:
            token = get_auth_token(self.credentials)
            cs = CommonServices()
            subscription_list = cs.get_subscriptions_list(token)
            for subscription in subscription_list:
                url = sql_server_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(token, url, '2015-05-01-preview')
                server_list = response['value']
                for server in server_list:
                    temp = dict()
                    temp["region"] = server['location']
                    audit_url = base_url + server['id'] + "/securityAlertPolicies/default"
                    audit_response = rest_api_call(token, audit_url, '2019-06-01-preview')
                    if len(audit_response['properties']['emailAddresses']) <= 1 and audit_response['properties']['emailAddresses'][0] == '':
                        temp["status"] = "Fail"
                        temp["resource_name"] = server["name"]
                        temp["resource_id"] = server["id"]
                        temp["problem"] = "Send email notifications for threat detection is not enabled for Azure SQL server {}.".format(server["name"])
                    else:
                        temp["status"] = "Pass"
                        temp["resource_name"] = server["name"]
                        temp["resource_id"] = server["id"]
                        temp["problem"] = "Send email notification for threat detection is enabled for Azure SQL server {}.".format(
                            server["name"])
                    issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def sql_rest_encryption(self):
        issues = []
        try:
            token = get_auth_token(self.credentials)
            cs = CommonServices()
            subscription_list = cs.get_subscriptions_list(token)
            for subscription in subscription_list:
                url = sql_server_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(token, url, '2015-05-01-preview')
                server_list = response['value']
                for server in server_list:
                    temp = dict()
                    temp["region"] = server['location']
                    db_url = base_url + server['id'] + "/databases"
                    db_response = rest_api_call(token, db_url, '2019-06-01-preview')
                    db_list = db_response['value']
                    for db in db_list:
                        tde_url = base_url + db['id'] + "/transparentDataEncryption/current"
                        tde_response = rest_api_call(token, tde_url, '2014-04-01')
                        print(tde_response)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def mysql_encryption(self):
        issues = []
        try:
            token = get_auth_token(self.credentials)
            cs = CommonServices()
            subscription_list = cs.get_subscriptions_list(token)
            for subscription in subscription_list:
                url = mysql_server_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(token, url,'2017-12-01')
                server_list = response['value']
                for server in server_list:
                    temp = dict()
                    temp["region"] = server['location']
                    if server["properties"]["sslEnforcement"] == "Enabled":
                        temp["status"] = "Pass"
                        temp["resource_name"] = server['name']
                        temp["resource_id"] = server['id']
                        temp["problem"] = "In-transit encryption with SSL is enabled for Azure MySQL server {}.".format(
                            server['name'])
                    else:
                        temp["status"] = "Fail"
                        temp["resource_name"] = server['name']
                        temp["resource_id"] = server['id']
                        temp["problem"] = "In-transit encryption with SSL is not enabled for Azure MySQL server {}.".format(
                            server['name'])
                    issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues