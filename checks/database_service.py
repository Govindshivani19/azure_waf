from checks.common_services import CommonServices
from helper_function import get_auth_token, rest_api_call
from contants import postgres_server_list_url, base_url, sql_server_list_url, mysql_server_list_url


class DatabaseService:
    def __init__(self, credentials, subscription_list):
        self.credentials = credentials
        self.subscription_list = subscription_list

    def psql_log_retension_period(self):
        issues=[]
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                url = postgres_server_list_url.format(subscription['subscriptionId'])
                token = get_auth_token(self.credentials)
                response = rest_api_call(token, url, '2017-12-01')
                server_list = response['value']
                for server in server_list:
                    temp = dict()
                    temp["region"] = server['location']
                    id = server['id']
                    config_url = base_url + id + "/configurations"
                    token = get_auth_token(self.credentials)
                    config_response = rest_api_call(token, config_url, '2017-12-01')
                    properties_list = config_response['value']
                    for property in properties_list:
                        if property['name'] == "log_retention_days":
                            retension_days = property['properties']['value']
                            if int(retension_days) <= 3:
                                temp['status'] = "Fail"
                                temp['resource_name'] = server['name']
                                temp['resource_id'] = server['id']
                                temp["subscription_id"] = subscription['subscriptionId']
                                temp["subscription_name"] = subscription["displayName"]
                            else:
                                temp['status'] = "Pass"
                                temp['resource_name'] = server['name']
                                temp['resource_id'] = server['id']
                                temp["subscription_id"] = subscription['subscriptionId']
                                temp["subscription_name"] = subscription["displayName"]
                            issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def enable_psql_connection_throttling(self):
        issues=[]
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                url = postgres_server_list_url.format(subscription['subscriptionId'])
                token = get_auth_token(self.credentials)
                response = rest_api_call(token, url, '2017-12-01')
                server_list = response['value']
                for server in server_list:
                    temp = dict()
                    temp["region"] = server['location']
                    id = server['id']
                    config_url = base_url + id + "/configurations"
                    token = get_auth_token(self.credentials)
                    config_response = rest_api_call(token, config_url, '2017-12-01')
                    properties_list = config_response['value']
                    for property in properties_list:
                        if property['name'] == "connection_throttling":
                            if property['properties']['value'].lower() == "off":
                                temp['status'] = "Fail"
                                temp['resource_name'] = server['name']
                                temp['resource_id'] = server['id']
                                temp["subscription_id"] = subscription['subscriptionId']
                                temp["subscription_name"] = subscription["displayName"]
                            else:
                                temp['status'] = "Pass"
                                temp['resource_name'] = server['name']
                                temp['resource_id'] = server['id']
                                temp["subscription_id"] = subscription['subscriptionId']
                                temp["subscription_name"] = subscription["displayName"]
                            issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def enable_psql_log_checkpoints(self):
        issues=[]
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                url = postgres_server_list_url.format(subscription['subscriptionId'])
                token = get_auth_token(self.credentials)
                response = rest_api_call(token, url, '2017-12-01')
                server_list = response['value']
                for server in server_list:
                    temp = dict()
                    temp["region"] = server['location']
                    id = server['id']
                    config_url = base_url + id + "/configurations"
                    token = get_auth_token(self.credentials)
                    config_response = rest_api_call(token, config_url, '2017-12-01')
                    properties_list = config_response['value']
                    for property in properties_list:
                        if property['name'] == "log_checkpoints":
                            if property['properties']['value'].lower() == "off":
                                temp['status'] = "Fail"
                                temp['resource_name'] = server['name']
                                temp['resource_id'] = server['id']
                                temp["subscription_id"] = subscription['subscriptionId']
                                temp["subscription_name"] = subscription["displayName"]
                            else:
                                temp['status'] = "Pass"
                                temp['resource_name'] = server['name']
                                temp['resource_id'] = server['id']
                                temp["subscription_id"] = subscription['subscriptionId']
                                temp["subscription_name"] = subscription["displayName"]
                            issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def enable_psql_log_connections(self):
        issues=[]
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                url = postgres_server_list_url.format(subscription['subscriptionId'])
                token = get_auth_token(self.credentials)
                response = rest_api_call(token, url, '2017-12-01')
                server_list = response['value']
                for server in server_list:
                    temp = dict()
                    temp["region"] = server['location']
                    id = server['id']
                    config_url = base_url + id + "/configurations"
                    token = get_auth_token(self.credentials)
                    config_response = rest_api_call(token, config_url, '2017-12-01')
                    properties_list = config_response['value']
                    for property in properties_list:
                        if property['name'] == "log_connections":
                            if property['properties']['value'].lower() == "off":
                                temp['status'] = "Fail"
                                temp['resource_name'] = server['name']
                                temp['resource_id'] = server['id']
                                temp["subscription_id"] = subscription['subscriptionId']
                                temp["subscription_name"] = subscription["displayName"]
                            else:
                                temp['status'] = "Pass"
                                temp['resource_name'] = server['name']
                                temp['resource_id'] = server['id']
                                temp["subscription_id"] = subscription['subscriptionId']
                                temp["subscription_name"] = subscription["displayName"]
                            issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def enable_psql_log_disconnections(self):
        issues=[]
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                url = postgres_server_list_url.format(subscription['subscriptionId'])
                token = get_auth_token(self.credentials)
                response = rest_api_call(token, url, '2017-12-01')
                server_list = response['value']
                for server in server_list:
                    temp = dict()
                    temp["region"] = server['location']
                    id = server['id']
                    config_url = base_url + id + "/configurations"
                    token = get_auth_token(self.credentials)
                    config_response = rest_api_call(token, config_url, '2017-12-01')
                    properties_list = config_response['value']
                    for property in properties_list:
                        if property['name'] == "log_disconnections":
                            if property['properties']['value'].lower() == "off":
                                temp['status'] = "Fail"
                                temp['resource_name'] = server['name']
                                temp['resource_id'] = server['id']
                                temp["subscription_id"] = subscription['subscriptionId']
                                temp["subscription_name"] = subscription["displayName"]
                            else:
                                temp['status'] = "Pass"
                                temp['resource_name'] = server['name']
                                temp['resource_id'] = server['id']
                                temp["subscription_id"] = subscription['subscriptionId']
                                temp["subscription_name"] = subscription["displayName"]
                            issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def enable_psql_log_duration(self):
        issues=[]
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                url = postgres_server_list_url.format(subscription['subscriptionId'])
                token = get_auth_token(self.credentials)
                response = rest_api_call(token, url, '2017-12-01')
                server_list = response['value']
                for server in server_list:
                    temp = dict()
                    temp["region"] = server['location']
                    id = server['id']
                    config_url = base_url + id + "/configurations"
                    token = get_auth_token(self.credentials)
                    config_response = rest_api_call(token, config_url, '2017-12-01')
                    properties_list = config_response['value']
                    for property in properties_list:
                        if property['name'] == "log_duration":
                            if property['properties']['value'].lower() == "off":
                                temp['status'] = "Fail"
                                temp['resource_name'] = server['name']
                                temp['resource_id'] = server['id']
                                temp["subscription_id"] = subscription['subscriptionId']
                                temp["subscription_name"] = subscription["displayName"]
                            else:
                                temp['status'] = "Pass"
                                temp['resource_name'] = server['name']
                                temp['resource_id'] = server['id']
                                temp["subscription_id"] = subscription['subscriptionId']
                                temp["subscription_name"] = subscription["displayName"]
                            issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def enable_psql_ssl_enforcement(self):
        issues=[]
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                url = postgres_server_list_url.format(subscription['subscriptionId'])
                token = get_auth_token(self.credentials)
                response = rest_api_call(token, url, '2017-12-01')
                server_list = response['value']
                for server in server_list:
                    temp = dict()
                    temp["region"] = server['location']
                    if server["properties"]["sslEnforcement"] == "Enabled":
                        temp["status"] = "Pass"
                        temp["resource_name"] = server['name']
                        temp["resource_id"] = server['id']
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]
                    else:
                        temp["status"] = "Fail"
                        temp["resource_name"] = server['name']
                        temp["resource_id"] = server['id']
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]
                    issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def sql_audit_retension_priod(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                url = sql_server_list_url.format(subscription['subscriptionId'])
                token = get_auth_token(self.credentials)
                response = rest_api_call(token, url, '2015-05-01-preview')
                server_list = response['value']
                for server in server_list:
                    temp = dict()
                    temp["region"] = server["location"]
                    temp["subscription_id"] = subscription['subscriptionId']
                    temp["subscription_name"] = subscription["displayName"]

                    audit_url = base_url + server['id'] + "/auditingSettings/default"
                    token = get_auth_token(self.credentials)
                    audit_response = rest_api_call(token, audit_url, '2017-03-01-preview')
                    retension_days = audit_response['properties']['retentionDays']
                    if retension_days <= 0:
                        temp["status"] = "Fail"
                        temp["resource_name"] = server["name"]
                        temp["resource_id"] = server["id"]
                    elif retension_days < 90:
                        temp["status"] = "Fail"
                        temp["resource_name"] = server["name"]
                        temp["resource_id"] = server["id"]
                    else:
                        temp["status"] = "Pass"
                        temp["resource_name"] = server["name"]
                        temp["resource_id"] = server["id"]

                    issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def sql_enable_audit_action_group(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                url = sql_server_list_url.format(subscription['subscriptionId'])
                token = get_auth_token(self.credentials)
                response = rest_api_call(token, url, '2015-05-01-preview')
                server_list = response['value']
                for server in server_list:
                    temp = dict()
                    temp["region"] = server['location']
                    temp["subscription_id"] = subscription['subscriptionId']
                    temp["subscription_name"] = subscription["displayName"]

                    audit_url = base_url + server['id'] + "/auditingSettings/default"
                    token = get_auth_token(self.credentials)
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
                    else:
                        temp["status"] = "Pass"
                        temp["resource_name"] = server["name"]
                        temp["resource_id"] = server["id"]

                    issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def enable_sql_threat_detection(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                url = sql_server_list_url.format(subscription['subscriptionId'])
                token = get_auth_token(self.credentials)
                response = rest_api_call(token, url, '2019-06-01-preview')
                server_list = response['value']
                for server in server_list:
                    temp = dict()
                    temp["region"] = server['location']
                    temp["subscription_id"] = subscription['subscriptionId']
                    temp["subscription_name"] = subscription["displayName"]
                    audit_url = base_url + server['id'] + "/securityAlertPolicies/default"
                    token = get_auth_token(self.credentials)
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
                    else:
                        temp["status"] = "Fail"
                        temp["resource_name"] = server["name"]
                        temp["resource_id"] = server["id"]
                    issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def sql_enable_auditing(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                url = sql_server_list_url.format(subscription['subscriptionId'])
                token = get_auth_token(self.credentials)
                response = rest_api_call(token, url, '2015-05-01-preview')
                server_list = response['value']
                for server in server_list:
                    temp = dict()
                    temp["region"] = server['location']
                    temp["subscription_id"] = subscription['subscriptionId']
                    temp["subscription_name"] = subscription["displayName"]
                    audit_url = base_url + server['id'] + "/auditingSettings/AuditState"
                    token = get_auth_token(self.credentials)
                    audit_response = rest_api_call(token, audit_url, '2017-03-01-preview')
                    if audit_response['properties']['state'] == "Disabled":
                        temp["status"] = "Fail"
                        temp["resource_name"] = server["name"]
                        temp["resource_id"] = server["id"]
                    else:
                        temp["status"] = "Pass"
                        temp["resource_name"] = server["name"]
                        temp["resource_id"] = server["id"]
                    issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def enable_sql_threat_email_notification_admins(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                url = sql_server_list_url.format(subscription['subscriptionId'])
                token = get_auth_token(self.credentials)
                response = rest_api_call(token, url, '2015-05-01-preview')
                server_list = response['value']
                for server in server_list:
                    temp = dict()
                    temp["region"] = server['location']
                    temp["subscription_id"] = subscription['subscriptionId']
                    temp["subscription_name"] = subscription["displayName"]
                    audit_url = base_url + server['id'] + "/securityAlertPolicies/default"
                    token = get_auth_token(self.credentials)
                    audit_response = rest_api_call(token, audit_url, '2019-06-01-preview')
                    if audit_response['properties']['emailAccountAdmins']:
                        temp["status"] = "Pass"
                        temp["resource_name"] = server["name"]
                        temp["resource_id"] = server["id"]
                    else:
                        temp["status"] = "Fail"
                        temp["resource_name"] = server["name"]
                        temp["resource_id"] = server["id"]
                    issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def enable_sql_threat_email_notification(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                url = sql_server_list_url.format(subscription['subscriptionId'])
                token = get_auth_token(self.credentials)
                response = rest_api_call(token, url, '2015-05-01-preview')
                server_list = response['value']
                for server in server_list:
                    temp = dict()
                    temp["region"] = server['location']
                    temp["subscription_id"] = subscription['subscriptionId']
                    temp["subscription_name"] = subscription["displayName"]
                    audit_url = base_url + server['id'] + "/securityAlertPolicies/default"
                    token = get_auth_token(self.credentials)
                    audit_response = rest_api_call(token, audit_url, '2019-06-01-preview')
                    if len(audit_response['properties']['emailAddresses']) <= 1 and audit_response['properties']['emailAddresses'][0] == '':
                        temp["status"] = "Fail"
                        temp["resource_name"] = server["name"]
                        temp["resource_id"] = server["id"]
                    else:
                        temp["status"] = "Pass"
                        temp["resource_name"] = server["name"]
                        temp["resource_id"] = server["id"]
                    issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def sql_rest_encryption(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                url = sql_server_list_url.format(subscription['subscriptionId'])
                token = get_auth_token(self.credentials)
                response = rest_api_call(token, url, '2015-05-01-preview')
                server_list = response['value']
                for server in server_list:
                    temp = dict()
                    temp["region"] = server['location']
                    temp["subscription_id"] = subscription['subscriptionId']
                    temp["subscription_name"] = subscription["displayName"]
                    db_url = base_url + server['id'] + "/databases"
                    token = get_auth_token(self.credentials)
                    db_response = rest_api_call(token, db_url, '2019-06-01-preview')
                    db_list = db_response['value']
                    for db in db_list:
                        tde_url = base_url + db['id'] + "/transparentDataEncryption/current"
                        token = get_auth_token(self.credentials)
                        tde_response = rest_api_call(token, tde_url, '2014-04-01')
                        print(tde_response)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def mysql_encryption(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                url = mysql_server_list_url.format(subscription['subscriptionId'])
                token = get_auth_token(self.credentials)
                response = rest_api_call(token, url,'2017-12-01')
                server_list = response['value']
                for server in server_list:
                    temp = dict()
                    temp["region"] = server['location']
                    temp["subscription_id"] = subscription['subscriptionId']
                    temp["subscription_name"] = subscription["displayName"]
                    if server["properties"]["sslEnforcement"] == "Enabled":
                        temp["status"] = "Pass"
                        temp["resource_name"] = server['name']
                        temp["resource_id"] = server['id']
                    else:
                        temp["status"] = "Fail"
                        temp["resource_name"] = server['name']
                        temp["resource_id"] = server['id']
                    issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues