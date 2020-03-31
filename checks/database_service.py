from checks.common_services import CommonServices
from helper_function import rest_api_call
from constants import *


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
                response = rest_api_call(self.credentials, url, '2017-12-01')
                server_list = response['value']
                for server in server_list:
                    temp = dict()
                    temp["region"] = server['location']
                    id = server['id']
                    config_url = base_url + id + "/configurations"
                    config_response = rest_api_call(self.credentials, config_url, '2017-12-01')
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
                response = rest_api_call(self.credentials, url, '2017-12-01')
                server_list = response['value']
                for server in server_list:
                    temp = dict()
                    temp["region"] = server['location']
                    id = server['id']
                    config_url = base_url + id + "/configurations"
                    config_response = rest_api_call(self.credentials, config_url, '2017-12-01')
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
                response = rest_api_call(self.credentials, url, '2017-12-01')
                server_list = response['value']
                for server in server_list:
                    temp = dict()
                    temp["region"] = server['location']
                    id = server['id']
                    config_url = base_url + id + "/configurations"
                    config_response = rest_api_call(self.credentials, config_url, '2017-12-01')
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
                response = rest_api_call(self.credentials, url, '2017-12-01')
                server_list = response['value']
                for server in server_list:
                    temp = dict()
                    temp["region"] = server['location']
                    id = server['id']
                    config_url = base_url + id + "/configurations"
                    config_response = rest_api_call(self.credentials, config_url, '2017-12-01')
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
                response = rest_api_call(self.credentials, url, '2017-12-01')
                server_list = response['value']
                for server in server_list:
                    temp = dict()
                    temp["region"] = server['location']
                    id = server['id']
                    config_url = base_url + id + "/configurations"
                    config_response = rest_api_call(self.credentials, config_url, '2017-12-01')
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
                response = rest_api_call(self.credentials, url, '2017-12-01')
                server_list = response['value']
                for server in server_list:
                    temp = dict()
                    temp["region"] = server['location']
                    id = server['id']
                    config_url = base_url + id + "/configurations"
                    config_response = rest_api_call(self.credentials, config_url, '2017-12-01')
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
                response = rest_api_call(self.credentials, url, '2017-12-01')
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
                response = rest_api_call(self.credentials, url, '2015-05-01-preview')
                server_list = response['value']
                for server in server_list:
                    temp = dict()
                    temp["region"] = server["location"]
                    temp["subscription_id"] = subscription['subscriptionId']
                    temp["subscription_name"] = subscription["displayName"]

                    audit_url = base_url + server['id'] + "/auditingSettings/default"
                    audit_response = rest_api_call(self.credentials, audit_url, '2017-03-01-preview')
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
                response = rest_api_call(self.credentials, url, '2015-05-01-preview')
                server_list = response['value']
                for server in server_list:
                    temp = dict()
                    temp["region"] = server['location']
                    temp["subscription_id"] = subscription['subscriptionId']
                    temp["subscription_name"] = subscription["displayName"]

                    audit_url = base_url + server['id'] + "/auditingSettings/default"
                    audit_response = rest_api_call(self.credentials, audit_url, '2017-03-01-preview')
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
                response = rest_api_call(self.credentials, url, '2019-06-01-preview')
                server_list = response['value']
                for server in server_list:
                    temp = dict()
                    temp["region"] = server['location']
                    temp["subscription_id"] = subscription['subscriptionId']
                    temp["subscription_name"] = subscription["displayName"]
                    audit_url = base_url + server['id'] + "/securityAlertPolicies/default"
                    audit_response = rest_api_call(self.credentials, audit_url, '2019-06-01-preview')
                    if len(
                            audit_response
                                    .get("properties", {})
                                    .get("disabledAlerts", [])
                            ) == 0 or \
                            len(audit_response[0]) == 0:

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
                response = rest_api_call(self.credentials, url, '2015-05-01-preview')
                server_list = response['value']
                for server in server_list:
                    temp = dict()
                    temp["region"] = server['location']
                    temp["subscription_id"] = subscription['subscriptionId']
                    temp["subscription_name"] = subscription["displayName"]
                    audit_url = base_url + server['id'] + "/auditingSettings/AuditState"
                    audit_response = rest_api_call(self.credentials, audit_url, '2017-03-01-preview')
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
                response = rest_api_call(self.credentials, url, '2015-05-01-preview')
                server_list = response['value']
                for server in server_list:
                    temp = dict()
                    temp["region"] = server['location']
                    temp["subscription_id"] = subscription['subscriptionId']
                    temp["subscription_name"] = subscription["displayName"]
                    audit_url = base_url + server['id'] + "/securityAlertPolicies/default"
                    audit_response = rest_api_call(self.credentials, audit_url, '2019-06-01-preview')
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
                response = rest_api_call(self.credentials, url, '2015-05-01-preview')
                server_list = response['value']
                for server in server_list:
                    temp = dict()
                    temp["region"] = server['location']
                    temp["subscription_id"] = subscription['subscriptionId']
                    temp["subscription_name"] = subscription["displayName"]
                    audit_url = base_url + server['id'] + "/securityAlertPolicies/default"
                    audit_response = rest_api_call(self.credentials, audit_url, '2019-06-01-preview')['properties']
                    if len(audit_response.get('emailAddresses', [])) == 0 or \
                            (len(
                                audit_response.get('emailAddresses', [])) == 1
                                and len(audit_response.get(
                                        'emailAddresses', [''])[0]) == 0):
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

    # def sql_rest_encryption(self):
    #     issues = []
    #     try:
    #         subscription_list = self.subscription_list
    #         for subscription in subscription_list:
    #             url = sql_server_list_url.format(subscription['subscriptionId'])
    #             #             response = rest_api_call(self.credentials, url, '2015-05-01-preview')
    #             server_list = response['value']
    #             for server in server_list:
    #                 temp = dict()
    #                 temp["region"] = server['location']
    #                 db_url = base_url + server['id'] + "/databases"
    #                 #                 db_response = \
    #                     rest_api_call(self.credentials, db_url, '2019-06-01-preview')
    #                 db_list = db_response['value']
    #                 for db in db_list:
    #                     tde_url = \
    #                         "{}{}/transparentDataEncryption/current".format(
    #                             base_url,
    #                             db['id']
    #                         )
    #                     #                     tde_response = \
    #                         rest_api_call(self.credentials, tde_url, '2014-04-01')
    #                     # Skipped as the response is xml
    #
    #     except Exception as e:
    #         print(str(e))
    #     finally:
    #         return issue

    def mysql_encryption(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                url = mysql_server_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(self.credentials, url,'2017-12-01')
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

    def postgresql_log_duration_should_be_enabled(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                url = postgres_server_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(self.credentials, url, '2017-12-01')
                postgresql_server_list = response['value']
                for postgresql_server in postgresql_server_list:
                    temp = dict()
                    temp["region"] = postgresql_server["location"]
                    temp["status"] = "Pass"
                    temp["resource_name"] = postgresql_server['name']
                    temp["resource_id"] = postgresql_server['id']
                    temp["subscription_id"] = subscription['subscriptionId']
                    temp["subscription_name"] = subscription["displayName"]
                    url = base_url+postgresql_server["id"]+'/configurations'
                    response = rest_api_call(self.credentials, url, '2017-12-01')
                    log_duration_prop = (response['value'][51])["properties"]
                    log_duration_value = log_duration_prop["value"]
                    if log_duration_value == "off":
                        temp["status"] = "Fail"
                    issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def postgresql_log_checkpoint_should_be_enabled(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                url = postgres_server_list_url.format(subscription['subscriptionId'])
                response = rest_api_call(self.credentials, url, '2017-12-01')
                postgresql_server_list = response['value']
                print(postgresql_server_list)
                for postgresql_server in postgresql_server_list:
                    temp = dict()
                    temp["region"] = postgresql_server["location"]
                    temp["status"] = "Pass"
                    temp["resource_name"] = postgresql_server['name']
                    temp["resource_id"] = postgresql_server['id']
                    temp["subscription_id"] = subscription['subscriptionId']
                    temp["subscription_name"] = subscription["displayName"]
                    url = base_url + postgresql_server["id"] + '/configurations'
                    response = rest_api_call(self.credentials, url, '2017-12-01')
                    log_duration_prop = (response['value'][48])["properties"]
                    log_duration_value = log_duration_prop["value"]
                    if log_duration_value == "off":
                        temp["status"] = "Fail"
                    issues.append(temp)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def vulnerability_threat_detection_email(self):

        issues = []

        try:

            for subscription in self.subscription_list:

                servers_url = sql_server_list_url.format(
                    subscription.get("subscriptionId", ""))
                servers = rest_api_call(
                    credentials=self.credentials,
                    url=servers_url,
                    api_version="2019-06-01-preview"
                ).get("value", [])

                for server in servers:

                    if server.get("type", "") == "Microsoft.Sql/servers":
                        vulnerability_assessments_url = \
                            "{}/{}/vulnerabilityAssessments/default".format(
                                base_url,
                                server.get("id", "")
                            )

                        vulnerability_assessments = rest_api_call(
                            credentials=self.credentials,
                            url=vulnerability_assessments_url,
                            api_version="2018-06-01-preview"
                        )

                        issue = {}

                        if len(
                                vulnerability_assessments
                                    .get("properties", {})
                                    .get("recurringScans", {})
                                    .get("emails", [])
                                ) > 0:
                            issue["status"] = "Pass"
                            issue["resource_name"] = server.get("name", "NA")
                            issue["resource_id"] = server.get("id", "NA")
                            issue["problem"] = \
                                "Emails are configured in Vulnerability " \
                                "Assessment settings for SQL server {} to " \
                                "receive scan reports.".format(
                                    server.get("name", "NA"))
                        else:
                            issue["status"] = "Fail"
                            issue["resource_name"] = server.get("name", "NA")
                            issue["resource_id"] = server.get("id", "NA")
                            issue["problem"] = \
                                "No emails are configured in Vulnerability " \
                                "Assessment settings for SQL server {} to " \
                                "receive scan reports.".format(
                                    server.get("name", "NA"))

                        issues.append(issue)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def sql_server_tde_byok(self):

        issues = []

        try:

            for subscription in self.subscription_list:

                servers_url = sql_server_list_url.format(
                    subscription.get("subscriptionId", ""))
                servers = rest_api_call(
                    credentials=self.credentials,
                    url=servers_url,
                    api_version="2019-06-01-preview"
                ).get("value", [])

                for server in servers:

                    if server.get("type", "") == "Microsoft.Sql/servers":
                        encryption_protector_url = \
                            "{}/{}/encryptionProtector/current".format(
                                base_url,
                                server.get("id", "")
                            )

                        encryption_protector = rest_api_call(
                            credentials=self.credentials,
                            url=encryption_protector_url,
                            api_version="2015-05-01-preview"
                        )

                        issue = {}

                        if encryption_protector\
                                .get("properties", {})\
                                .get("serverKeyType", "") == "AzureKeyVault" \
                                and len(
                                encryption_protector
                                    .get("properties", {})
                                    .get("uri", "")
                                ) > 0:
                            issue["status"] = "Pass"
                            issue["resource_name"] = server.get("name", "NA")
                            issue["resource_id"] = server.get("id", "NA")
                            issue["problem"] = \
                                "SQL server {} TDE protector is encrypted " \
                                "with your own key".format(
                                    server.get("name", "NA"))
                        else:
                            issue["status"] = "Fail"
                            issue["resource_name"] = server.get("name", "NA")
                            issue["resource_id"] = server.get("id", "NA")
                            issue["problem"] = \
                                "SQL server {} TDE protector is NOT " \
                                "encrypted with your own key".format(
                                    server.get("name", "NA"))

                        issues.append(issue)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def sql_managed_instance_tde_byok(self):

        issues = []

        try:

            for subscription in self.subscription_list:

                instances_url = \
                    sql_server_managed_instances_list_url.format(
                        subscription.get("subscriptionId", ""))
                instances = rest_api_call(
                    credentials=self.credentials,
                    url=instances_url,
                    api_version="2019-06-01-preview"
                ).get("value", [])

                for instance in instances:

                    if instance.get("type", "") == \
                            "Microsoft.Sql/managedInstances":
                        encryption_protector_url = \
                            "{}/{}/encryptionProtector/current".format(
                                base_url,
                                instance.get("id", "")
                            )

                        encryption_protector = rest_api_call(
                            credentials=self.credentials,
                            url=encryption_protector_url,
                            api_version="2015-05-01-preview"
                        )

                        issue = {}

                        if encryption_protector\
                                .get("properties", {})\
                                .get("serverKeyType", "") == "AzureKeyVault" \
                                and len(
                                encryption_protector
                                    .get("properties", {})
                                    .get("uri", "")
                                ) > 0:
                            issue["status"] = "Pass"
                            issue["resource_name"] = instance.get("name", "NA")
                            issue["resource_id"] = instance.get("id", "NA")
                            issue["problem"] = \
                                "SQL Managed Instance {} TDE protector is " \
                                "encrypted with your own key".format(
                                    instance.get("name", "NA"))
                        else:
                            issue["status"] = "Fail"
                            issue["resource_name"] = instance.get("name", "NA")
                            issue["resource_id"] = instance.get("id", "NA")
                            issue["problem"] = \
                                "SQL Managed Instance {} TDE protector is " \
                                "NOT encrypted with your own key".format(
                                    instance.get("name", "NA"))

                        issues.append(issue)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def sql_server_virtual_endpoint(self):

        issues = []

        try:

            for subscription in self.subscription_list:

                servers_url = sql_server_list_url.format(
                    subscription.get("subscriptionId", ""))
                servers = rest_api_call(
                    credentials=self.credentials,
                    url=servers_url,
                    api_version="2019-06-01-preview"
                ).get("value", [])

                for server in servers:

                    if server.get("type", "") == "Microsoft.Sql/servers":
                        virtual_network_rules_url = \
                            "{}/{}/virtualNetworkRules".format(
                                base_url,
                                server.get("id", "")
                            )

                        virtual_network_rules = rest_api_call(
                            credentials=self.credentials,
                            url=virtual_network_rules_url,
                            api_version="2015-05-01-preview"
                        ).get("value", [])

                        issue = {}

                        is_virtual_endpoint = False
                        for rule in virtual_network_rules:
                            if len(rule.get("properties", {}).get(
                                    "virtualNetworkSubnetId", "")) > 0:
                                is_virtual_endpoint = True
                                break

                        if is_virtual_endpoint:
                            issue["status"] = "Pass"
                            issue["resource_name"] = server.get("name", "NA")
                            issue["resource_id"] = server.get("id", "NA")
                            issue["problem"] = \
                                "SQL Server {} has a virtual network service "\
                                "endpoint".format(
                                    server.get("name", "NA"))
                        else:
                            issue["status"] = "Fail"
                            issue["resource_name"] = server.get("name", "NA")
                            issue["resource_id"] = server.get("id", "NA")
                            issue["problem"] = \
                                "SQL Server {} does NOT have a virtual "\
                                "network service endpoint".format(
                                    server.get("name", "NA"))

                        issues.append(issue)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def mysql_server_virtual_endpoint(self):

        issues = []

        try:

            for subscription in self.subscription_list:

                servers_url = mysql_server_list_url.format(
                    subscription.get("subscriptionId", ""))
                servers = rest_api_call(
                    credentials=self.credentials,
                    url=servers_url,
                    api_version="2017-12-01"
                ).get("value", [])

                for server in servers:

                    if server.get("type", "") == \
                            "Microsoft.DBforMySQL/servers":
                        virtual_network_rules_url = \
                            "{}/{}/virtualNetworkRules".format(
                                base_url,
                                server.get("id", "")
                            )

                        virtual_network_rules = rest_api_call(
                            credentials=self.credentials,
                            url=virtual_network_rules_url,
                            api_version="2017-12-01"
                        ).get("value", [])

                        issue = {}

                        is_virtual_endpoint = False
                        for rule in virtual_network_rules:
                            if len(rule.get("properties", {}).get(
                                    "virtualNetworkSubnetId", "")) > 0:
                                is_virtual_endpoint = True
                                break

                        if is_virtual_endpoint:
                            issue["status"] = "Pass"
                            issue["resource_name"] = server.get("name", "NA")
                            issue["resource_id"] = server.get("id", "NA")
                            issue["problem"] = \
                                "MySQL Server {} has a virtual network service "\
                                "endpoint".format(
                                    server.get("name", "NA"))
                        else:
                            issue["status"] = "Fail"
                            issue["resource_name"] = server.get("name", "NA")
                            issue["resource_id"] = server.get("id", "NA")
                            issue["problem"] = \
                                "MySQL Server {} does NOT have a virtual "\
                                "network service endpoint".format(
                                    server.get("name", "NA"))

                        issues.append(issue)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def postgresql_server_virtual_endpoint(self):

        issues = []

        try:

            for subscription in self.subscription_list:

                servers_url = postgres_server_list_url.format(
                    subscription.get("subscriptionId", ""))
                servers = rest_api_call(
                    credentials=self.credentials,
                    url=servers_url,
                    api_version="2017-12-01"
                ).get("value", [])

                for server in servers:

                    if server.get("type", "") == \
                            "Microsoft.DBforPostgreSQL/servers":
                        virtual_network_rules_url = \
                            "{}/{}/virtualNetworkRules".format(
                                base_url,
                                server.get("id", "")
                            )

                        virtual_network_rules = rest_api_call(
                            credentials=self.credentials,
                            url=virtual_network_rules_url,
                            api_version="2017-12-01"
                        ).get("value", [])

                        issue = {}

                        is_virtual_endpoint = False
                        for rule in virtual_network_rules:
                            if len(rule.get("properties", {}).get(
                                    "virtualNetworkSubnetId", "")) > 0:
                                is_virtual_endpoint = True
                                break

                        if is_virtual_endpoint:
                            issue["status"] = "Pass"
                            issue["resource_name"] = server.get("name", "NA")
                            issue["resource_id"] = server.get("id", "NA")
                            issue["problem"] = \
                                "PostgreSQL Server {} has a virtual network "\
                                "service endpoint".format(
                                    server.get("name", "NA"))
                        else:
                            issue["status"] = "Fail"
                            issue["resource_name"] = server.get("name", "NA")
                            issue["resource_id"] = server.get("id", "NA")
                            issue["problem"] = \
                                "PostgreSQL Server {} does NOT have a "\
                                "virtual network service endpoint".format(
                                    server.get("name", "NA"))

                        issues.append(issue)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def sql_managed_instance_admin_email_active(self):

        issues = []

        try:

            for subscription in self.subscription_list:

                instances_url = sql_server_managed_instances_list_url.format(
                    subscription.get("subscriptionId", ""))
                instances = rest_api_call(
                    credentials=self.credentials,
                    url=instances_url,
                    api_version="2019-06-01-preview"
                ).get("value", [])

                for instance in instances:

                    if instance.get("type", "") == \
                            "Microsoft.Sql/managedInstances":
                        security_alert_policies_url = \
                            "{}/{}/securityAlertPolicies/Default".format(
                                base_url,
                                instance.get("id", "")
                            )

                        security_alert_policies = rest_api_call(
                            credentials=self.credentials,
                            url=security_alert_policies_url,
                            api_version="2017-03-01-preview"
                        )

                        issue = {}

                        if security_alert_policies \
                                .get("properties", {}) \
                                .get("emailAccountAdmins", False):
                            issue["status"] = "Pass"
                            issue["resource_name"] = instance.get("name", "NA")
                            issue["resource_id"] = instance.get("id", "NA")
                            issue["problem"] = \
                                "Email notifications to admins and " \
                                "subscription owners is enabled in SQL " \
                                "Managed Instances {} advanced data security " \
                                "settings".format(
                                    instance.get("name", "NA"))
                        else:
                            issue["status"] = "Fail"
                            issue["resource_name"] = instance.get("name", "NA")
                            issue["resource_id"] = instance.get("id", "NA")
                            issue["problem"] = \
                                "Email notifications to admins and " \
                                "subscription owners is NOT enabled in SQL " \
                                "Managed Instances {} advanced data security " \
                                "settings".format(
                                    instance.get("name", "NA"))

                        issues.append(issue)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def sql_managed_instance_admin_email_available(self):

        issues = []

        try:

            for subscription in self.subscription_list:

                instances_url = sql_server_managed_instances_list_url.format(
                    subscription.get("subscriptionId", ""))
                instances = rest_api_call(
                    credentials=self.credentials,
                    url=instances_url,
                    api_version="2019-06-01-preview"
                ).get("value", [])

                for instance in instances:

                    if instance.get("type", "") == \
                            "Microsoft.Sql/managedInstances":
                        security_alert_policies_url = \
                            "{}/{}/securityAlertPolicies/Default".format(
                                base_url,
                                instance.get("id", "")
                            )

                        security_alert_policies = rest_api_call(
                            credentials=self.credentials,
                            url=security_alert_policies_url,
                            api_version="2017-03-01-preview"
                        )

                        issue = {}

                        if len(
                                security_alert_policies
                                    .get('properties', {})
                                    .get('emailAddresses', [])) == 1 \
                                or (len(
                                        security_alert_policies
                                            .get('properties', {})
                                            .get('emailAddresses', [])) == 1
                                    and security_alert_policies
                                            .get('properties', {})
                                            .get('emailAddresses', [])[0] == ''
                        ):
                            issue["status"] = "Pass"
                            issue["resource_name"] = instance.get("name", "NA")
                            issue["resource_id"] = instance.get("id", "NA")
                            issue["problem"] = \
                                "Advanced data security settings for SQL " \
                                "managed instance {} has email address to " \
                                "receive security alerts".format(
                                    instance.get("name", "NA"))
                        else:
                            issue["status"] = "Fail"
                            issue["resource_name"] = instance.get("name", "NA")
                            issue["resource_id"] = instance.get("id", "NA")
                            issue["problem"] = \
                                "Advanced data security settings for SQL " \
                                "managed instance {} does NOT have any email " \
                                "address to receive security alerts".format(
                                    instance.get("name", "NA"))

                        issues.append(issue)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def data_security_managed_instance_status(self):

        issues = []

        try:

            for subscription in self.subscription_list:

                instances_url = sql_server_managed_instances_list_url.format(
                    subscription.get("subscriptionId", ""))
                instances = rest_api_call(
                    credentials=self.credentials,
                    url=instances_url,
                    api_version="2019-06-01-preview"
                ).get("value", [])

                for instance in instances:

                    if instance.get("type", "") == \
                            "Microsoft.Sql/managedInstances":
                        security_alert_policies_url = \
                            "{}/{}/securityAlertPolicies/Default".format(
                                base_url,
                                instance.get("id", "")
                            )

                        security_alert_policies = rest_api_call(
                            credentials=self.credentials,
                            url=security_alert_policies_url,
                            api_version="2017-03-01-preview"
                        )

                        issue = {}

                        if security_alert_policies\
                                .get("properties", {})\
                                .get("state", "Disabled") != "Disabled":
                            issue["status"] = "Pass"
                            issue["resource_name"] = instance.get("name", "NA")
                            issue["resource_id"] = instance.get("id", "NA")
                            issue["problem"] = \
                                "Advanced data security is enabled on your " \
                                "SQL managed instance {}".format(
                                    instance.get("name", "NA"))
                        else:
                            issue["status"] = "Fail"
                            issue["resource_name"] = instance.get("name", "NA")
                            issue["resource_id"] = instance.get("id", "NA")
                            issue["problem"] = \
                                "Advanced data security is enabled on your " \
                                "SQL managed instance {}".format(
                                    instance.get("name", "NA"))

                        issues.append(issue)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def threat_protection_type_managed_instance(self):

        issues = []

        try:

            for subscription in self.subscription_list:

                instances_url = sql_server_managed_instances_list_url.format(
                    subscription.get("subscriptionId", ""))
                instances = rest_api_call(
                    credentials=self.credentials,
                    url=instances_url,
                    api_version="2019-06-01-preview"
                ).get("value", [])

                for instance in instances:

                    if instance.get("type", "") == \
                            "Microsoft.Sql/managedInstances":
                        security_alert_policies_url = \
                            "{}/{}/securityAlertPolicies/Default".format(
                                base_url,
                                instance.get("id", "")
                            )

                        security_alert_policies = rest_api_call(
                            credentials=self.credentials,
                            url=security_alert_policies_url,
                            api_version="2017-03-01-preview"
                        )

                        issue = {}

                        if len(
                                security_alert_policies
                                        .get("properties", {})
                                        .get("disabledAlerts", [])
                                ) == 0 or \
                                len(security_alert_policies[0]) == 0:
                            issue["status"] = "Pass"
                            issue["resource_name"] = instance.get("name", "NA")
                            issue["resource_id"] = instance.get("id", "NA")
                            issue["problem"] = \
                                "Advanced Threat Protection types is 'All' " \
                                "in SQL managed instance {} Advanced Data " \
                                "Security settings".format(
                                    instance.get("name", "NA"))
                        else:
                            issue["status"] = "Fail"
                            issue["resource_name"] = instance.get("name", "NA")
                            issue["resource_id"] = instance.get("id", "NA")
                            issue["problem"] = \
                                "Advanced Threat Protection types is NOT " \
                                "'All' in SQL managed instance {} Advanced " \
                                "Data Security settings".format(
                                    instance.get("name", "NA"))

                        issues.append(issue)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    # def azure_ad_admin_sql_servers(self):
    #
    #     issues = []
    #
    #     try:
    #
    #         for subscription in self.subscription_list:
    #
    #             servers_url = sql_server_list_url.format(
    #                 subscription.get("subscriptionId", ""))
    #             #
    #             servers = rest_api_call(
    #                 credentials=self.credentials,
    #                 url=servers_url,
    #                 api_version="2019-06-01-preview"
    #             ).get("value", [])
    #
    #             for server in servers:
    #
    #                 if server.get("type", "") == "Microsoft.Sql/servers":
    #                     sql_server_admin_url = \
    #                         "{}/{}/administrators".format(
    #                             base_url,
    #                             server.get("id", "")
    #                         )
    #
    #                     sql_server_admin = rest_api_call(
    #                         credentials=self.credentials,
    #                         url=sql_server_admin_url,
    #                         api_version="2014-04-01"
    #                     ).get("value", [])
    #
    #                     issue = {}
    #
    #                     if len(sql_server_admin) == 0:
    #                         issue["status"] = "Pass"
    #                         issue["resource_name"] = server.get("name", "NA")
    #                         issue["resource_id"] = server.get("id", "NA")
    #                         issue["problem"] = \
    #                             "An Azure Active Directory administrator is " \
    #                             "provisioned for SQL server {}".format(
    #                                 server.get("name", "NA"))
    #                     else:
    #                         issue["status"] = "Fail"
    #                         issue["resource_name"] = server.get("name", "NA")
    #                         issue["resource_id"] = server.get("id", "NA")
    #                         issue["problem"] = \
    #                             "An Azure Active Directory administrator is " \
    #                             "NOT provisioned for SQL server {}".format(
    #                                 server.get("name", "NA"))
    #
    #                     issues.append(issue)
    #     except Exception as e:
    #         print(str(e))
    #     finally:
    #         return issues

    def audit_sql_server(self):

        issues = []

        try:

            for subscription in self.subscription_list:

                servers_url = sql_server_list_url.format(
                    subscription.get("subscriptionId", ""))
                servers = rest_api_call(
                    credentials=self.credentials,
                    url=servers_url,
                    api_version="2019-06-01-preview"
                ).get("value", [])

                for server in servers:

                    if server.get("type", "") == "Microsoft.Sql/servers":
                        sql_audit_settings_url = \
                            "{}/{}/auditingSettings/default".format(
                                base_url,
                                server.get("id", "")
                            )

                        sql_audit_settings = rest_api_call(
                            credentials=self.credentials,
                            url=sql_audit_settings_url,
                            api_version="2017-03-01-preview"
                        )

                        issue = {}

                        if sql_audit_settings\
                                .get("properties", {})\
                                .get("state", "Disabled") != "Disabled":
                            issue["status"] = "Pass"
                            issue["resource_name"] = server.get("name", "NA")
                            issue["resource_id"] = server.get("id", "NA")
                            issue["problem"] = \
                                "Auditing on SQL server {} should is " \
                                "enabled".format(
                                    server.get("name", "NA"))
                        else:
                            issue["status"] = "Fail"
                            issue["resource_name"] = server.get("name", "NA")
                            issue["resource_id"] = server.get("id", "NA")
                            issue["problem"] = \
                                "Auditing on SQL server {} should is NOT " \
                                "enabled".format(
                                    server.get("name", "NA"))

                        issues.append(issue)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def geo_redundant_backup_sql(self):

        issues = []

        try:

            for subscription in self.subscription_list:

                servers_url = sql_server_list_url.format(
                    subscription.get("subscriptionId", ""))
                servers = rest_api_call(
                    credentials=self.credentials,
                    url=servers_url,
                    api_version="2019-06-01-preview"
                ).get("value", [])

                for server in servers:

                    if server.get("type", "") == "Microsoft.Sql/servers":

                        db_url = "{}/{}/databases".format(
                                base_url,
                                server.get("id", "")
                        )

                        databases = rest_api_call(
                            credentials=self.credentials,
                            url=db_url,
                            api_version="2017-03-01-preview"
                        ).get("value", {})

                        for db in databases:
                            if "master" == db.get("name", ""):
                                continue

                            sql_backup_policy_url = \
                                "{}/{}/backupLongTermRetentionPolicies/" \
                                "default".format(
                                    base_url,
                                    db.get("id", "")
                                )

                            sql_backup_policy = rest_api_call(
                                credentials=self.credentials,
                                url=sql_backup_policy_url,
                                api_version="2017-03-01-preview"
                            ).get("properties", {})

                            issue = {}

                            if "PT0S" not in [
                                sql_backup_policy.get("weeklyRetention",
                                                      "PT0S"),
                                sql_backup_policy.get("monthlyRetention",
                                                      "PT0S"),
                                sql_backup_policy.get("yearlyRetention",
                                                      "PT0S")
                            ]:
                                issue["status"] = "Pass"
                                issue["resource_name"] = \
                                    server.get("name", "NA")
                                issue["resource_id"] = \
                                    server.get("id", "NA")
                                issue["problem"] = \
                                    "Long-term geo-redundant backup is " \
                                    "enabled for Azure SQL Database {}".format(
                                        server.get("name", "NA"))
                            else:
                                issue["status"] = "Fail"
                                issue["resource_name"] = \
                                    server.get("name", "NA")
                                issue["resource_id"] = \
                                    server.get("id", "NA")
                                issue["problem"] = \
                                    "Long-term geo-redundant backup is NOT " \
                                    "enabled for Azure SQL Database {}".format(
                                        server.get("name", "NA"))

                            issues.append(issue)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def geo_redundant_backup_mariadb(self):

        issues = []

        try:

            for subscription in self.subscription_list:

                servers_url = mariadb_server_list_url.format(
                    subscription.get("subscriptionId", ""))
                servers = rest_api_call(
                    credentials=self.credentials,
                    url=servers_url,
                    api_version="2018-06-01"
                ).get("value", [])

                for server in servers:

                    if server.get("type", "") == \
                            "Microsoft.DBforMariaDB/servers":

                        issue = {}

                        if "Enabled" == server\
                                .get("properties", {})\
                                .get("storageProfile", {})\
                                .get("geoRedundantBackup", "Disabled"):
                            issue["status"] = "Pass"
                            issue["resource_name"] = server.get("name", "NA")
                            issue["resource_id"] = server.get("id", "NA")
                            issue["problem"] = \
                                "Geo-redundant backup is enabled for Azure " \
                                "Database for MariaDB {}".format(
                                    server.get("name", "NA"))
                        else:
                            issue["status"] = "Fail"
                            issue["resource_name"] = server.get("name", "NA")
                            issue["resource_id"] = server.get("id", "NA")
                            issue["problem"] = \
                                "Geo-redundant backup is NOT enabled for " \
                                "Azure Database for MariaDB {}".format(
                                    server.get("name", "NA"))

                        issues.append(issue)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def geo_redundant_backup_mysql(self):

        issues = []

        try:

            for subscription in self.subscription_list:

                servers_url = mysql_server_list_url.format(
                    subscription.get("subscriptionId", ""))
                servers = rest_api_call(
                    credentials=self.credentials,
                    url=servers_url,
                    api_version="2017-12-01"
                ).get("value", [])

                for server in servers:

                    if server.get("type", "") == \
                            "Microsoft.DBforMySQL/servers":

                        issue = {}

                        if "Enabled" == server\
                                .get("properties", {})\
                                .get("storageProfile", {})\
                                .get("geoRedundantBackup", "Disabled"):
                            issue["status"] = "Pass"
                            issue["resource_name"] = server.get("name", "NA")
                            issue["resource_id"] = server.get("id", "NA")
                            issue["problem"] = \
                                "Geo-redundant backup is enabled for Azure " \
                                "Database for MySQL {}".format(
                                    server.get("name", "NA"))
                        else:
                            issue["status"] = "Fail"
                            issue["resource_name"] = server.get("name", "NA")
                            issue["resource_id"] = server.get("id", "NA")
                            issue["problem"] = \
                                "Geo-redundant backup is NOT enabled for " \
                                "Azure Database for MySQL {}".format(
                                    server.get("name", "NA"))

                        issues.append(issue)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def geo_redundant_backup_postgresql(self):

        issues = []

        try:

            for subscription in self.subscription_list:

                servers_url = postgres_server_list_url.format(
                    subscription.get("subscriptionId", ""))
                servers = rest_api_call(
                    credentials=self.credentials,
                    url=servers_url,
                    api_version="2017-12-01"
                ).get("value", [])

                for server in servers:

                    if server.get("type", "") == \
                            "Microsoft.DBforPostgreSQL/servers":

                        issue = {}

                        if "Enabled" == server\
                                .get("properties", {})\
                                .get("storageProfile", {})\
                                .get("geoRedundantBackup", "Disabled"):
                            issue["status"] = "Pass"
                            issue["resource_name"] = server.get("name", "NA")
                            issue["resource_id"] = server.get("id", "NA")
                            issue["problem"] = \
                                "Geo-redundant backup is enabled for Azure " \
                                "Database for PostgreSQL {}".format(
                                    server.get("name", "NA"))
                        else:
                            issue["status"] = "Fail"
                            issue["resource_name"] = server.get("name", "NA")
                            issue["resource_id"] = server.get("id", "NA")
                            issue["problem"] = \
                                "Geo-redundant backup is NOT enabled for " \
                                "Azure Database for PostgreSQL {}".format(
                                    server.get("name", "NA"))

                        issues.append(issue)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def mariadb_server_virtual_endpoint(self):

        issues = []

        try:

            for subscription in self.subscription_list:

                servers_url = mariadb_server_list_url.format(
                    subscription.get("subscriptionId", ""))
                servers = rest_api_call(
                    credentials=self.credentials,
                    url=servers_url,
                    api_version="2018-06-01"
                ).get("value", [])

                for server in servers:

                    if server.get("type", "") == \
                            "Microsoft.DBforMariaDB/servers":
                        virtual_network_rules_url = \
                            "{}/{}/virtualNetworkRules".format(
                                base_url,
                                server.get("id", "")
                            )

                        virtual_network_rules = rest_api_call(
                            credentials=self.credentials,
                            url=virtual_network_rules_url,
                            api_version="2018-06-01-preview"
                        )

                        issue = {}

                        is_virtual_endpoint = False
                        for rule in virtual_network_rules:
                            if len(rule.get("properties", {}).get(
                                    "virtualNetworkSubnetId", "")) > 0:
                                is_virtual_endpoint = True
                                break

                        if is_virtual_endpoint:
                            issue["status"] = "Pass"
                            issue["resource_name"] = server.get("name", "NA")
                            issue["resource_id"] = server.get("id", "NA")
                            issue["problem"] = \
                                "MariaDB Server {} has a virtual network "\
                                "service endpoint".format(
                                    server.get("name", "NA"))
                        else:
                            issue["status"] = "Fail"
                            issue["resource_name"] = server.get("name", "NA")
                            issue["resource_id"] = server.get("id", "NA")
                            issue["problem"] = \
                                "MariaDB Server {} does NOT have a virtual "\
                                "network service endpoint".format(
                                    server.get("name", "NA"))

                        issues.append(issue)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def sql_server_vulnerability_assessment(self):

        issues = []

        try:

            for subscription in self.subscription_list:

                servers_url = sql_server_list_url.format(
                    subscription.get("subscriptionId", ""))
                servers = rest_api_call(
                    credentials=self.credentials,
                    url=servers_url,
                    api_version="2019-06-01-preview"
                ).get("value", [])

                for server in servers:

                    if server.get("type", "") == "Microsoft.Sql/servers":
                        vulnerability_assessments_url = \
                            "{}/{}/vulnerabilityAssessments".format(
                                base_url,
                                server.get("id", "")
                            )

                        vulnerability_assessments = rest_api_call(
                            credentials=self.credentials,
                            url=vulnerability_assessments_url,
                            api_version="2018-06-01-preview"
                        ).get("value", [])

                        issue = {}

                        is_vulnerability_assessment = False

                        for item in vulnerability_assessments:

                            if not item.get("properties", {})\
                                    .get("recurringScans", {})\
                                    .get("isEnabled", False):
                                break
                        else:
                            is_vulnerability_assessment = True

                        if is_vulnerability_assessment:
                            issue["status"] = "Pass"
                            issue["resource_name"] = server.get("name", "NA")
                            issue["resource_id"] = server.get("id", "NA")
                            issue["problem"] = \
                                "Vulnerability assessment is enabled on " \
                                "SQL server {}".format(
                                    server.get("name", "NA"))
                        else:
                            issue["status"] = "Fail"
                            issue["resource_name"] = server.get("name", "NA")
                            issue["resource_id"] = server.get("id", "NA")
                            issue["problem"] = \
                                "Vulnerability assessment is NOT enabled on " \
                                "SQL server {}".format(
                                    server.get("name", "NA"))

                        issues.append(issue)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def sql_managed_instance_vulnerability_assessment(self):

        issues = []

        try:

            for subscription in self.subscription_list:

                instances_url = sql_server_managed_instances_list_url.format(
                    subscription.get("subscriptionId", ""))
                instances = rest_api_call(
                    credentials=self.credentials,
                    url=instances_url,
                    api_version="2019-06-01-preview"
                ).get("value", [])

                for instance in instances:

                    if instance.get("type", "") == \
                            "Microsoft.Sql/managedInstances":
                        vulnerability_assessments_url = \
                            "{}/{}/vulnerabilityAssessments".format(
                                base_url,
                                server.get("id", "")
                            )

                        vulnerability_assessments = rest_api_call(
                            credentials=self.credentials,
                            url=vulnerability_assessments_url,
                            api_version="2018-06-01-preview"
                        ).get("value", [])

                        issue = {}

                        is_vulnerability_assessment = False

                        for item in vulnerability_assessments:

                            if not item.get("properties", {})\
                                    .get("recurringScans", {})\
                                    .get("isEnabled", False):
                                break
                        else:
                            is_vulnerability_assessment = True

                        if is_vulnerability_assessment:
                            issue["status"] = "Pass"
                            issue["resource_name"] = instance.get("name", "NA")
                            issue["resource_id"] = instance.get("id", "NA")
                            issue["problem"] = \
                                "Vulnerability assessment is enabled on " \
                                "SQL server {}".format(
                                    instance.get("name", "NA"))
                        else:
                            issue["status"] = "Fail"
                            issue["resource_name"] = instance.get("name", "NA")
                            issue["resource_id"] = instance.get("id", "NA")
                            issue["problem"] = \
                                "Vulnerability assessment is NOT enabled on " \
                                "SQL server {}".format(
                                    instance.get("name", "NA"))

                        issues.append(issue)
        except Exception as e:
            print(str(e))
        finally:
            return issues

    def data_security_sql_server_status(self):

        issues = []

        try:

            for subscription in self.subscription_list:

                servers_url = sql_server_list_url.format(
                    subscription.get("subscriptionId", ""))
                servers = rest_api_call(
                    credentials=self.credentials,
                    url=servers_url,
                    api_version="2019-06-01-preview"
                ).get("value", [])

                for server in servers:

                    if server.get("type", "") == "Microsoft.Sql/servers":
                        security_alert_policies_url = \
                            "{}/{}/securityAlertPolicies/Default".format(
                                base_url,
                                server.get("id", "")
                            )

                        security_alert_policies = rest_api_call(
                            credentials=self.credentials,
                            url=security_alert_policies_url,
                            api_version="2017-03-01-preview"
                        )

                        issue = {}

                        if security_alert_policies\
                                .get("properties", {})\
                                .get("state", "Disabled") != "Disabled":
                            issue["status"] = "Pass"
                            issue["resource_name"] = server.get("name", "NA")
                            issue["resource_id"] = server.get("id", "NA")
                            issue["problem"] = \
                                "Advanced data security is enabled on your " \
                                "SQL managed instance {}".format(
                                    server.get("name", "NA"))
                        else:
                            issue["status"] = "Fail"
                            issue["resource_name"] = server.get("name", "NA")
                            issue["resource_id"] = server.get("id", "NA")
                            issue["problem"] = \
                                "Advanced data security is enabled on your " \
                                "SQL managed instance {}".format(
                                    server.get("name", "NA"))

                        issues.append(issue)
        except Exception as e:
            print(str(e))
        finally:
            return issues
