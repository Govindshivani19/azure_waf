from helper_function import rest_api_call
from constants import base_url, app_list_url
import re
import logging as logger


class AppService:
    def __init__(self, credentials, subscription_list):
        self.credentials = credentials
        self.subscription_list = subscription_list

    def cors_function_app(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                url = app_list_url.format(subscription["subscriptionId"])
                response = rest_api_call(self.credentials, url, '2019-08-01')
                for app in response["value"]:
                    x = re.findall("functionapp*", app["kind"])
                    if x :
                        temp = dict()
                        temp["region"] = app["location"]
                        temp["status"] = "Pass"
                        temp['resource_name'] = app['name']
                        temp['resource_id'] = ""
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]

                        config_url = base_url+app["id"]+"/config/web"
                        response = rest_api_call(self.credentials, config_url, '2019-08-01')
                        try:
                            enabled_cors = response["properties"]["cors"]["allowedOrigins"]
                            for cors in enabled_cors:
                                if cors == "*":
                                    temp["status"] = "Fail"
                        except:
                            temp["status"] = "Fail"

                        issues.append(temp)
        except Exception as e:
            logger.error(e);
        finally:
            return issues

    def cors_function_api_app(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                url = app_list_url.format(subscription["subscriptionId"])
                response = rest_api_call(self.credentials, url, '2019-08-01')
                for app in response["value"]:
                    x = re.findall("api", app["kind"])
                    if x :
                        temp = dict()
                        temp["region"] = app["location"]
                        temp["status"] = "Pass"
                        temp['resource_name'] = app['name']
                        temp['resource_id'] = ""
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]

                        config_url = base_url+app["id"]+"/config/web"
                        response = rest_api_call(self.credentials, config_url, '2019-08-01')
                        try:
                            enabled_cors = response["properties"]["cors"]["allowedOrigins"]
                            for cors in enabled_cors:
                                if cors == "*":
                                    temp["status"] = "Fail"
                        except:
                            temp["status"] = "Fail"

                        issues.append(temp)
        except Exception as e:
            logger.error(e);
        finally:
            return issues

    def cors_function_web_app(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                url = app_list_url.format(subscription["subscriptionId"])
                response = rest_api_call(self.credentials, url, '2019-08-01')
                for app in response["value"]:
                    x = re.findall("app*", app["kind"])
                    if x :
                        temp = dict()
                        temp["region"] = app["location"]
                        temp["status"] = "Pass"
                        temp['resource_name'] = app['name']
                        temp['resource_id'] = ""
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]

                        config_url = base_url+app["id"]+"/config/web"
                        response = rest_api_call(self.credentials, config_url, '2019-08-01')
                        try:
                            enabled_cors = response["properties"]["cors"]["allowedOrigins"]
                            for cors in enabled_cors:
                                if cors == "*":
                                    temp["status"] = "Fail"
                        except:
                            temp["status"] = "Fail"
                        issues.append(temp)
        except Exception as e:
            logger.error(e);
        finally:
            return issues

    def min_tls_version_function_app(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                url = app_list_url.format(subscription["subscriptionId"])
                response = rest_api_call(self.credentials, url, '2019-08-01')
                for app in response["value"]:
                    x = re.findall("functionapp*", app["kind"])
                    if x :
                        temp = dict()
                        temp["region"] = app["location"]
                        temp["status"] = "Fail"
                        temp['resource_name'] = app['name']
                        temp['resource_id'] = ""
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]

                        config_url = base_url+app["id"]+"/config/web"
                        response = rest_api_call(self.credentials, config_url, '2019-08-01')
                        try:
                            tls_version = 0.0
                            if "properties" in response:
                                tls_version = response["properties"].get("minTlsVersion")
                            else:
                                tls_version = response.get("minTlsVersion")
                            if tls_version == "1.2":
                                temp["status"] = "Pass"
                        except:
                            temp["status"] = "Fail"

                        issues.append(temp)
        except Exception as e:
            logger.error(e);
        finally:
            return issues

    def min_tls_version_web_app(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                url = app_list_url.format(subscription["subscriptionId"])
                response = rest_api_call(self.credentials, url, '2019-08-01')
                for app in response["value"]:
                    x = re.findall("app*", app["kind"])
                    if x :
                        temp = dict()
                        temp["region"] = app["location"]
                        temp["status"] = "Fail"
                        temp['resource_name'] = app['name']
                        temp['resource_id'] = ""
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]

                        config_url = base_url+app["id"]+"/config/web"
                        response = rest_api_call(self.credentials, config_url, '2019-08-01')
                        try:
                            tls_version = 0.0
                            if "properties" in response:
                                tls_version = response["properties"].get("minTlsVersion")
                            else:
                                tls_version = response.get("minTlsVersion")
                            if tls_version == "1.2":
                                temp["status"] = "Pass"
                        except:
                            temp["status"] = "Fail"

                        issues.append(temp)
        except Exception as e:
            logger.error(e);
        finally:
            return issues

    def min_tls_version_api_app(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                url = app_list_url.format(subscription["subscriptionId"])
                response = rest_api_call(self.credentials, url, '2019-08-01')
                for app in response["value"]:
                    x = re.findall("api", app["kind"])
                    if x :
                        temp = dict()
                        temp["region"] = app["location"]
                        temp["status"] = "Fail"
                        temp['resource_name'] = app['name']
                        temp['resource_id'] = ""
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]

                        config_url = base_url+app["id"]+"/config/web"
                        response = rest_api_call(self.credentials, config_url, '2019-08-01')
                        try:
                            tls_version = 0.0
                            if "properties" in response:
                                tls_version = response["properties"].get("minTlsVersion")
                            else:
                                tls_version = response.get("minTlsVersion")
                            if tls_version == "1.2":
                                temp["status"] = "Pass"
                        except:
                            temp["status"] = "Fail"

                        issues.append(temp)
        except Exception as e:
            logger.error(e);
        finally:
            return issues

    def enable_client_certificates_webapp(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                url = app_list_url.format(subscription["subscriptionId"])
                response = rest_api_call(self.credentials, url, '2019-08-01')
                for app in response["value"]:
                    x = re.findall("app*", app["kind"])
                    if x:
                        temp = dict()
                        temp["region"] = app["location"]
                        temp["status"] = "Fail"
                        temp['resource_name'] = app['name']
                        temp['resource_id'] = ""
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]
                        if app["properties"]["clientCertEnabled"] is True:
                            temp["status"] = "Pass"
                        issues.append(temp)
        except Exception as e:
            logger.error(e);
        finally:
            return issues

    def enable_client_certificates_functionapp(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                url = app_list_url.format(subscription["subscriptionId"])
                response = rest_api_call(self.credentials, url, '2019-08-01')
                for app in response["value"]:
                    x = re.findall("functionapp*", app["kind"])
                    if x:
                        temp = dict()
                        temp["region"] = app["location"]
                        temp["status"] = "Fail"
                        temp['resource_name'] = app['name']
                        temp['resource_id'] = ""
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]
                        if app["properties"]["clientCertEnabled"] is True:
                            temp["status"] = "Pass"
                        issues.append(temp)
        except Exception as e:
            logger.error(e);
        finally:
            return issues

    def enable_client_certificates_apiapp(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                url = app_list_url.format(subscription["subscriptionId"])
                response = rest_api_call(self.credentials, url, '2019-08-01')
                for app in response["value"]:
                    x = re.findall("api", app["kind"])
                    if x:
                        temp = dict()
                        temp["region"] = app["location"]
                        temp["status"] = "Fail"
                        temp['resource_name'] = app['name']
                        temp['resource_id'] = ""
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]
                        if app["properties"]["clientCertEnabled"] is True:
                            temp["status"] = "Pass"
                        issues.append(temp)
        except Exception as e:
            logger.error(e);
        finally:
            return issues

    def managed_identity_web_app(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                url = app_list_url.format(subscription["subscriptionId"])
                response = rest_api_call(self.credentials, url, '2019-08-01')
                for app in response["value"]:
                    x = re.findall("app*", app["kind"])
                    if x :
                        temp = dict()
                        temp["region"] = app["location"]
                        temp["status"] = "Fail"
                        temp['resource_name'] = app['name']
                        temp['resource_id'] = ""
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]

                        config_url = base_url+app["id"]+"/config/web"
                        response = rest_api_call(self.credentials, config_url, '2019-08-01')
                        try:
                            if "properties" in response:
                                if "managedServiceIdentityId" in response["properties"]:
                                    temp["status"] = "Pass"
                            else:
                                if "managedServiceIdentityId" in response:
                                    temp["status"] = "Pass"
                        except:
                            temp["status"] = "Fail"

                        issues.append(temp)
        except Exception as e:
            logger.error(e);
        finally:
            return issues

    def managed_identity_api_app(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                url = app_list_url.format(subscription["subscriptionId"])
                response = rest_api_call(self.credentials, url, '2019-08-01')
                for app in response["value"]:
                    x = re.findall("api", app["kind"])
                    if x :
                        temp = dict()
                        temp["region"] = app["location"]
                        temp["status"] = "Fail"
                        temp['resource_name'] = app['name']
                        temp['resource_id'] = ""
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]

                        config_url = base_url+app["id"]+"/config/web"
                        response = rest_api_call(self.credentials, config_url, '2019-08-01')
                        try:
                            if "properties" in response:
                                if "managedServiceIdentityId" in response["properties"]:
                                    temp["status"] = "Pass"
                            else:
                                if "managedServiceIdentityId" in response:
                                    temp["status"] = "Pass"
                        except:
                            temp["status"] = "Fail"

                        issues.append(temp)
        except Exception as e:
            logger.error(e);
        finally:
            return issues

    def managed_identity_function_app(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                url = app_list_url.format(subscription["subscriptionId"])
                response = rest_api_call(self.credentials, url, '2019-08-01')
                for app in response["value"]:
                    x = re.findall("functionapp*", app["kind"])
                    if x:
                        temp = dict()
                        temp["region"] = app["location"]
                        temp["status"] = "Fail"
                        temp['resource_name'] = app['name']
                        temp['resource_id'] = ""
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]

                        config_url = base_url + app["id"] + "/config/web"
                        response = rest_api_call(self.credentials, config_url, '2019-08-01')
                        try:
                            if "properties" in response:
                                if "managedServiceIdentityId" in response["properties"]:
                                    temp["status"] = "Pass"
                            else:
                                if "managedServiceIdentityId" in response:
                                    temp["status"] = "Pass"
                        except:
                            temp["status"] = "Fail"

                        issues.append(temp)
        except Exception as e:
            logger.error(e);
        finally:
            return issues

    def remote_debugging_api_app(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                url = app_list_url.format(subscription["subscriptionId"])
                response = rest_api_call(self.credentials, url, '2019-08-01')
                for app in response["value"]:
                    x = re.findall("api", app["kind"])
                    if x :
                        temp = dict()
                        temp["region"] = app["location"]
                        temp["status"] = "Fail"
                        temp['resource_name'] = app['name']
                        temp['resource_id'] = ""
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]

                        config_url = base_url+app["id"]+"/config/web"
                        response = rest_api_call(self.credentials, config_url, '2019-08-01')
                        try:
                            if "properties" in response:
                                if response["properties"]["remoteDebuggingEnabled"] is True:
                                    temp["status"] = "Pass"
                            else:
                                if response["remoteDebuggingEnabled"] is True:
                                    temp["status"] = "Pass"
                        except:
                            temp["status"] = "Fail"

                        issues.append(temp)
        except Exception as e:
            logger.error(e);
        finally:
            return issues

    def remote_debugging_function_app(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                url = app_list_url.format(subscription["subscriptionId"])
                response = rest_api_call(self.credentials, url, '2019-08-01')
                for app in response["value"]:
                    x = re.findall("functionapp*", app["kind"])
                    if x :
                        temp = dict()
                        temp["region"] = app["location"]
                        temp["status"] = "Fail"
                        temp['resource_name'] = app['name']
                        temp['resource_id'] = ""
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]

                        config_url = base_url+app["id"]+"/config/web"
                        response = rest_api_call(self.credentials, config_url, '2019-08-01')
                        try:
                            if "properties" in response:
                                if response["properties"]["remoteDebuggingEnabled"] is True:
                                    temp["status"] = "Pass"
                            else:
                                if response["remoteDebuggingEnabled"] is True:
                                    temp["status"] = "Pass"
                        except:
                            temp["status"] = "Fail"

                        issues.append(temp)
        except Exception as e:
            logger.error(e);
        finally:
            return issues

    def remote_debugging_web_app(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                url = app_list_url.format(subscription["subscriptionId"])
                response = rest_api_call(self.credentials, url, '2019-08-01')
                for app in response["value"]:
                    x = re.findall("app*", app["kind"])
                    if x :
                        temp = dict()
                        temp["region"] = app["location"]
                        temp["status"] = "Fail"
                        temp['resource_name'] = app['name']
                        temp['resource_id'] = ""
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]

                        config_url = base_url+app["id"]+"/config/web"
                        response = rest_api_call(self.credentials, config_url, '2019-08-01')
                        try:
                            if "properties" in response:
                                if response["properties"]["remoteDebuggingEnabled"] is True:
                                    temp["status"] = "Pass"
                            else:
                                if response["remoteDebuggingEnabled"] is True:
                                    temp["status"] = "Pass"
                        except:
                            temp["status"] = "Fail"

                        issues.append(temp)
        except Exception as e:
            logger.error(e);
        finally:
            return issues

    def check_dotnet_version_web_app(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                url = app_list_url.format(subscription["subscriptionId"])
                response = rest_api_call(self.credentials, url, '2019-08-01')
                for app in response["value"]:
                    x = re.findall("app*", app["kind"])
                    if x:
                        temp = dict()
                        temp["region"] = app["location"]
                        temp["status"] = "Fail"
                        temp['resource_name'] = app['name']
                        temp['resource_id'] = ""
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]

                        config_url = base_url+app["id"]+"/config/web"
                        response = rest_api_call(self.credentials, config_url, '2019-08-01')
                        try:
                            version = 0.0
                            if "properties" in response:
                                version = response["properties"].get("netFrameworkVersion")
                            else:
                                version = response.get("netFrameworkVersion")
                            if version == "v3.0" or version == "v4.0":
                                temp["status"] = "Pass"
                        except:
                            temp["status"] = "Fail"

                        issues.append(temp)
        except Exception as e:
            logger.error(e);
        finally:
            return issues

    def check_dotnet_version_function_app(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                url = app_list_url.format(subscription["subscriptionId"])
                response = rest_api_call(self.credentials, url, '2019-08-01')
                for app in response["value"]:
                    x = re.findall("functionapp*", app["kind"])
                    if x :
                        temp = dict()
                        temp["region"] = app["location"]
                        temp["status"] = "Fail"
                        temp['resource_name'] = app['name']
                        temp['resource_id'] = ""
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]

                        config_url = base_url+app["id"]+"/config/web"
                        response = rest_api_call(self.credentials, config_url, '2019-08-01')
                        try:
                            version = 0.0
                            if "properties" in response:
                                version = response["properties"].get("netFrameworkVersion")
                            else:
                                version = response.get("netFrameworkVersion")
                            if version == "v3.0" or version == "v4.0":
                                temp["status"] = "Pass"
                        except:
                            temp["status"] = "Fail"

                        issues.append(temp)
        except Exception as e:
            logger.error(e);
        finally:
            return issues

    def check_dotnet_version_api_app(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                url = app_list_url.format(subscription["subscriptionId"])
                response = rest_api_call(self.credentials, url, '2019-08-01')
                for app in response["value"]:
                    x = re.findall("api", app["kind"])
                    if x :
                        temp = dict()
                        temp["region"] = app["location"]
                        temp["status"] = "Fail"
                        temp['resource_name'] = app['name']
                        temp['resource_id'] = ""
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]

                        config_url = base_url+app["id"]+"/config/web"
                        response = rest_api_call(self.credentials, config_url, '2019-08-01')
                        try:
                            version = 0.0
                            if "properties" in response:
                                version = response["properties"].get("netFrameworkVersion")
                            else:
                                version = response.get("netFrameworkVersion")
                            if version == "v3.0" or version == "v4.0":
                                temp["status"] = "Pass"
                        except:
                            temp["status"] = "Fail"

                        issues.append(temp)
        except Exception as e:
            logger.error(e);
        finally:
            return issues

    def enable_ftp_api_app(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                url = app_list_url.format(subscription["subscriptionId"])
                response = rest_api_call(self.credentials, url, '2019-08-01')
                for app in response["value"]:
                    x = re.findall("api", app["kind"])
                    if x :
                        temp = dict()
                        temp["region"] = app["location"]
                        temp["status"] = "Fail"
                        temp['resource_name'] = app['name']
                        temp['resource_id'] = ""
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]

                        config_url = base_url+app["id"]+"/config/web"
                        response = rest_api_call(self.credentials, config_url, '2019-08-01')
                        try:
                            if "properties" in response:
                                if response["properties"]["ftpsState"] == "FtpsOnly":
                                    temp["status"] = "Pass"
                            else:
                                if response["ftpsState"] == "FtpsOnly":
                                    temp["status"] = "Pass"
                        except:
                            temp["status"] = "Fail"

                        issues.append(temp)
        except Exception as e:
            logger.error(e);
        finally:
            return issues

    def enable_ftp_function_app(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                url = app_list_url.format(subscription["subscriptionId"])
                response = rest_api_call(self.credentials, url, '2019-08-01')
                for app in response["value"]:
                    x = re.findall("functionapp*", app["kind"])
                    if x :
                        temp = dict()
                        temp["region"] = app["location"]
                        temp["status"] = "Fail"
                        temp['resource_name'] = app['name']
                        temp['resource_id'] = ""
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]

                        config_url = base_url+app["id"]+"/config/web"
                        response = rest_api_call(self.credentials, config_url, '2019-08-01')
                        try:
                            if "properties" in response:
                                if response["properties"]["ftpsState"] == "FtpsOnly":
                                    temp["status"] = "Pass"
                            else:
                                if response["ftpsState"] == "FtpsOnly":
                                    temp["status"] = "Pass"
                        except:
                            temp["status"] = "Fail"

                        issues.append(temp)
        except Exception as e:
            logger.error(e);
        finally:
            return issues

    def enable_ftp_web_app(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                url = app_list_url.format(subscription["subscriptionId"])
                response = rest_api_call(self.credentials, url, '2019-08-01')
                for app in response["value"]:
                    x = re.findall("app*", app["kind"])
                    if x :
                        temp = dict()
                        temp["region"] = app["location"]
                        temp["status"] = "Fail"
                        temp['resource_name'] = app['name']
                        temp['resource_id'] = ""
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]

                        config_url = base_url+app["id"]+"/config/web"
                        response = rest_api_call(self.credentials, config_url, '2019-08-01')
                        try:
                            if "properties" in response:
                                if response["properties"]["ftpsState"] == "FtpsOnly":
                                    temp["status"] = "Pass"
                            else:
                                if response["ftpsState"] == "FtpsOnly":
                                    temp["status"] = "Pass"
                        except:
                            temp["status"] = "Fail"

                        issues.append(temp)
        except Exception as e:
            logger.error(e);
        finally:
            return issues

    def enable_authentication_web_app(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                url = app_list_url.format(subscription["subscriptionId"])
                response = rest_api_call(self.credentials, url, '2019-08-01')
                for app in response["value"]:
                    x = re.findall("app*", app["kind"])
                    if x :
                        temp = dict()
                        temp["region"] = app["location"]
                        temp["status"] = "Pass"
                        temp['resource_name'] = app['name']
                        temp['resource_id'] = ""
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]

                        config_url = base_url+app["id"]+"/config/web"
                        response = rest_api_call(self.credentials, config_url, '2019-08-01')
                        try:
                            if "properties" in response:
                                if response["properties"]["siteAuthEnabled"] is False:
                                    temp["status"] = "Fail"
                            else:
                                if response["siteAuthEnabled"] is False:
                                    temp["status"] = "Fail"
                        except:
                            temp["status"] = "Fail"

                        issues.append(temp)
        except Exception as e:
            logger.error(e);
        finally:
            return issues

    def enable_authentication_function_app(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                url = app_list_url.format(subscription["subscriptionId"])
                response = rest_api_call(self.credentials, url, '2019-08-01')
                for app in response["value"]:
                    x = re.findall("functionapp*", app["kind"])
                    if x :
                        temp = dict()
                        temp["region"] = app["location"]
                        temp["status"] = "Pass"
                        temp['resource_name'] = app['name']
                        temp['resource_id'] = ""
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]

                        config_url = base_url+app["id"]+"/config/web"
                        response = rest_api_call(self.credentials, config_url, '2019-08-01')
                        try:
                            if "properties" in response:
                                if response["properties"]["siteAuthEnabled"] is False:
                                    temp["status"] = "Fail"
                            else:
                                if response["siteAuthEnabled"] is False:
                                    temp["status"] = "Fail"
                        except:
                            temp["status"] = "Fail"

                        issues.append(temp)
        except Exception as e:
            logger.error(e);
        finally:
            return issues

    def enable_authentication_api_app(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                url = app_list_url.format(subscription["subscriptionId"])
                response = rest_api_call(self.credentials, url, '2019-08-01')
                for app in response["value"]:
                    x = re.findall("api", app["kind"])
                    if x :
                        temp = dict()
                        temp["region"] = app["location"]
                        temp["status"] = "Pass"
                        temp['resource_name'] = app['name']
                        temp['resource_id'] = ""
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]

                        config_url = base_url+app["id"]+"/config/web"
                        response = rest_api_call(self.credentials, config_url, '2019-08-01')
                        try:
                            if "properties" in response:
                                if response["properties"]["siteAuthEnabled"] is False:
                                    temp["status"] = "Fail"
                            else:
                                if response["siteAuthEnabled"] is False:
                                    temp["status"] = "Fail"
                        except:
                            temp["status"] = "Fail"

                        issues.append(temp)
        except Exception as e:
            logger.error(e);
        finally:
            return issues

    def enable_latest_httpversion_web_app(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                url = app_list_url.format(subscription["subscriptionId"])
                response = rest_api_call(self.credentials, url, '2019-08-01')
                for app in response["value"]:
                    x = re.findall("app*", app["kind"])
                    if x :
                        temp = dict()
                        temp["region"] = app["location"]
                        temp["status"] = "Pass"
                        temp['resource_name'] = app['name']
                        temp['resource_id'] = ""
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]

                        config_url = base_url+app["id"]+"/config/web"
                        response = rest_api_call(self.credentials, config_url, '2019-08-01')
                        try:
                            if "properties" in response:
                                if response["properties"]["http20Enabled"] is False:
                                    temp["status"] = "Fail"
                            else:
                                if response["http20Enabled"] is False:
                                    temp["status"] = "Fail"
                        except:
                            temp["status"] = "Fail"

                        issues.append(temp)
        except Exception as e:
            logger.error(e);
        finally:
            return issues

    def enable_latest_httpversion_function_app(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                url = app_list_url.format(subscription["subscriptionId"])
                response = rest_api_call(self.credentials, url, '2019-08-01')
                for app in response["value"]:
                    x = re.findall("functionapp*", app["kind"])
                    if x :
                        temp = dict()
                        temp["region"] = app["location"]
                        temp["status"] = "Pass"
                        temp['resource_name'] = app['name']
                        temp['resource_id'] = ""
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]

                        config_url = base_url+app["id"]+"/config/web"
                        response = rest_api_call(self.credentials, config_url, '2019-08-01')
                        try:
                            if "properties" in response:
                                if response["properties"]["http20Enabled"] is False:
                                    temp["status"] = "Fail"
                            else:
                                if response["http20Enabled"] is False:
                                    temp["status"] = "Fail"
                        except:
                            temp["status"] = "Fail"

                        issues.append(temp)
        except Exception as e:
            logger.error(e);
        finally:
            return issues

    def enable_latest_httpversion_api_app(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                url = app_list_url.format(subscription["subscriptionId"])
                response = rest_api_call(self.credentials, url, '2019-08-01')
                for app in response["value"]:
                    x = re.findall("api", app["kind"])
                    if x :
                        temp = dict()
                        temp["region"] = app["location"]
                        temp["status"] = "Pass"
                        temp['resource_name'] = app['name']
                        temp['resource_id'] = ""
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]

                        config_url = base_url+app["id"]+"/config/web"
                        response = rest_api_call(self.credentials, config_url, '2019-08-01')
                        try:
                            if "properties" in response:
                                if response["properties"]["http20Enabled"] is False:
                                    temp["status"] = "Fail"
                            else:
                                if response["http20Enabled"] is False:
                                    temp["status"] = "Fail"
                        except:
                            temp["status"] = "Fail"

                        issues.append(temp)
        except Exception as e:
            logger.error(e);
        finally:
            return issues

    def enable_https_access_functionapp(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                url = app_list_url.format(subscription["subscriptionId"])
                response = rest_api_call(self.credentials, url, '2019-08-01')
                for app in response["value"]:
                    x = re.findall("functionapp*", app["kind"])
                    if x:
                        temp = dict()
                        temp["region"] = app["location"]
                        temp["status"] = "Fail"
                        temp['resource_name'] = app['name']
                        temp['resource_id'] = ""
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]
                        if app["properties"]["httpsOnly"] is True:
                            temp["status"] = "Pass"
                        issues.append(temp)
        except Exception as e:
            logger.error(e);
        finally:
            return issues

    def enable_https_access_webapp(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                url = app_list_url.format(subscription["subscriptionId"])
                response = rest_api_call(self.credentials, url, '2019-08-01')
                for app in response["value"]:
                    x = re.findall("app*", app["kind"])
                    if x:
                        temp = dict()
                        temp["region"] = app["location"]
                        temp["status"] = "Fail"
                        temp['resource_name'] = app['name']
                        temp['resource_id'] = ""
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]
                        if app["properties"]["httpsOnly"] is True:
                            temp["status"] = "Pass"
                        issues.append(temp)
        except Exception as e:
            logger.error(e);
        finally:
            return issues

    def enable_https_access_apiapp(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                url = app_list_url.format(subscription["subscriptionId"])
                response = rest_api_call(self.credentials, url, '2019-08-01')
                for app in response["value"]:
                    x = re.findall("api", app["kind"])
                    if x:
                        temp = dict()
                        temp["region"] = app["location"]
                        temp["status"] = "Fail"
                        temp['resource_name'] = app['name']
                        temp['resource_id'] = ""
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]
                        if app["properties"]["httpsOnly"] is True:
                            temp["status"] = "Pass"
                        issues.append(temp)
        except Exception as e:
            logger.error(e);
        finally:
            return issues

    def enable_diagnostic_logs(self):
        issues = []
        try:
            subscription_list = self.subscription_list
            for subscription in subscription_list:
                url = app_list_url.format(subscription["subscriptionId"])
                response = rest_api_call(self.credentials, url, '2019-08-01')
                for app in response["value"]:
                    x = re.findall("functionapp*", app["kind"])
                    if not x :
                        temp = dict()
                        temp["region"] = app["location"]
                        temp["status"] = "Pass"
                        temp['resource_name'] = app['name']
                        temp['resource_id'] = ""
                        temp["subscription_id"] = subscription['subscriptionId']
                        temp["subscription_name"] = subscription["displayName"]

                        config_url = base_url+app["id"]+"/config/web"
                        response = rest_api_call(self.credentials, config_url, '2019-08-01')
                        try:
                            if "properties" in response:
                                if response["properties"]["detailedErrorLoggingEnabled"] is False and \
                                        response["properties"]["httpLoggingEnabled"] is False \
                                        and response["properties"]["requestTracingEnabled"] is False:
                                    temp["status"] = "Fail"
                            else:
                                if response["properties"]["detailedErrorLoggingEnabled"] is False and \
                                        response["properties"]["httpLoggingEnabled"] is False \
                                        and response["properties"]["requestTracingEnabled"] is False:
                                    temp["status"] = "Fail"
                        except:
                            temp["status"] = "Fail"

                        issues.append(temp)
        except Exception as e:
            logger.error(e);
        finally:
            return issues

    def function_app_python_version(self):

        issues = []

        try:

            for subscription in self.subscription_list:

                apps_url = app_list_url.format(
                    subscription.get("subscriptionId", ""))
                apps = rest_api_call(
                    credentials=self.credentials,
                    url=apps_url,
                    api_version="2019-08-01"
                ).get("value", [])

                for app in apps:

                    if app.get("type", "") == "Microsoft.Web/sites" and \
                            app.get("kind", "").startswith("functionapp"):
                        config_url = \
                            "{}/{}/config".format(
                                base_url,
                                app.get("id", "")
                            )

                        configs = rest_api_call(
                            credentials=self.credentials,
                            url=config_url,
                            api_version="2019-08-01"
                        ).get("value", [])

                        for config in configs:

                            linux_version = \
                                config.get("properties", {}).get(
                                    "linuxFxVersion", " | ").lower()
                            python_version = config.get(
                                "properties", {}).get("pythonVersion", "")

                            issue = {}

                            if "python" not in linux_version and \
                                    python_version not in ["", None]:

                                issue["status"] = "Info"
                                issue["resource_name"] = \
                                    config.get("name", "NA")
                                issue["resource_id"] = config.get("id", "NA")
                                issue["problem"] = \
                                    "Ensure that Python version - {} is the " \
                                    "latest in Function app {}".format(
                                        python_version,
                                        config.get("name", "NA"))

                            elif python_version in ["", None] and \
                                    "python" in linux_version:
                                try:
                                    python_version = \
                                        linux_version.split("|")[-1]
                                except:
                                    python_version = "NA"

                                issue["status"] = "Info"
                                issue["resource_name"] = \
                                    config.get("name", "NA")
                                issue["resource_id"] = config.get("id", "NA")
                                issue["problem"] = \
                                    "Ensure that Python version - {} is the " \
                                    "latest in Function app {}".format(
                                        python_version,
                                        config.get("name", "NA"))

                            else:
                                continue

                            issues.append(issue)
        except Exception as e:
            logger.error(e);
        finally:
            return issues

    def function_app_java_version(self):

        issues = []

        try:

            for subscription in self.subscription_list:

                apps_url = app_list_url.format(
                    subscription.get("subscriptionId", ""))
                apps = rest_api_call(
                    credentials=self.credentials,
                    url=apps_url,
                    api_version="2019-08-01"
                ).get("value", [])

                for app in apps:

                    if app.get("type", "") == "Microsoft.Web/sites" and \
                            app.get("kind", "").startswith("functionapp"):
                        config_url = \
                            "{}/{}/config".format(
                                base_url,
                                app.get("id", "")
                            )

                        configs = rest_api_call(
                            credentials=self.credentials,
                            url=config_url,
                            api_version="2019-08-01"
                        ).get("value", [])

                        for config in configs:

                            linux_version = \
                                config.get("properties", {}).get(
                                    "linuxFxVersion", " | ").lower()
                            java_version = config.get(
                                "properties", {}).get("javaVersion", "")

                            issue = {}

                            if "java" not in linux_version and \
                                    java_version not in ["", None]:

                                issue["status"] = "Info"
                                issue["resource_name"] = \
                                    config.get("name", "NA")
                                issue["resource_id"] = config.get("id", "NA")
                                issue["problem"] = \
                                    "Ensure that Java version - {} is the " \
                                    "latest in Function app {}".format(
                                        java_version,
                                        config.get("name", "NA"))

                            elif java_version in ["", None] and \
                                    "java" in linux_version:
                                try:
                                    java_version = \
                                        linux_version.split("|")[-1]
                                except:
                                    java_version = "NA"

                                issue["status"] = "Info"
                                issue["resource_name"] = \
                                    config.get("name", "NA")
                                issue["resource_id"] = config.get("id", "NA")
                                issue["problem"] = \
                                    "Ensure that Java version - {} is the " \
                                    "latest in Function app {}".format(
                                        java_version,
                                        config.get("name", "NA"))

                            else:
                                continue

                            issues.append(issue)
        except Exception as e:
            logger.error(e);
        finally:
            return issues

    def web_app_python_version(self):

        issues = []

        try:

            for subscription in self.subscription_list:

                apps_url = app_list_url.format(
                    subscription.get("subscriptionId", ""))
                apps = rest_api_call(
                    credentials=self.credentials,
                    url=apps_url,
                    api_version="2019-08-01"
                ).get("value", [])

                for app in apps:

                    if app.get("type", "") == "Microsoft.Web/sites" and \
                            app.get("kind", "").startswith("app"):
                        config_url = \
                            "{}/{}/config".format(
                                base_url,
                                app.get("id", "")
                            )

                        configs = rest_api_call(
                            credentials=self.credentials,
                            url=config_url,
                            api_version="2019-08-01"
                        ).get("value", [])

                        for config in configs:

                            linux_version = \
                                config.get("properties", {}).get(
                                    "linuxFxVersion", " | ").lower()
                            python_version = config.get(
                                "properties", {}).get("pythonVersion", "")

                            issue = {}

                            if "python" not in linux_version and \
                                    python_version not in ["", None]:

                                issue["status"] = "Info"
                                issue["resource_name"] = \
                                    config.get("name", "NA")
                                issue["resource_id"] = config.get("id", "NA")
                                issue["problem"] = \
                                    "Ensure that Python version - {} is the " \
                                    "latest in Function app {}".format(
                                        python_version,
                                        config.get("name", "NA"))

                            elif python_version in ["", None] and \
                                    "python" in linux_version:
                                try:
                                    python_version = \
                                        linux_version.split("|")[-1]
                                except:
                                    python_version = "NA"

                                issue["status"] = "Info"
                                issue["resource_name"] = \
                                    config.get("name", "NA")
                                issue["resource_id"] = config.get("id", "NA")
                                issue["problem"] = \
                                    "Ensure that Python version - {} is the " \
                                    "latest in Function app {}".format(
                                        python_version,
                                        config.get("name", "NA"))

                            else:
                                continue

                            issues.append(issue)
        except Exception as e:
            logger.error(e);
        finally:
            return issues

    def web_app_java_version(self):

        issues = []

        try:

            for subscription in self.subscription_list:

                apps_url = app_list_url.format(
                    subscription.get("subscriptionId", ""))
                apps = rest_api_call(
                    credentials=self.credentials,
                    url=apps_url,
                    api_version="2019-08-01"
                ).get("value", [])

                for app in apps:

                    if app.get("type", "") == "Microsoft.Web/sites" and \
                            app.get("kind", "").startswith("app"):
                        config_url = \
                            "{}/{}/config".format(
                                base_url,
                                app.get("id", "")
                            )

                        configs = rest_api_call(
                            credentials=self.credentials,
                            url=config_url,
                            api_version="2019-08-01"
                        ).get("value", [])

                        for config in configs:

                            linux_version = \
                                config.get("properties", {}).get(
                                    "linuxFxVersion", " | ").lower()
                            java_version = config.get(
                                "properties", {}).get("javaVersion", "")

                            issue = {}

                            if "java" not in linux_version and \
                                    java_version not in ["", None]:

                                issue["status"] = "Info"
                                issue["resource_name"] = \
                                    config.get("name", "NA")
                                issue["resource_id"] = config.get("id", "NA")
                                issue["problem"] = \
                                    "Ensure that Java version - {} is the " \
                                    "latest in Function app {}".format(
                                        java_version,
                                        config.get("name", "NA"))

                            elif java_version in ["", None] and \
                                    "java" in linux_version:
                                try:
                                    java_version = \
                                        linux_version.split("|")[-1]
                                except:
                                    java_version = "NA"

                                issue["status"] = "Info"
                                issue["resource_name"] = \
                                    config.get("name", "NA")
                                issue["resource_id"] = config.get("id", "NA")
                                issue["problem"] = \
                                    "Ensure that Java version - {} is the " \
                                    "latest in Function app {}".format(
                                        java_version,
                                        config.get("name", "NA"))

                            else:
                                continue

                            issues.append(issue)
        except Exception as e:
            logger.error(e);
        finally:
            return issues

    def web_app_php_version(self):

        issues = []

        try:

            for subscription in self.subscription_list:

                apps_url = app_list_url.format(
                    subscription.get("subscriptionId", ""))
                apps = rest_api_call(
                    credentials=self.credentials,
                    url=apps_url,
                    api_version="2019-08-01"
                ).get("value", [])

                for app in apps:

                    if app.get("type", "") == "Microsoft.Web/sites" and \
                            app.get("kind", "").startswith("app"):
                        config_url = \
                            "{}/{}/config".format(
                                base_url,
                                app.get("id", "")
                            )

                        configs = rest_api_call(
                            credentials=self.credentials,
                            url=config_url,
                            api_version="2019-08-01"
                        ).get("value", [])

                        for config in configs:

                            linux_version = \
                                config.get("properties", {}).get(
                                    "linuxFxVersion", " | ").lower()
                            php_version = config.get(
                                "properties", {}).get("phpVersion", "")

                            issue = {}

                            if "php" not in linux_version and \
                                    php_version not in ["", None]:

                                issue["status"] = "Info"
                                issue["resource_name"] = \
                                    config.get("name", "NA")
                                issue["resource_id"] = config.get("id", "NA")
                                issue["problem"] = \
                                    "Ensure that PHP version - {} is the " \
                                    "latest in Function app {}".format(
                                        php_version,
                                        config.get("name", "NA"))

                            elif php_version in ["", None] and \
                                    "php" in linux_version:
                                try:
                                    php_version = \
                                        linux_version.split("|")[-1]
                                except:
                                    php_version = "NA"

                                issue["status"] = "Info"
                                issue["resource_name"] = \
                                    config.get("name", "NA")
                                issue["resource_id"] = config.get("id", "NA")
                                issue["problem"] = \
                                    "Ensure that PHP version - {} is the " \
                                    "latest in Function app {}".format(
                                        php_version,
                                        config.get("name", "NA"))

                            else:
                                continue

                            issues.append(issue)
        except Exception as e:
            logger.error(e);
        finally:
            return issues

    def api_app_python_version(self):

        issues = []

        try:

            for subscription in self.subscription_list:

                apps_url = app_list_url.format(
                    subscription.get("subscriptionId", ""))
                apps = rest_api_call(
                    credentials=self.credentials,
                    url=apps_url,
                    api_version="2019-08-01"
                ).get("value", [])

                for app in apps:

                    if app.get("type", "") == "Microsoft.Web/sites" and \
                            app.get("kind", "").startswith("api"):
                        config_url = \
                            "{}/{}/config".format(
                                base_url,
                                app.get("id", "")
                            )

                        configs = rest_api_call(
                            credentials=self.credentials,
                            url=config_url,
                            api_version="2019-08-01"
                        ).get("value", [])

                        for config in configs:

                            linux_version = \
                                config.get("properties", {}).get(
                                    "linuxFxVersion", " | ").lower()
                            python_version = config.get(
                                "properties", {}).get("pythonVersion", "")

                            print(linux_version, python_version)

                            issue = {}

                            if "python" not in linux_version and \
                                    python_version not in ["", None]:

                                issue["status"] = "Info"
                                issue["resource_name"] = \
                                    config.get("name", "NA")
                                issue["resource_id"] = config.get("id", "NA")
                                issue["problem"] = \
                                    "Ensure that Python version - {} is the " \
                                    "latest in Function app {}".format(
                                        python_version,
                                        config.get("name", "NA"))

                            elif python_version in ["", None] and \
                                    "python" in linux_version:
                                try:
                                    python_version = \
                                        linux_version.split("|")[-1]
                                except:
                                    python_version = "NA"

                                issue["status"] = "Info"
                                issue["resource_name"] = \
                                    config.get("name", "NA")
                                issue["resource_id"] = config.get("id", "NA")
                                issue["problem"] = \
                                    "Ensure that Python version - {} is the " \
                                    "latest in Function app {}".format(
                                        python_version,
                                        config.get("name", "NA"))

                            else:
                                continue

                            issues.append(issue)
        except Exception as e:
            logger.error(e);
        finally:
            return issues

    def api_app_php_version(self):

        issues = []

        try:

            for subscription in self.subscription_list:

                apps_url = app_list_url.format(
                    subscription.get("subscriptionId", ""))
                apps = rest_api_call(
                    credentials=self.credentials,
                    url=apps_url,
                    api_version="2019-08-01"
                ).get("value", [])

                for app in apps:

                    if app.get("type", "") == "Microsoft.Web/sites" and \
                            app.get("kind", "").startswith("api"):
                        config_url = \
                            "{}/{}/config".format(
                                base_url,
                                app.get("id", "")
                            )

                        configs = rest_api_call(
                            credentials=self.credentials,
                            url=config_url,
                            api_version="2019-08-01"
                        ).get("value", [])

                        for config in configs:

                            linux_version = \
                                config.get("properties", {}).get(
                                    "linuxFxVersion", " | ").lower()
                            php_version = config.get(
                                "properties", {}).get("phpVersion", "")

                            issue = {}

                            if "php" not in linux_version and \
                                    php_version not in ["", None]:

                                issue["status"] = "Info"
                                issue["resource_name"] = \
                                    config.get("name", "NA")
                                issue["resource_id"] = config.get("id", "NA")
                                issue["problem"] = \
                                    "Ensure that PHP version - {} is the " \
                                    "latest in Function app {}".format(
                                        php_version,
                                        config.get("name", "NA"))

                            elif php_version in ["", None] and \
                                    "php" in linux_version:
                                try:
                                    php_version = \
                                        linux_version.split("|")[-1]
                                except:
                                    php_version = "NA"

                                issue["status"] = "Info"
                                issue["resource_name"] = \
                                    config.get("name", "NA")
                                issue["resource_id"] = config.get("id", "NA")
                                issue["problem"] = \
                                    "Ensure that PHP version - {} is the " \
                                    "latest in Function app {}".format(
                                        php_version,
                                        config.get("name", "NA"))

                            else:
                                continue

                            issues.append(issue)
        except Exception as e:
            logger.error(e);
        finally:
            return issues

    def function_app_php_version(self):

        issues = []

        try:

            for subscription in self.subscription_list:

                apps_url = app_list_url.format(
                    subscription.get("subscriptionId", ""))
                apps = rest_api_call(
                    credentials=self.credentials,
                    url=apps_url,
                    api_version="2019-08-01"
                ).get("value", [])

                for app in apps:

                    if app.get("type", "") == "Microsoft.Web/sites" and \
                            app.get("kind", "").startswith("functionapp"):
                        config_url = \
                            "{}/{}/config".format(
                                base_url,
                                app.get("id", "")
                            )

                        configs = rest_api_call(
                            credentials=self.credentials,
                            url=config_url,
                            api_version="2019-08-01"
                        ).get("value", [])

                        for config in configs:

                            linux_version = \
                                config.get("properties", {}).get(
                                    "linuxFxVersion", " | ").lower()
                            java_version = config.get(
                                "properties", {}).get("phpVersion", "")

                            issue = {}

                            if "java" not in linux_version and \
                                    java_version not in ["", None]:

                                issue["status"] = "Info"
                                issue["resource_name"] = \
                                    config.get("name", "NA")
                                issue["resource_id"] = config.get("id", "NA")
                                issue["problem"] = \
                                    "Ensure that PHP version - {} is the " \
                                    "latest in API app {}".format(
                                        java_version,
                                        config.get("name", "NA"))

                            elif java_version in ["", None] and \
                                    "java" in linux_version:
                                try:
                                    java_version = \
                                        linux_version.split("|")[-1]
                                except:
                                    java_version = "NA"

                                issue["status"] = "Info"
                                issue["resource_name"] = \
                                    config.get("name", "NA")
                                issue["resource_id"] = config.get("id", "NA")
                                issue["problem"] = \
                                    "Ensure that PHP version - {} is the " \
                                    "latest in API app {}".format(
                                        java_version,
                                        config.get("name", "NA"))

                            else:
                                continue

                            issues.append(issue)
        except Exception as e:
            logger.error(e);
        finally:
            return issues

    def api_app_java_version(self):

        issues = []

        try:

            for subscription in self.subscription_list:

                apps_url = app_list_url.format(
                    subscription.get("subscriptionId", ""))
                apps = rest_api_call(
                    credentials=self.credentials,
                    url=apps_url,
                    api_version="2019-08-01"
                ).get("value", [])

                for app in apps:

                    if app.get("type", "") == "Microsoft.Web/sites" and \
                            app.get("kind", "").startswith("api"):
                        config_url = \
                            "{}/{}/config".format(
                                base_url,
                                app.get("id", "")
                            )

                        configs = rest_api_call(
                            credentials=self.credentials,
                            url=config_url,
                            api_version="2019-08-01"
                        ).get("value", [])

                        for config in configs:

                            linux_version = \
                                config.get("properties", {}).get(
                                    "linuxFxVersion", " | ").lower()
                            php_version = config.get(
                                "properties", {}).get("javaVersion", "")

                            issue = {}

                            if "php" not in linux_version and \
                                    php_version not in ["", None]:

                                issue["status"] = "Info"
                                issue["resource_name"] = \
                                    config.get("name", "NA")
                                issue["resource_id"] = config.get("id", "NA")
                                issue["problem"] = \
                                    "Ensure that JAVA version - {} is the " \
                                    "latest in Function app {}".format(
                                        php_version,
                                        config.get("name", "NA"))

                            elif php_version in ["", None] and \
                                    "php" in linux_version:
                                try:
                                    php_version = \
                                        linux_version.split("|")[-1]
                                except:
                                    php_version = "NA"

                                issue["status"] = "Info"
                                issue["resource_name"] = \
                                    config.get("name", "NA")
                                issue["resource_id"] = config.get("id", "NA")
                                issue["problem"] = \
                                    "Ensure that JAVA version - {} is the " \
                                    "latest in Function app {}".format(
                                        php_version,
                                        config.get("name", "NA"))

                            else:
                                continue

                            issues.append(issue)
        except Exception as e:
            logger.error(e);
        finally:
            return issues