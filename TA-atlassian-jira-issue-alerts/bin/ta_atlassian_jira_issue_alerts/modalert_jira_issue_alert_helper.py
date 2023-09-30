# encoding = utf-8
import json
import requests
from requests.auth import HTTPBasicAuth

class JiraUtils:
    def __init__(self, server, username, key,  helper, verify_ssl=True):
        clean_server = server.replace("https://","").replace("http://","")
        self._server = "https://{}".format(clean_server)
        self._verify = verify_ssl
        self._token = ''
        self._cookie = ''
        self._auth = HTTPBasicAuth(username, key)
        self._deploymentTypeCloud = False
        self._version = ""
        self._helper = helper
        res = self.request("/rest/api/2/serverInfo", "GET")
        if res.status_code == 200:
            result = res.json()
            self._deploymentTypeCloud = False if result.get("deploymentType", "") == "Server" else True
            self._version = result.get("version")

    def request(self, api_url, type, payload=None):
        headers = {"Content-Type": "application/json"}
        if type == "POST":
            return requests.post(self._server + api_url, data=payload, headers=headers, auth=self._auth)
        return requests.get(self._server + api_url, headers=headers, auth=self._auth)

    def check_meta_project(self, project_key, issuetype_key):
        try:

            if self._deploymentTypeCloud:
                url_issuetypes_cloud = "/rest/api/2/issue/createmeta?projectKeys={}".format(project_key)
                issues_types = self.request(url_issuetypes_cloud, "GET")
                if issues_types.status_code != 200:
                    raise Exception(
                        "No matched issuetype with project {} statuscode {} and response text {}".format(project_key,
                                                                                                         issues_types.status_code,
                                                                                                         issues_types.text))
                res = issues_types.json()

                project_allowed_issuetypes = res.get("projects")[0].get("issuetypes")

                issuetype_id = self.get_record_from_list(project_allowed_issuetypes, issuetype_key)

                url = url_issuetypes_cloud + "&issuetypeIds={}&expand=projects.issuetypes.fields".format(issuetype_id)
                issues_types_meta = self.request(url, "GET")
                if issues_types_meta.status_code != 200:
                    raise Exception(
                        "No matched issuetype with issuetype_key {} statuscode {} and response text {}".format(
                            issuetype_key,
                            issues_types_meta.status_code,
                            issues_types_meta.text))
                res = issues_types_meta.json()
                project_meta = list(res.get("projects")[0].get("issuetypes")[0].get("fields").values())
                return project_meta, issuetype_id
            else:
                url_issuetypes_server = "/rest/api/2/issue/createmeta/{}/issuetypes/".format(project_key)

                issues_types = self.request(url_issuetypes_server, "GET")
                if issues_types.status_code != 200:
                    raise Exception(
                        "No matched issuetype with project {} statuscode {} and response text {}".format(project_key,
                                                                                                         issues_types.status_code,
                                                                                                         issues_types.text))
                res = issues_types.json()

                project_allowed_issuetypes = res.get("values")

                issuetype_id = self.get_record_from_list(project_allowed_issuetypes, issuetype_key)

                url = url_issuetypes_server + "{}/".format(issuetype_id)
                issues_types_meta = self.request(url, "GET")
                if issues_types_meta.status_code != 200:
                    raise Exception(
                        "No matched issuetype with issuetype_key {} statuscode {} and response text {}".format(
                            issuetype_key,
                            issues_types_meta.status_code,
                            issues_types_meta.text))
                res = issues_types_meta.json()
                return res.get("values"), issuetype_id

        except Exception as e:
            self._helper.log_error("Failed checking meta of project")
            raise Exception(e)

    def get_record_from_list(self, allowedValues, key):
        if allowedValues is None:
            return key
        priority_recs = list(filter(lambda x: (x.get("name") is not None and x.get("name").lower() == key.lower()
                                               or (x.get("value") is not None and x.get("value").lower() ==  key.lower())), allowedValues))
        if len(priority_recs) != 1:
            raise Exception("No record = {} in meta".format(key))
        return priority_recs[0].get("id")

    def get_allowed_values(self,field_name, meta):
        meta_fields = []
        if self._deploymentTypeCloud:
            meta_fields = list(filter(lambda x: x.get("name").lower() == field_name.lower(), meta))
        else:
            meta_fields = list(filter(lambda x: x.get("fieldId").lower() == field_name.lower(), meta))
        if len(meta_fields) == 0:
            raise Exception("No {} in meta".format(field_name))
        allowedValues = meta_fields[0].get("allowedValues")
        return allowedValues

    def get_key_by_name(self,field_name, meta):
        meta_fields = list(filter(lambda x: x.get("name").lower() == field_name.lower(), meta))
        if len(meta_fields) == 0:
            raise Exception("No {} in meta".format(field_name))
        return meta_fields[0].get("key") if self._deploymentTypeCloud else meta_fields[0].get("fieldId")

    def get_id_from_key(self, field_name, key, meta):
        try:
            allowedValues = self.get_allowed_values(field_name,meta)
            return self.get_record_from_list(allowedValues, key)
        except Exception as e:
            self._helper.log_error("Failed get id for field name {}".format(field_name))
            raise e

    def get_userId_by_name(self, username):
        url = ""
        if self._deploymentTypeCloud:
            url = "/rest/api/2/user/search?query={}".format(username)
        else:
            url = "/rest/api/2/user/search?username={}".format(username)
        assignee_search_res = self.request(url, "GET")
        if assignee_search_res.status_code != 200:
            raise Exception("No matched user with username {}".format(username))
        assigne_search_list = assignee_search_res.json()
        first_match = assigne_search_list[0]
        return first_match.get("accountId"), first_match.get("name")

    def create_jira_issue(self, project_key, issuetype_key, priority, summary, description, labels_str, components_str,
                          assignee, additional_field_1_name, additional_field_1_value):
        meta, issuetype_id = self.check_meta_project(project_key, issuetype_key)

        priority_id = self.get_id_from_key("priority", priority, meta)

        labels = []
        if labels_str is not None and labels_str.strip() !="":
            for x in labels_str.split(","):
                val = x.strip()
                if val != "":
                    labels.append(val)

        components_ids = []
        if components_str is not None and components_str.strip() !="":
            for components_key in components_str.split(","):
                val = components_key.strip()
                if val != "":
                    components_ids.append({"id": self.get_id_from_key("components", val, meta)})

        payload = {
            "fields": {
                "project": {"key": project_key},
                "summary": summary,
                "priority": {"id": priority_id},
                "description": description,
                "issuetype": {"id": issuetype_id},
            }
        }


        if assignee is not None  and assignee.strip() != "":
            if assignee == "-1":
                payload["fields"].update({"assignee": {"name": assignee}})
            else:
                assignee_id, assignee_name = self.get_userId_by_name(assignee)
                payload["fields"].update({"assignee": {"id": assignee_id} if self._deploymentTypeCloud else {"name": assignee_name}})

        if len(labels) > 0:
            payload["fields"].update({"labels":labels})
        if len(components_ids) > 0:
            payload["fields"].update({"components": components_ids})

        if additional_field_1_name and additional_field_1_value:
            key = self.get_key_by_name(additional_field_1_name,meta)
            allowed_values = self.get_allowed_values(additional_field_1_name,meta)
            if allowed_values is not None:
                id = self.get_id_from_key(additional_field_1_name, additional_field_1_value, meta)
                payload["fields"][key] = {"id":id}
            else:
                payload["fields"][key] = additional_field_1_value

        data = json.dumps(payload)

        #self._helper.log_info("Payload for jira {}".format(data))
        res = self.request("/rest/api/2/issue", "POST", payload=data)
        return res

def process_event(helper, *args, **kwargs):
    """
    # IMPORTANT
    # Do not remove the anchor macro:start and macro:end lines.
    # These lines are used to generate sample code. If they are
    # removed, the sample code will not be updated when configurations
    # are updated.

    [sample_code_macro:start]

    # The following example sends rest requests to some endpoint
    # response is a response object in python requests library
    response = helper.send_http_request("http://www.splunk.com", "GET", parameters=None,
                                        payload=None, headers=None, cookies=None, verify=True, cert=None, timeout=None, use_proxy=True)
    # get the response headers
    r_headers = response.headers
    # get the response body as text
    r_text = response.text
    # get response body as json. If the body text is not a json string, raise a ValueError
    r_json = response.json()
    # get response cookies
    r_cookies = response.cookies
    # get redirect history
    historical_responses = response.history
    # get response status code
    r_status = response.status_code
    # check the response status, if the status is not sucessful, raise requests.HTTPError
    response.raise_for_status()


    # The following example gets account information
    user_account = helper.get_user_credential("<account_name>")

    # The following example gets the alert action parameters and prints them to the log
    string_label = helper.get_param("string_label")
    helper.log_info("string_label={}".format(string_label))

    string_label_1690228571881 = helper.get_param("string_label_1690228571881")
    helper.log_info("string_label_1690228571881={}".format(string_label_1690228571881))

    string_label_1690228574367 = helper.get_param("string_label_1690228574367")
    helper.log_info("string_label_1690228574367={}".format(string_label_1690228574367))

    dropdown_list = helper.get_param("dropdown_list")
    helper.log_info("dropdown_list={}".format(dropdown_list))

    dropdown_list_1690228577930 = helper.get_param("dropdown_list_1690228577930")
    helper.log_info("dropdown_list_1690228577930={}".format(dropdown_list_1690228577930))


    # The following example adds two sample events ("hello", "world")
    # and writes them to Splunk
    # NOTE: Call helper.writeevents() only once after all events
    # have been added
    helper.addevent("hello", sourcetype="sample_sourcetype")
    helper.addevent("world", sourcetype="sample_sourcetype")
    helper.writeevents(index="summary", host="localhost", source="localhost")

    # The following example gets the events that trigger the alert
    events = helper.get_events()
    for event in events:
        helper.log_info("event={}".format(event))

    # helper.settings is a dict that includes environment configuration
    # Example usage: helper.settings["server_uri"]
    helper.log_info("server_uri={}".format(helper.settings["server_uri"]))
    [sample_code_macro:end]
    """

    helper.log_info("Alert action jira_issue_alert started.")

    # The following example gets the setup parameters and prints them to the log
    atlassian_jira_url = helper.get_global_setting("atlassian_jira_url").strip()
    if atlassian_jira_url[-1:] == "/":
        atlassian_jira_url = atlassian_jira_url[:-1]
    helper.log_info("atlassian_jira_url={}".format(atlassian_jira_url))
    jira_username = helper.get_global_setting("JIRA_username")
    jira_password = helper.get_global_setting("jira_password")
    don_t_verify_tls_certificate = helper.get_global_setting("don_t_verify_tls_certificate")
    helper.log_info("don_t_verify_tls_certificate={}".format(don_t_verify_tls_certificate))

    # The following example gets the alert action parameters and prints them to the log
    project_key = helper.get_param("project")
    helper.log_info("project_key={}".format(project_key))

    summary = helper.get_param("summary")
    helper.log_info("summary={}".format(summary))

    issue_type = helper.get_param("issue_type")
    helper.log_info("issue_type={}".format(issue_type))

    priority = helper.get_param("priority")
    helper.log_info("priority={}".format(priority))

    description = helper.get_param("description")
    helper.log_info("description={}".format(description))

    assignee = (helper.get_param("assignee"))
    helper.log_info("assignee={}".format(assignee))

    labels = (helper.get_param("labels"))
    helper.log_info("labels={}".format(labels))

    components = (helper.get_param("components"))
    helper.log_info("components={}".format(components))

    additional_field_1_name = (helper.get_param("additional_field_1_name"))
    helper.log_info("additional_field_1_name={}".format(additional_field_1_name))

    additional_field_1_value = (helper.get_param("additional_field_1_value"))
    helper.log_info("additional_field_1_value={}".format(additional_field_1_value))

    append_alert_result = helper.get_param("append_alert_result")
    helper.log_info("append_alert_result={}".format(append_alert_result))

    append_alert_result_text = ""
    if append_alert_result != "1":
        events = helper.get_events()
        for event in events:
            new_dict = {}
            for ev in event:
                if str.startswith(ev, "__"):
                    continue
                else:
                    new_dict.update({ev: event.get(ev)})

            if len(append_alert_result_text) > 32000:
                break
            if append_alert_result == "2":
                if append_alert_result_text == "":
                    append_alert_result_text = "||" + "||".join(new_dict.keys())
                append_alert_result_text = append_alert_result_text + "\r\n" + "|" + "|".join(new_dict.values())
            elif append_alert_result == "3":
                if append_alert_result_text == "":
                    append_alert_result_text = "{code:title=Detailed Results|theme=FadeToGrey|linenumbers=true|language=PlainText|firstline=0001|collapse=true}"
                    append_alert_result_text = append_alert_result_text + "\t".join(new_dict.keys())
                append_alert_result_text = append_alert_result_text + "\r\n\r\n" + "\t".join(new_dict.values())

        if append_alert_result == "3":
            append_alert_result_text = append_alert_result_text + "{code}"

        append_alert_result_text = "\r\n----\r\n" + append_alert_result_text

    description = description + append_alert_result_text

    jira = JiraUtils(atlassian_jira_url, jira_username, jira_password, helper, verify_ssl= bool(don_t_verify_tls_certificate) )
    result = jira.create_jira_issue(project_key, issue_type, priority, summary, description, labels,
                                    components, assignee, additional_field_1_name, additional_field_1_value)
    if result.status_code > 300:
        helper.log_error("Error issue creation - {}".format(result.text))
        return 1
    return 0
