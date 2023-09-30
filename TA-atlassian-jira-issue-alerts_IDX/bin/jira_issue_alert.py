
# encoding = utf-8
# Always put this line at the beginning of this file
import ta_atlassian_jira_issue_alerts_declare

import os
import sys

from alert_actions_base import ModularAlertBase
import modalert_jira_issue_alert_helper

class AlertActionWorkerjira_issue_alert(ModularAlertBase):

    def __init__(self, ta_name, alert_name):
        super(AlertActionWorkerjira_issue_alert, self).__init__(ta_name, alert_name)

    def validate_params(self):

        if not self.get_global_setting("atlassian_jira_url"):
            self.log_error('atlassian_jira_url is a mandatory setup parameter, but its value is None.')
            return False

        if not self.get_global_setting("JIRA_username"):
            self.log_error('JIRA_username is a mandatory setup parameter, but its value is None.')
            return False

        if not self.get_global_setting("jira_password"):
            self.log_error('jira_password is a mandatory setup parameter, but its value is None.')
            return False

        if not self.get_param("project"):
            self.log_error('project is a mandatory parameter, but its value is None.')
            return False

        if not self.get_param("summary"):
            self.log_error('summary is a mandatory parameter, but its value is None.')
            return False

        if not self.get_param("issue_type"):
            self.log_error('issue_type is a mandatory parameter, but its value is None.')
            return False

        if not self.get_param("priority"):
            self.log_error('priority is a mandatory parameter, but its value is None.')
            return False

        if not self.get_param("description"):
            self.log_error('description is a mandatory parameter, but its value is None.')
            return False
        return True

    def process_event(self, *args, **kwargs):
        status = 0
        try:
            if not self.validate_params():
                return 3
            status = modalert_jira_issue_alert_helper.process_event(self, *args, **kwargs)
        except (AttributeError, TypeError) as ae:
            self.log_error("Error: {}. Please double check spelling and also verify that a compatible version of Splunk_SA_CIM is installed.".format(str(ae)))
            return 4
        except Exception as e:
            msg = "Unexpected error: {}."
            if e:
                self.log_error(msg.format(str(e)))
            else:
                import traceback
                self.log_error(msg.format(traceback.format_exc()))
            return 5
        return status

if __name__ == "__main__":
    exitcode = AlertActionWorkerjira_issue_alert("TA-atlassian-jira-issue-alerts", "jira_issue_alert").run(sys.argv)
    sys.exit(exitcode)
