This add-on helps to create customized Jira issues based on triggered events in Splunk.
It supports both Atlassian Jira Cloud and Atlassian Jira Server versions. Automatically detects which APIs need to use.
Features:
Cover all standart necessary fields in Atlassian Jira for issue creation such as: Project, Summary, Issue type, Priority, Description, Assignee, Labels , Components.
* Add the result of Splunk Alert into the Jira issue at the end of the description field. There is two possible view of added data
    1) The table view where table head consists from Splunk Alert result fields
    2) The list view when the result of Splunk alert will be added as a Jira code snippet.
* Possibility to use one additional custom field to create Jira issues.
* Control what information from Splunk Alert will appear in Jira issues. Pass search result values dynamically into Jira issues.
* Not necessary to use digital identificators of values in the Jira field. All fields take human readable values.
* Sample: you have a Jira project with short name “CORP” with id=2331. In configuration of Splunk Alert you don’t need to use the Id of Jira Project. You need to use the name of Project “CORP”.  Atlassian JIRA Issue Alerts add-on will automatically convert  human readable values into digital identificators.
* Possibility to assign issues to specific people even if you don’t know thier UUID in Jira Cloud. Assignment by username.

# Binary File Declaration
/opt/splunk/var/data/tabuilder/package/TA-atlassian-jira-issue-alerts/bin/ta_atlassian_jira_issue_alerts/aob_py3/markupsafe/_speedups.cpython-37m-x86_64-linux-gnu.so: this file does not require any source code
