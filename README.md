# Graylog Plugin for JIRA with templating
___

A Graylog alarm callback plugin that integrates [Graylog](https://www.graylog.org/) into [JIRA](https://www.atlassian.com/software/jira/).

:scream: **IMPORTANT**: When upgrading to Graylog 2.2.0, the Manage Alert Conditions seem to have dropped/defaulted. Click on "Alerts" and verify that your settings are still correct. In my case, the message count condition was completely gone.

:scream: **IMPORTANT**: ~~Graylog 2.0.2 introduces a single classloader for plugins which has now resulted in the Jira plugin breaking due to the map-plugin shipping an outdated version of httpclient. There is no real clean way to fix this other than hoping that Graylog developers will come up with a cleaner solution. I unfortunatley do not have the time to attempt to manually hack this plugin to avoid class-conflicts, so my suggestion is to remove the map-plugin.~~ This was fixed in Graylog 2.1.3.

## Main features
* Templating of JIRA issue title and JIRA message via place holders
* Embed a MD5 hash into the JIRA issue via custom-field or embed within JIRA-message to prevent duplicate JIRA issues

![Graylog JIRA plugin](https://raw.githubusercontent.com/magicdude4eva/graylog-jira-alarmcallback/master/screenshots/screenshot-alert-config.png)

# Pre-requisites for Java exception logging
If you use an application server such as Tomcat, we suggest that you use [Logstash](https://www.elastic.co/products/logstash) to pre-process your log-files and ship the log-records via Gelf output into Graylog.

A very reliable way of processing Tomcat logs can be achieved by:
 
* Using Logstash with `sincedb_path` and `sincedb_write_interval` 
* Use Log4J to consistently format log records to consist of `%{LOGLEVEL} %{timestamp} %{threadname} %{MESSAGE}`
* Use a multi-line codec to extract exception messages
* Use a series of grok patterns to retag multiline messages as "exception" you want a Graylog stream to process - i.e. `match => { message => [ "(^.+Exception: .+)|(^.+Stacktrace:.+)" ] }`
* Discard and sanitize messages in Logstash - this will improve storage, filtering and stream processing

With the above you can easily setup a stream where your condition is as simple as "`type must match exactly tomcat AND tags must match exactly exception`"

## About MD5 hashing to avoid duplicates
When you want to automatically log JIRA issues as an exception occurs on your servers, you want to make sure that only one issue is logged. This is achieved by creating a MD5 from a portion of the message (typically the logmessage without the timestamp) and then injecting the MD5 into the JIRA issue.

As Graylog fires an alarm, this plugin will search JIRA for any existing issues (via the MD5) to avoid creation of duplicate issues. Out of the box, this plugin will append a MD5 hash to the JIRA issue description and no JIRA additional configuration is required.

If you are able to add custom fields, the preferred option is to create a JIRA custom field with the name `graylog_md5` and the plugin will then automatically insert the MD5 hash into the JIRA field.
 

Installation of plugin
----------------------
This plugin has been tested with Graylog v1.3.3, Graylog v2.0 and JIRA v7.0.10.

Download the [latest release](https://github.com/magicdude4eva/graylog-jira-alarmcallback/releases) and copy the `.jar` file into your Graylog plugin directory (default is in `/usr/share/graylog-server/plugin`).
If you are unsure about the plugin location, do a `grep -i plugin_dir /etc/graylog/server/server.conf`.

Restart Graylog via `systemctl restart graylog-server`


Troubleshooting the plugin
--------------------------
Sending a test alert will create a real ticket in JIRA and any obvious errors will be displayed in the Graylog web-interface. If you run into any issues, it is best to look at the Graylog server log which is at `/var/log/graylog/server.log`.

If you just do a `grep -i jira /var/log/graylog/server.log or` a `tail -f /var/log/graylog/server.log | grep -i jira` you should see output like the below:

```
2016-04-19T16:33:28.362+02:00 INFO  [JiraAlarmCallback] [JIRA] Checking for duplicate issues with MD5=25933c67013ea3bbb722e34cbe997d1b, using filter-query=AND Status not in (Closed, Done, Resolved)
2016-04-19T16:33:28.700+02:00 INFO  [JiraAlarmCallback] [JIRA] There is one issue with the same hash
```

If you found a bug, have an issue or have a feature suggestion, please just log an issue.


Configuration
-------------

### Configure the stream alert
![Graylog callback configuration](https://raw.githubusercontent.com/magicdude4eva/graylog-jira-alarmcallback/master/screenshots/screenshot-plugin-overview.png)

### Callback options
* __JIRA Instance URL__: The URL to your JIRA server
* __Project Key__: The project key under which the issue will be created in JIRA
* __Issue Type__: The JIRA issue type (defaults to `Bug`). Ensure that the issue type matches your project settings
* __Graylog URL__: The URL to the Graylog web-interface. The URL is used to generate links within JIRA
* __Issue Priority__: The JIRA issue priority (defaults to `Minor`). Ensure that the issue priority matches your project settings
* __Labels__: Comma-separated list of labels to add to the issue
* __Message template__: Message template used to create a JIRA issue. The message template uses JIRA Text Formatting Notation. Line-breaks can be added as "`\n`". The message-template also accepts `[PLACEHOLDERS]`
  * __[STREAM_TITLE]__: Title of the stream
  * __[STREAM_URL]__: URL to the stream
  * __[STREAM_RULES]__: Stream rules triggered
  * __[STREAM_RESULT]__: Includes stream-result description i.e. `'Stream had 7 messages in the last 30 minutes with trigger condition more than 5 messages. (Current grace time: 0 minutes)'`
  * __[ALERT_TRIGGERED_AT]__: Timestamp when alert was triggered
  * __[ALERT_TRIGGERED_CONDITION]__: Conditions triggering the alert
  * __[LAST_MESSAGE.source]__: If a message is present, the placeholder will be replaced with the source origin of the message
  * __[LAST_MESSAGE.message]__: The actual message
  * __[LAST_MESSAGE.fieldname]__: Replaces with the field `fieldname` in the logged record i.e. "`[LAST_MESSAGE.path]`" would display the full logpath where the message originated from. `fieldname` is case-sensitive. If a `fieldname` does not exist in the message, the template field is deleted in the message.
* __JIRA task title__: Sets the title of the JIRA task. Can include `[MESSAGE_REGEX]`(see __Message regex__). Can also include any field via `[LAST_MESSAGE.fieldname]`
* __Message regex__: A regular expression to extract a portion of the message. This is used to extract an exception message and can be used to populate the __JIRA task title__ or the __JIRA MD5 pattern__
* __JIRA MD5 pattern__: A string of multiple placeholders patterns to calculate a MD5 pattern which is used to avoid duplicates in JIRA. It defaults to __[MESSAGE_REGEX]__ but can also include any field from __[LAST_MESSAGE.*]__:
  * Create a MD5 consisting of message regex and message source: __[LAST_MESSAGE.source][MESSAGE_REGEX]__
  * Create a MD5 consisting of fields from the message: __[LAST_MESSAGE.source][LAST_MESSAGE.errorCode][LAST_MESSAGE.tags][LAST_MESSAGE.type]__
  * If a specified field does not exist in the last message, it will be skipped as part of the MD5 generation
* __JIRA MD5 custom field__: The JIRA custom-field name (typically called `customfield_####`. If the field is not set, the plugin will search the JIRA tasks meta-data for the `graylog_md5` and then use the defined custom-field automatically. It is preferred to specify the custom-field to avoid giving the JIRA user edit-permissions (and to also avoid another JIRA lookup call)
  * You can get the custom-field id via the JIRA interface or by calling https://MYJIRA.SERVER.COM/rest/api/2/issue/[ISSUE_KEY]/editmeta and then search for `graylog_md5`. 
* __JIRA duplicate filter query__: An optional filter query which is used when searching for the MD5 field in JIRA. The filter query must contain the `AND` term and can include any valid JQL - i.e. `AND Status not in (Closed, Done, Resolved)`.
* __JIRA/Graylog field mapping__: An optional comma-separated list of Graylog message-fields mapping into JIRA. The list needs to be in the format of `graylogmessagefieldname1=jirafieldname1,graylogmessagefieldname2=jirafieldname2` 
  * JIRA fields which are iterable (such as `fixVersions` or `versions`) need to be configured as `fixVersions#i`   

### Callback examples

If a log-message contains:
```
H/M 07/03/16 15:37:23 tcbobe-56 OrderStructureIO java.sql.SQLIntegrityConstraintViolationException: ORA-00001: unique constraint (PRODZA.ORDERS_PK) violated
at oracle.jdbc.driver.T4CTTIoer.processError(T4CTTIoer.java:450)
at oracle.jdbc.driver.T4CTTIoer.processError(T4CTTIoer.java:399)
at oracle.jdbc.driver.T4C8Oall.processError(T4C8Oall.java:1059)
at oracle.jdbc.driver.T4CTTIfun.receive(T4CTTIfun.java:522)
at oracle.jdbc.driver.T4CTTIfun.doRPC(T4CTTIfun.java:257)
at oracle.jdbc.driver.T4C8Oall.doOALL(T4C8Oall.java:587)
at oracle.jdbc.driver.T4CPreparedStatement.doOall8(T4CPreparedStatement.java:225)
at oracle.jdbc.driver.T4CPreparedStatement.doOall8(T4CPreparedStatement.java:53)
at oracle.jdbc.driver.T4CPreparedStatement.executeForRows(T4CPreparedStatement.java:943)
at oracle.jdbc.driver.OracleStatement.doExecuteWithTimeout(OracleStatement.java:1150)
at oracle.jdbc.driver.OraclePreparedStatement.executeInternal(OraclePreparedStatement.java:4798)
at oracle.jdbc.driver.OraclePreparedStatement.executeUpdate(OraclePreparedStatement.java:4875)
at oracle.jdbc.driver.OraclePreparedStatementWrapper.executeUpdate(OraclePreparedStatementWrapper.java:1361)
```

With the following settings:
* __Message regex__ = `([a-zA-Z_.]+(?!.*Exception): .+)`
* __JIRA task title__ = `[Graylog-[LAST_MESSAGE.source]] [MESSAGE_REGEX]` 
* __Message template__ = `*Alert triggered at:* \n [ALERT_TRIGGERED_AT]\n\n *Stream URL:* \n [STREAM_URL]\n\n*Source:* \n [LAST_MESSAGE.source]\n\n *Message:* \n [LAST_MESSAGE.message]\n\n`
* __JIRA MD5 pattern__ = `[MESSAGE_REGEX]`

The JIRA issue will be logged as follows:
![JIRA issue](https://raw.githubusercontent.com/magicdude4eva/graylog-jira-alarmcallback/master/screenshots/screenshot-jira.png)
 
## Copyright

Original idea from https://github.com/tjackiw/graylog-plugin-jira
