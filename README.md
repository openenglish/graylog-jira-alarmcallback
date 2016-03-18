# Graylog Plugin for JIRA with templating

A Graylog alarm callback plugin that integrates [Graylog](https://www.graylog.org/) into [JIRA](https://www.atlassian.com/software/jira/).

## Main features
* Templating in JIRA issue title and JIRA message via place holders
* Embed a MD5 hash into the JIRA issue to prevent duplicate JIRA issues

![Graylog JIRA plugin](https://raw.githubusercontent.com/magicdude4eva/graylog-jira-alarmcallback/master/screenshot-alert-config.png)

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
This plugin has been tested with Graylog v1.3.3 and JIRA v7.0.10.

Download the [latest release](https://github.com/magicdude4eva/graylog-jira-alarmcallback/releases) and copy the `.jar` file into your Graylog plugin directory (default is in `/usr/share/graylog-server/plugin`).
If you are unsure about the plugin location, do a `grep -i plugin_dir /etc/graylog/server/server.conf`.

Restart Graylog via `systemctl restart graylog-server`

Configuration
-------------

### Configure the stream alert
![Graylog callback configuration](https://raw.githubusercontent.com/magicdude4eva/graylog-jira-alarmcallback/master/screenshot-plugin-overview.png)

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
  * __[ALERT_TRIGGERED_AT]__: Timestamp when alert was triggered
  * __[ALERT_TRIGGERED_CONDITION]__: Conditions triggering the alert
  * __[LAST_MESSAGE.SOURCE]__: If a message is present, the placeholder will be replaced with the source origin of the message
  * __[LAST_MESSAGE.MESSAGE]__: The actual message
  * __[LAST_MESSAGE.FIELDNAME]__: Replaces with any field in the logged record. i.e. "`[LAST_MESSAGE.PATH]`" would display the full logpath where the message originated from.
* __JIRA task title__: Sets the title of the JIRA task. Can include `[MESSAGE_REGEX]`(see __Message regex__). Can also include any field via `[LAST_MESSAGE.FIELDNAME]`
* __Message regex__: A regular expression to extract a portion of the message. This is used to extract an exception message as well as to generate a MD5 hash to identify duplicate JIRA issues.
  

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
* __JIRA task title__ = `[Graylog-[LAST_MESSAGE.SOURCE]] [MESSAGE_REGEX]` 
* __Message template__ = `*Alert triggered at:* \n [ALERT_TRIGGERED_AT]\n\n *Stream URL:* \n [STREAM_URL]\n\n*Source:* \n [LAST_MESSAGE.SOURCE]\n\n *Message:* \n [LAST_MESSAGE.MESSAGE]\n\n`

The JIRA issue will be logged as follows:
![JIRA issue](https://raw.githubusercontent.com/magicdude4eva/graylog-jira-alarmcallback/master/screenshot-jira.png)
 
## Copyright

Original idea from https://github.com/tjackiw/graylog-plugin-jira
