package com.bidorbuy.graylog.alarmcallbacks.jira.util;

import com.bidorbuy.graylog.alarmcallbacks.jira.JiraAlarmCallback;
import com.openenglish.util.StringUtil;
import org.apache.commons.lang3.StringEscapeUtils;
import org.apache.commons.lang3.StringUtils;
import org.graylog2.plugin.MessageSummary;
import org.graylog2.plugin.Tools;
import org.graylog2.plugin.alarms.AlertCondition;
import org.graylog2.plugin.configuration.Configuration;
import org.graylog2.plugin.streams.Stream;
import org.graylog2.plugin.streams.StreamRule;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class JiraUtil {

    private static final Logger LOG = LoggerFactory.getLogger(JiraUtil.class);

    /**
     * Build stream URL string
     */
    public static String buildStreamURL(final Configuration configuration, final Stream stream) {
        String baseUrl = configuration.getString(JiraAlarmCallback.GRAYLOG_URL);

        if (!baseUrl.endsWith("/")) {
            baseUrl += "/";
        }

        return baseUrl + "streams/" + stream.getId() + "/messages?q=*&rangetype=relative&relative=" + configuration.getString(JiraAlarmCallback.GRAYLOG_HISTOGRAM_TIME_SPAN);
    }

    /**
     * Build the JIRA issue title
     */
    public static String buildJIRATitle(final Configuration configuration, final Stream stream, final AlertCondition.CheckResult result) {
        LOG.debug("Starting buildJIRATitle(...)");

        LOG.info("result.getResultDescription(): " + result.getResultDescription());

        String title = "[Alert] Graylog alert for stream: " + stream.getTitle();

        try {
            if (!result.getMatchingMessages().isEmpty()) {
                // get fields from last message only
                MessageSummary lastMessage = result.getMatchingMessages().get(0);

                String message = lastMessage.getMessage();
                LOG.info("lastMessage.getMessage(): " + message);

                LOG.info("configuration.getString(JIRA_TITLE_TEMPLATE): " + configuration.getString(JiraAlarmCallback.JIRA_TITLE_TEMPLATE));

                LOG.info("title (initial): " + title);

                if (isSetAndNotNullText(configuration, JiraAlarmCallback.JIRA_TITLE_TEMPLATE)) {
                    title = configuration.getString(JiraAlarmCallback.JIRA_TITLE_TEMPLATE);
                }

                LOG.info("title (template): " + title);

                title = replaceMessageSummaryPlaceholders(title, lastMessage);

                LOG.info("title (after placeholders): " + title);

                LOG.info("MESSAGE_REGEX: " + JiraAlarmCallback.MESSAGE_REGEX);

                String regex = configuration.getString(JiraAlarmCallback.MESSAGE_REGEX);
                LOG.info("configuration.getString(MESSAGE_REGEX): " + regex);

                if (isSetAndNotNullText(configuration, JiraAlarmCallback.MESSAGE_REGEX)) {
                    title = StringUtil.captureGroupAndReplace(title, message, regex);
                }
            }
        } catch (Exception ex) {
            // can not do anything - we skip
            LOG.info("error-Error in building title: " + ex.getMessage());
        }

        LOG.debug("Finishing buildJIRATitle(...)");

        return title;
    }

    public static boolean isSetAndNotNullText(Configuration configuration, String fieldName) {
        return configuration.stringIsSet(fieldName) && !configuration.getString(fieldName).equals("null");
    }

    private static String replaceMessageSummaryPlaceholders(String s, MessageSummary messageSummary) {
        s = s.replace("[LAST_MESSAGE.message]", messageSummary.getMessage());
        s = s.replace("[LAST_MESSAGE.source]", messageSummary.getSource());

        // iterate through all the message fields and replace the template
        Map<String, Object> lastMessageFields = messageSummary.getFields();
        for (Map.Entry<String, Object> arg : lastMessageFields.entrySet()) {
            s = s.replace("[LAST_MESSAGE." + arg.getKey() + "]", arg.getValue().toString());
        }

        // We regex template fields which have not been replaced
        s = s.replaceAll("\\[LAST_MESSAGE\\.[^\\]]*\\]", "");
        return s;
    }

    private static String replaceStandardPlaceholders(String s, final Configuration configuration, final Stream stream, final AlertCondition.CheckResult result) {
        // replace placeholders
        s = s.replace("[CALLBACK_DATE]", Tools.iso8601().toString()); // e.g. 2017-07-21T18:19:44.243Z
        s = s.replace("[STREAM_ID]", stream.getId()); // e.g. 5968db3189c88913066fc469
        s = s.replace("[STREAM_TITLE]", stream.getTitle()); // e.g. oe-wolverine WARN
        s = s.replace("[STREAM_URL]", buildStreamURL(configuration, stream)); // e.g. http://graylog.openenglish.com/streams/5968db3189c88913066fc469/messages?q=*&rangetype=relative&relative=35
        s = s.replace("[STREAM_RULES]", buildStreamRules(stream)); // e.g source REGEX ^wolverine[0-9]$ message CONTAINS WARN
        s = s.replace("[STREAM_RESULT]", result.getResultDescription()); // e.g. Stream had 2614 messages in the last 5 minutes with trigger condition more than 0 messages. (Current grace time: 1 minutes)
        s = s.replace("[ALERT_TRIGGERED_AT]", result.getTriggeredAt().toString()); // e.g. 2017-07-21T17:09:55.701Z
        s = s.replace("[ALERT_TRIGGERED_CONDITION]", result.getTriggeredCondition().toString()); // e.g. 32044c6a-7d73-4155-ba04-44323b403002:message_count={time: 5, threshold_type: more, threshold: 0, grace: 1, repeat notifications: true}, stream:={5968db3189c88913066fc469: "oe-wolverine WARN"}

        return s;
    }

    /**
     * Build the JIRA description
     */
    public static String buildJIRADescription(final Configuration configuration, final Stream stream, final AlertCondition.CheckResult result) {
        LOG.debug("Starting buildJIRADescription(...)");

        String message = JiraAlarmCallback.DEFAULT_JIRA_MESSAGE_TEMPLATE;

        if (isSetAndNotNullText(configuration, JiraAlarmCallback.JIRA_MESSAGE_TEMPLATE)) {
            message = configuration.getString(JiraAlarmCallback.JIRA_MESSAGE_TEMPLATE);
        }

        message = StringEscapeUtils.unescapeJava(message);

        // Get the last message
        if (!result.getMatchingMessages().isEmpty()) {
            // get fields from last message only
            MessageSummary lastMessage = result.getMatchingMessages().get(0);

            message = replaceMessageSummaryPlaceholders(message, lastMessage);
        }

        message = replaceStandardPlaceholders(message, configuration, stream, result);

        LOG.debug("Finishing buildJIRADescription(...)");

        return "\n\n" + message + "\n\n";
    }

    /**
     * Build the stream rules
     */
    private static String buildStreamRules(final Stream stream) {

        StringBuilder sb = new StringBuilder();

        for (StreamRule streamRule : stream.getStreamRules()) {
            sb.append("_").append(streamRule.getField()).append("_ ");
            sb.append(streamRule.getType()).append(" _").append(streamRule.getValue())
                    .append("_").append("\n");
        }
        return sb.toString();
    }

    /**
     * Build up a list of JIRA/Graylog field mappings
     */
    public static Map<String, String> buildJIRAGraylogMapping(final Configuration configuration, final AlertCondition.CheckResult result) {
        LOG.debug("Starting buildJIRAGraylogMapping(...)");

        Map<String, String> JIRAFieldMapping = new HashMap<>();

        if (isSetAndNotNullText(configuration, JiraAlarmCallback.JIRA_GRAYLOG_MESSAGE_FIELD_MAPPING) && !result.getMatchingMessages().isEmpty()) {
            try {
                // get fields from last message only
                MessageSummary lastMessage = result.getMatchingMessages().get(0);

                String[] mappingPairs = StringUtils.split(configuration.getString(JiraAlarmCallback.JIRA_GRAYLOG_MESSAGE_FIELD_MAPPING), ',');

                if (mappingPairs != null && mappingPairs.length > 0) {
                    for (String mappingString : mappingPairs) {
                        String[] mapping = StringUtils.split(mappingString, '=');

                        if (mapping.length == 2 && lastMessage.hasField(mapping[0])) {
                            Object test = lastMessage.getField(mapping[0]);
                            JIRAFieldMapping.put(mapping[1], test.toString());
                        }
                    }
                }
            } catch (Exception ex) {
                // can not do anything - we skip
                LOG.info("error-Error in generating JIRA/Graylog mapping " + ex.getMessage());
            }
        }

        LOG.debug("Finishing buildJIRAGraylogMapping(...)");

        return JIRAFieldMapping;
    }

    /**
     * Generates the MD5 digest of either the message or a number of fields provided
     */
    public static String buildJIRAMessageDigest(final Configuration configuration, final AlertCondition.CheckResult result) {
        LOG.debug("Starting buildJIRAMessageDigest(...)");

        String jiraMessageMatch = "";
        String jiraMD5HashPattern = "";
        String jiraMessageDigest = "";

        // Get the last message
        if (!result.getMatchingMessages().isEmpty()) {

            MessageSummary lastMessage = result.getMatchingMessages().get(0);

            // Let's extract the message regex first
            if (isSetAndNotNullText(configuration, JiraAlarmCallback.MESSAGE_REGEX)) {
                try {
                    Matcher matcher = Pattern.compile(configuration.getString(JiraAlarmCallback.MESSAGE_REGEX)).matcher(lastMessage.getMessage());

                    if (matcher.find()) {
                        jiraMessageMatch = lastMessage.getMessage().substring(matcher.start());
                    }
                } catch (Exception ex) {
                    LOG.info("warn-Error in JIRA-issue MD5-MESSAGE_REGEX generation: " + ex.getMessage());
                }
            }

            // Let's extract the message regex first
            if (isSetAndNotNullText(configuration, JiraAlarmCallback.JIRA_MD5_HASH_PATTERN)) {

                try {
                    jiraMD5HashPattern = configuration.getString(JiraAlarmCallback.JIRA_MD5_HASH_PATTERN);

                    // replace the message-regex place-holder
                    jiraMD5HashPattern = jiraMD5HashPattern.replace("[MESSAGE_REGEX]", jiraMessageMatch);

                    jiraMD5HashPattern = replaceMessageSummaryPlaceholders(jiraMD5HashPattern, lastMessage);
                } catch (Exception ex) {
                    LOG.info("warn-Error in JIRA-issue MD5-HASH_PATTERN generation: " + ex.getMessage());
                }
            }

            // We default the extracted message as the template
            if (StringUtils.isBlank(jiraMD5HashPattern)) {
                jiraMD5HashPattern = jiraMessageMatch;
            }

            // Create the MD5 from the template
            if (StringUtils.isNotBlank(jiraMD5HashPattern)) {
                try {
                    MessageDigest m = MessageDigest.getInstance("MD5");
                    m.update(jiraMD5HashPattern.getBytes(), 0, jiraMD5HashPattern.length());
                    jiraMessageDigest = new BigInteger(1, m.digest()).toString(16);
                } catch (Exception ex) {
                    LOG.info("warn-Error in JIRA-issue MD5 generation (MD5-string=" + jiraMD5HashPattern + "): " + ex.getMessage());
                }
            } else {
                LOG.info("warn-Skipped MD5-hash creation, MD5-string is empty. Check your config.");
            }
        } else {
            LOG.info("warn-Skipping JIRA-issue MD5 generation, alarmcallback did not provide a message.");
        }

        LOG.debug("Finishing buildJIRAMessageDigest(...)");

        return jiraMessageDigest;
    }
}
