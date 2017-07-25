/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2016 Gerd Naschenweng / bidorbuy.co.za
 *
 * Original idea from https://github.com/tjackiw/graylog-plugin-jira
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */

package com.bidorbuy.graylog.alarmcallbacks.jira;

import java.math.BigInteger;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.MessageDigest;
import java.util.*;
import java.util.regex.*;

import com.openenglish.util.StringUtil;
import org.apache.commons.lang3.StringEscapeUtils;
import org.apache.commons.lang3.StringUtils;
import org.graylog2.plugin.MessageSummary;
import org.graylog2.plugin.Tools;
import org.graylog2.plugin.alarms.AlertCondition;
import org.graylog2.plugin.alarms.callbacks.*;
import org.graylog2.plugin.configuration.*;
import org.graylog2.plugin.configuration.fields.ConfigurationField;
import org.graylog2.plugin.configuration.fields.TextField;
import org.graylog2.plugin.streams.Stream;
import org.graylog2.plugin.streams.StreamRule;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.Maps;

public class JiraAlarmCallback implements AlarmCallback {

    // The logger
    private static final Logger LOG = LoggerFactory.getLogger(JiraAlarmCallback.class);

    // Configuration Constants
    private static final String JIRA_INSTANCE_URL = "jira_instance_url";
    private static final String JIRA_USERNAME = "jira_username";
    private static final String JIRA_PASSWORD = "jira_password";
    private static final String JIRA_PROJECT_KEY = "jira_project_key";
    private static final String JIRA_TITLE_TEMPLATE = "jira_title_template";
    private static final String JIRA_ISSUE_TYPE = "jira_issue_type";
    private static final String JIRA_LABELS = "jira_labels";
    private static final String JIRA_PRIORITY = "jira_priority";
    private static final String JIRA_COMPONENTS = "jira_components";
    private static final String JIRA_MESSAGE_TEMPLATE = "jira_message_template";
    private static final String JIRA_MD5_HASH_PATTERN = "jira_md5_hash_pattern";
    private static final String JIRA_MD5_FILTER_QUERY = "jira_md5_filter_query";
    private static final String JIRA_GRAYLOG_MESSAGE_FIELD_MAPPING = "jira_graylog_message_field_mapping";

    static final String JIRA_MD5_CUSTOM_FIELD = "jira_md5_custom_field";

    private static final String GRAYLOG_URL = "graylog_url";
    private static final String GRAYLOG_HISTOGRAM_TIME_SPAN = "graylog_histogram_time_span";
    private static final String MESSAGE_REGEX = "message_regex";

    // Validation rules for config check
    private static final List<String> SENSITIVE_CONFIGURATION_KEYS = ImmutableList.of(JIRA_PASSWORD);

    private static final String[] CONFIGURATION_KEYS_MANDATORY = new String[]{JIRA_INSTANCE_URL, JIRA_USERNAME, JIRA_PASSWORD, JIRA_PROJECT_KEY, JIRA_ISSUE_TYPE};
    private static final String[] CONFIGURATION_KEYS_URL_VALIDATION = new String[]{JIRA_INSTANCE_URL, GRAYLOG_URL};

    // The message regex template used to extract content for an exception MD5
    private static final String EXAMPLE_JIRA_MESSAGE_REGEX = "([a-zA-Z_.]+(?!.*Exception): .+)";
    private static final String EXAMPLE_JIRA_MD5_TEMPLATE = "[MESSAGE_REGEX]";
    private static final String EXAMPLE_JIRA_MD5_FILTER_QUERY_TEMPLATE = "AND Status not in (Closed, Done, Resolved)";

    // The default title template for JIRA messages
    private static final String DEFAULT_JIRA_TITLE_TEMPLATE = "Jira [MESSAGE_REGEX]";
    private static final String DEFAULT_JIRA_MESSAGE_TEMPLATE = "[STREAM_RESULT]\\n\\n" +
            "*Stream title:*\\n[STREAM_TITLE]\\n\\n" +
            "*Stream URL:*\\n[STREAM_URL]\\n\\n" +
            "*Stream rules:*\\n[STREAM_RULES]\\n\\n" +
            "*Alert triggered at:*\\n[ALERT_TRIGGERED_AT]\\n\\n" +
            "*Triggered condition:*\\n[ALERT_TRIGGERED_CONDITION]\\n\\n" +
            "*Source:*\\n[LAST_MESSAGE.source]\\n\\n" +
            "*Message:*\\n[LAST_MESSAGE.message]\\n\\n";

    // The plugin configuration
    private Configuration configuration;

    /**
     * This is called once at the very beginning of the lifecycle of this plugin. It is common practice to
     * store the Configuration as a private member for later access.
     *
     * @see org.graylog2.plugin.alarms.callbacks.AlarmCallback#initialize(org.graylog2.plugin.configuration.Configuration)
     */
    @Override
    public void initialize(final Configuration configuration) throws AlarmCallbackConfigurationException {
        LOG.debug("Starting initialize(...)");

        this.configuration = configuration;

        LOG.debug("Finishing initialize(...)");
    }

    /**
     * Plugins can request configurations. The UI in the Graylog web interface is generated from this information and
     * the filled out configuration values are passed back to the plugin in initialize(Configuration configuration).
     * <p>
     * These values (including the default) are used to populate the form ONLY WHEN A NEW Notification is in the process of being created using the Graylog UI.
     *
     * @see org.graylog2.plugin.alarms.callbacks.AlarmCallback#getRequestedConfiguration()
     */
    @Override
    public ConfigurationRequest getRequestedConfiguration() {
        LOG.debug("Starting getRequestedConfiguration()");

        final ConfigurationRequest configurationRequest = new ConfigurationRequest();

        configurationRequest.addField(new TextField(
                JIRA_INSTANCE_URL, "JIRA Instance URL", "", "JIRA server URL.",
                ConfigurationField.Optional.NOT_OPTIONAL));

        configurationRequest.addField(new TextField(
                JIRA_USERNAME, "JIRA username", "", "Username to login to JIRA and create issues.",
                ConfigurationField.Optional.NOT_OPTIONAL));

        configurationRequest.addField(new TextField(
                JIRA_PASSWORD, "JIRA password", "", "Password to login to JIRA.",
                ConfigurationField.Optional.NOT_OPTIONAL, TextField.Attribute.IS_PASSWORD));

        configurationRequest.addField(new TextField(
                JIRA_PROJECT_KEY, "JIRA project Key", "", "Project under which the issue will be created.",
                ConfigurationField.Optional.NOT_OPTIONAL));

        configurationRequest.addField(new TextField(
                JIRA_ISSUE_TYPE, "JIRA issue Type", "Bug", "Type of issue.",
                ConfigurationField.Optional.NOT_OPTIONAL));

        configurationRequest.addField(new TextField(
                JIRA_MESSAGE_TEMPLATE, "JIRA message template", DEFAULT_JIRA_MESSAGE_TEMPLATE, "Message template for JIRA. Use \\n to separate lines.",
                ConfigurationField.Optional.NOT_OPTIONAL));

        configurationRequest.addField(new TextField(
                JIRA_TITLE_TEMPLATE, "JIRA issue title template", DEFAULT_JIRA_TITLE_TEMPLATE, "Title template for JIRA tasks.",
                ConfigurationField.Optional.NOT_OPTIONAL));

        configurationRequest.addField(new TextField(
                GRAYLOG_URL, "Graylog URL", null, "URL to your Graylog web interface. Used to build links in alarm notification.",
                ConfigurationField.Optional.NOT_OPTIONAL));

        configurationRequest.addField(new TextField(
                GRAYLOG_HISTOGRAM_TIME_SPAN, "Graylog Histogram Time Span", "30", "Time span (in seconds) for displaying Graylog Histogram messages.",
                ConfigurationField.Optional.NOT_OPTIONAL));

        configurationRequest.addField(new TextField(
                JIRA_PRIORITY, "JIRA Issue Priority", "Low", "Priority of the issue.",
                ConfigurationField.Optional.OPTIONAL));

        configurationRequest.addField(new TextField(
                JIRA_LABELS, "JIRA Labels", "", "List of comma-separated labels to add to this issue - i.e. graylog",
                ConfigurationField.Optional.OPTIONAL));

        configurationRequest.addField(new TextField(
                JIRA_COMPONENTS, "JIRA Components", "", "List of comma-separated components to add to this issue.",
                ConfigurationField.Optional.OPTIONAL));

        configurationRequest.addField(new TextField(
                MESSAGE_REGEX, "Message regex", "", "Message regex to extract message content. Example: " + EXAMPLE_JIRA_MESSAGE_REGEX,
                ConfigurationField.Optional.OPTIONAL));

        configurationRequest.addField(new TextField(
                JIRA_MD5_HASH_PATTERN, "JIRA MD5 pattern", "", "Pattern to construct MD5. Example: " + EXAMPLE_JIRA_MD5_TEMPLATE,
                ConfigurationField.Optional.OPTIONAL));

        configurationRequest.addField(new TextField(
                JIRA_MD5_CUSTOM_FIELD, "JIRA MD5 custom field", "", "Custom field name for the MD5 hash, this will be in the format of customfield_####. If not set, we will try and find it.",
                ConfigurationField.Optional.OPTIONAL));

        configurationRequest.addField(new TextField(
                JIRA_MD5_FILTER_QUERY, "JIRA duplicate filter query", "", "Additional filter query to check for duplicates. Example: " + EXAMPLE_JIRA_MD5_FILTER_QUERY_TEMPLATE,
                ConfigurationField.Optional.OPTIONAL));

        configurationRequest.addField(new TextField(
                JIRA_GRAYLOG_MESSAGE_FIELD_MAPPING, "JIRA/Graylog field mapping", "", "List of comma-separated Graylog/JIRA mapping fields to automatically map Graylog message fields into JIRA.",
                ConfigurationField.Optional.OPTIONAL));

        LOG.debug("Finishing getRequestedConfiguration()");

        return configurationRequest;
    }

    /**
     * This is the actual alarm callback being triggered.
     *
     * @see org.graylog2.plugin.alarms.callbacks.AlarmCallback#call(org.graylog2.plugin.streams.Stream, org.graylog2.plugin.alarms.AlertCondition.CheckResult)
     */
    @Override
    public void call(final Stream stream, final AlertCondition.CheckResult result) throws AlarmCallbackException {
        LOG.debug("Starting call(...)");

        JiraIssueClient jiraIssueClient = new JiraIssueClient(
                configuration.getString(JIRA_INSTANCE_URL),
                configuration.getString(JIRA_USERNAME),
                configuration.getString(JIRA_PASSWORD),

                configuration.getString(JIRA_PROJECT_KEY),
                configuration.getString(JIRA_LABELS),
                configuration.getString(JIRA_ISSUE_TYPE),
                configuration.getString(JIRA_COMPONENTS),
                configuration.getString(JIRA_PRIORITY),
                configuration.getString(JIRA_MD5_FILTER_QUERY),
                configuration.getString(JIRA_MD5_CUSTOM_FIELD),

                buildJIRATitle(configuration, stream, result),
                buildJIRADescription(configuration, stream, result),
                buildJIRAGraylogMapping(configuration, result),
                buildJIRAMessageDigest(configuration, result));

        jiraIssueClient.trigger();

        LOG.debug("Finishing call(...)");
    }

    /**
     * Return attributes that might be interesting to be shown under the alarm callback in the Graylog web interface.
     * It is common practice to at least return the used configuration here.
     *
     * @see org.graylog2.plugin.alarms.callbacks.AlarmCallback#getAttributes()
     */
    @Override
    public Map<String, Object> getAttributes() {
        return Maps.transformEntries(configuration.getSource(), new Maps.EntryTransformer<String, Object, Object>() {
            @Override
            public Object transformEntry(String key, Object value) {
                if (SENSITIVE_CONFIGURATION_KEYS.contains(key)) {
                    return "****";
                }
                return value;
            }
        });
    }

    /**
     * Throw a ConfigurationException if the user should have entered missing or invalid configuration parameters.
     *
     * @see org.graylog2.plugin.alarms.callbacks.AlarmCallback#checkConfiguration()
     */
    @Override
    public void checkConfiguration() throws ConfigurationException {
        LOG.debug("Starting checkConfiguration()");

        // Check if we have all mandatory keys
        for (String key : CONFIGURATION_KEYS_MANDATORY) {
            if (!isSetAndNotNullText(configuration, key)) {
                throw new ConfigurationException(key + " is mandatory and must not be empty.");
            }
        }

        // Check if the provided URLs are valid
        for (String key : CONFIGURATION_KEYS_URL_VALIDATION) {
            if (isSetAndNotNullText(configuration, key)) {
                try {
                    final URI configURI = new URI(configuration.getString(key));
                    if (!"http".equals(configURI.getScheme()) && !"https".equals(configURI.getScheme())) {
                        throw new ConfigurationException(key + " must be a valid HTTP or HTTPS URL.");
                    }
                } catch (URISyntaxException e) {
                    throw new ConfigurationException("Couldn't parse " + key + " correctly.", e);
                }
            }
        }

        LOG.debug("Finishing checkConfiguration()");
    }

    /**
     * Return a human readable name of this plugin.
     *
     * @see org.graylog2.plugin.alarms.callbacks.AlarmCallback#getName()
     */
    @Override
    public String getName() {
        return "OE - Graylog JIRA integration plugin";
    }

    /**
     * Build the JIRA issue title
     */
    private static String buildJIRATitle(final Configuration configuration, final Stream stream, final AlertCondition.CheckResult result) {
        LOG.debug("Starting buildJIRATitle(...)");

        LOG.info("result.getResultDescription(): " + result.getResultDescription());

        String title = "[Alert] Graylog alert for stream: " + stream.getTitle();

        try {
            if (!result.getMatchingMessages().isEmpty()) {
                // get fields from last message only
                MessageSummary lastMessage = result.getMatchingMessages().get(0);

                String message = lastMessage.getMessage();
                LOG.info("lastMessage.getMessage(): " + message);

                LOG.info("configuration.getString(JIRA_TITLE_TEMPLATE): " + configuration.getString(JIRA_TITLE_TEMPLATE));

                LOG.info("title (initial): " + title);

                if (isSetAndNotNullText(configuration, JIRA_TITLE_TEMPLATE)) {
                    title = configuration.getString(JIRA_TITLE_TEMPLATE);
                }

                LOG.info("title (template): " + title);

                title = replaceMessageSummaryPlaceholders(title, lastMessage);

                LOG.info("title (after placeholders): " + title);

                LOG.info("MESSAGE_REGEX: " + MESSAGE_REGEX);

                String regex = configuration.getString(MESSAGE_REGEX);
                LOG.info("configuration.getString(MESSAGE_REGEX): " + regex);

                if (isSetAndNotNullText(configuration, MESSAGE_REGEX)) {
                    String capturedGroupName = "relevant";
                    title = StringUtil.captureGroupAndReplace(title, message, regex, capturedGroupName);
                }
            }
        } catch (Exception ex) {
            // can not do anything - we skip
            LOG.info("error-Error in building title: " + ex.getMessage());
        }

        LOG.debug("Finishing buildJIRATitle(...)");

        return title;
    }

    private static boolean isSetAndNotNullText(Configuration configuration, String fieldName) {
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
    private static String buildJIRADescription(final Configuration configuration, final Stream stream, final AlertCondition.CheckResult result) {
        LOG.debug("Starting buildJIRADescription(...)");

        String message = DEFAULT_JIRA_MESSAGE_TEMPLATE;

        if (isSetAndNotNullText(configuration, JIRA_MESSAGE_TEMPLATE)) {
            message = configuration.getString(JIRA_MESSAGE_TEMPLATE);
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
     * Build stream URL string
     */
    private static String buildStreamURL(final Configuration configuration, final Stream stream) {
        String baseUrl = configuration.getString(GRAYLOG_URL);

        if (!baseUrl.endsWith("/")) {
            baseUrl += "/";
        }

        return baseUrl + "streams/" + stream.getId() + "/messages?q=*&rangetype=relative&relative=" + configuration.getString(GRAYLOG_HISTOGRAM_TIME_SPAN);
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
    private static Map<String, String> buildJIRAGraylogMapping(final Configuration configuration, final AlertCondition.CheckResult result) {
        LOG.debug("Starting buildJIRAGraylogMapping(...)");

        Map<String, String> JIRAFieldMapping = new HashMap<>();

        if (isSetAndNotNullText(configuration, JIRA_GRAYLOG_MESSAGE_FIELD_MAPPING) && !result.getMatchingMessages().isEmpty()) {
            try {
                // get fields from last message only
                MessageSummary lastMessage = result.getMatchingMessages().get(0);

                String[] mappingPairs = StringUtils.split(configuration.getString(JIRA_GRAYLOG_MESSAGE_FIELD_MAPPING), ',');

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
    private static String buildJIRAMessageDigest(final Configuration configuration, final AlertCondition.CheckResult result) {
        LOG.debug("Starting buildJIRAMessageDigest(...)");

        String jiraMessageMatch = "";
        String jiraMD5HashPattern = "";
        String jiraMessageDigest = "";

        // Get the last message
        if (!result.getMatchingMessages().isEmpty()) {

            MessageSummary lastMessage = result.getMatchingMessages().get(0);

            // Let's extract the message regex first
            if (isSetAndNotNullText(configuration, MESSAGE_REGEX)) {
                try {
                    Matcher matcher = Pattern.compile(configuration.getString(MESSAGE_REGEX)).matcher(lastMessage.getMessage());

                    if (matcher.find()) {
                        jiraMessageMatch = lastMessage.getMessage().substring(matcher.start());
                    }
                } catch (Exception ex) {
                    LOG.info("warn-Error in JIRA-issue MD5-MESSAGE_REGEX generation: " + ex.getMessage());
                }
            }

            // Let's extract the message regex first
            if (isSetAndNotNullText(configuration, JIRA_MD5_HASH_PATTERN)) {

                try {
                    jiraMD5HashPattern = configuration.getString(JIRA_MD5_HASH_PATTERN);

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
