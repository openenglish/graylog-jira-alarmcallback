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

import java.net.URI;
import java.net.URISyntaxException;
import java.util.*;

import com.bidorbuy.graylog.alarmcallbacks.jira.util.JiraUtil;
import org.graylog2.plugin.alarms.AlertCondition;
import org.graylog2.plugin.alarms.callbacks.*;
import org.graylog2.plugin.configuration.*;
import org.graylog2.plugin.configuration.fields.ConfigurationField;
import org.graylog2.plugin.configuration.fields.TextField;
import org.graylog2.plugin.streams.Stream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.Maps;

public class JiraAlarmCallback implements AlarmCallback {

    private static final Logger LOG = LoggerFactory.getLogger(JiraAlarmCallback.class);

    // Configuration Constants
    public static final String JIRA_INSTANCE_URL = "jira_instance_url";
    public static final String JIRA_USERNAME = "jira_username";
    public static final String JIRA_PASSWORD = "jira_password";
    public static final String JIRA_PROJECT_KEY = "jira_project_key";
    public static final String JIRA_TITLE_TEMPLATE = "jira_title_template";
    public static final String JIRA_ISSUE_TYPE = "jira_issue_type";
    public static final String JIRA_LABELS = "jira_labels";
    public static final String JIRA_PRIORITY = "jira_priority";
    public static final String JIRA_COMPONENTS = "jira_components";
    public static final String JIRA_MESSAGE_TEMPLATE = "jira_message_template";
    public static final String JIRA_MD5_HASH_PATTERN = "jira_md5_hash_pattern";
    public static final String JIRA_MD5_FILTER_QUERY = "jira_md5_filter_query";
    public static final String JIRA_GRAYLOG_MESSAGE_FIELD_MAPPING = "jira_graylog_message_field_mapping";

    public static final String JIRA_MD5_CUSTOM_FIELD = "jira_md5_custom_field";

    public static final String GRAYLOG_URL = "graylog_url";
    public static final String GRAYLOG_HISTOGRAM_TIME_SPAN = "graylog_histogram_time_span";
    public static final String MESSAGE_REGEX = "message_regex";

    // Validation rules for config check
    private static final List<String> SENSITIVE_CONFIGURATION_KEYS = ImmutableList.of(JIRA_PASSWORD);

    private static final String[] CONFIGURATION_KEYS_MANDATORY = new String[]{JIRA_INSTANCE_URL, JIRA_USERNAME, JIRA_PASSWORD, JIRA_PROJECT_KEY, JIRA_ISSUE_TYPE};
    private static final String[] CONFIGURATION_KEYS_URL_VALIDATION = new String[]{JIRA_INSTANCE_URL, GRAYLOG_URL};

    // The message regex template used to extract content for an exception MD5
    public static final String EXAMPLE_JIRA_MESSAGE_REGEX = "([a-zA-Z_.]+(?!.*Exception): .+)";
    public static final String EXAMPLE_JIRA_MD5_TEMPLATE = "[MESSAGE_REGEX]";
    public static final String EXAMPLE_JIRA_MD5_FILTER_QUERY_TEMPLATE = "AND Status not in (Closed, Done, Resolved)";

    // The default title template for JIRA messages
    public static final String DEFAULT_JIRA_TITLE_TEMPLATE = "Jira [MESSAGE_REGEX]";
    public static final String DEFAULT_JIRA_MESSAGE_TEMPLATE = "[STREAM_RESULT]\\n\\n" +
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

                JiraUtil.buildJIRATitle(configuration, stream, result),
                JiraUtil.buildJIRADescription(configuration, stream, result),
                JiraUtil.buildJIRAGraylogMapping(configuration, result),
                JiraUtil.buildJIRAMessageDigest(configuration, result));

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
            if (!JiraUtil.isSetAndNotNullText(configuration, key)) {
                throw new ConfigurationException(key + " is mandatory and must not be empty.");
            }
        }

        // Check if the provided URLs are valid
        for (String key : CONFIGURATION_KEYS_URL_VALIDATION) {
            if (JiraUtil.isSetAndNotNullText(configuration, key)) {
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

}
