package com.bidorbuy.graylog.alarmcallbacks.jira;

import net.rcarz.jiraclient.*;
import net.rcarz.jiraclient.Issue.FluentCreate;
import net.sf.json.JSONObject;
import org.apache.commons.lang3.StringUtils;
import org.graylog2.plugin.alarms.callbacks.AlarmCallbackException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Map;


class JiraIssueClient {

    private static final Logger LOG = LoggerFactory.getLogger(JiraIssueClient.class);

    // The JIRA field-name for the MD5 - digest
    private static final String GRAYLOG_MD5 = "graylog_md5";

    private final String jiraServerURL;
    private final String jiraUserName;
    private final String jiraPassword;

    private final String jiraProjectKey;
    private final String jiraLabels;
    private final String jiraIssueType;
    private final String jiraComponents;
    private final String jiraPriority;
    private final String jiraDuplicateIssueFilterQuery;
    private final String jiraMD5CustomFieldName;

    private final String jiraTitle;
    private final String jiraDescription;
    private final Map<String, String> jiraGraylogMapping;
    private final String jiraMessageDigest;

    JiraIssueClient(
            final String jiraServerURL,
            final String jiraUserName,
            final String jiraPassword,

            final String jiraProjectKey,
            final String jiraLabels,
            final String jiraIssueType,
            final String jiraComponents,
            final String jiraPriority,
            final String jiraDuplicateIssueFilterQuery,
            final String jiraMD5CustomFieldName,

            final String jiraTitle,
            final String jiraDescription,
            final Map<String, String> jiraGraylogMapping,
            final String jiraMessageDigest) {

        this.jiraServerURL = jiraServerURL;
        this.jiraUserName = jiraUserName;
        this.jiraPassword = jiraPassword;

        this.jiraProjectKey = jiraProjectKey;
        this.jiraLabels = jiraLabels;
        this.jiraIssueType = jiraIssueType;
        this.jiraComponents = jiraComponents;
        this.jiraPriority = jiraPriority;
        this.jiraDuplicateIssueFilterQuery = jiraDuplicateIssueFilterQuery;
        this.jiraMD5CustomFieldName = jiraMD5CustomFieldName;

        this.jiraTitle = jiraTitle;
        this.jiraDescription = jiraDescription;
        this.jiraGraylogMapping = jiraGraylogMapping;
        this.jiraMessageDigest = jiraMessageDigest;
    }

    void trigger() throws AlarmCallbackException {
        LOG.debug("Starting trigger()");

        try {
            BasicCredentials basicCredentials = new BasicCredentials(jiraUserName, jiraPassword);

            JiraClient jiraClient = new JiraClient(jiraServerURL, basicCredentials);

            if (!isDuplicateJIRAIssue(jiraClient)) {
                createJIRAIssue(jiraClient);
            }
        } catch (Throwable ex) {
            LOG.error("Error in trigger function" + ex.getMessage() + (ex.getCause() != null ? ", Cause=" + ex.getCause().getMessage() : ""), ex);
            throw ex;
        }

        LOG.debug("Finishing trigger()");
    }

    /**
     * Checks if a JIRA issue is duplicated.
     */
    private boolean isDuplicateJIRAIssue(JiraClient jiraClient) throws AlarmCallbackException {
        boolean isDuplicate = false;

        if (StringUtils.isBlank(jiraMessageDigest)) {
            return false;
        }

        try {
            // Search for duplicate issues
            Issue.SearchResult srJiraIssues = jiraClient.searchIssues("project = " + jiraProjectKey
                            + (jiraDuplicateIssueFilterQuery != null && !jiraDuplicateIssueFilterQuery.isEmpty() ? " " + jiraDuplicateIssueFilterQuery + " " : "")
                            + " AND (" + GRAYLOG_MD5 + " ~ \"" + jiraMessageDigest + "\" OR"
                            + " description ~ \"" + jiraMessageDigest + "\")",
                    "id,key,summary", 1);

            if (srJiraIssues != null && srJiraIssues.issues != null && !srJiraIssues.issues.isEmpty()) {
                isDuplicate = true;
                LOG.info("There " + (srJiraIssues.issues.size() > 1 ? "are " + srJiraIssues.issues.size() + " issues" : "is one issue") + " with MD5=" + jiraMessageDigest +
                        (StringUtils.isNotBlank(jiraDuplicateIssueFilterQuery) ? " and filter-query='" + jiraDuplicateIssueFilterQuery + "'" : ""));
            } else {
                LOG.info("No existing open JIRA issue for MD5=" + jiraMessageDigest +
                        (StringUtils.isNotBlank(jiraDuplicateIssueFilterQuery) ? " and filter-query='" + jiraDuplicateIssueFilterQuery + "'" : ""));
            }
        } catch (Throwable ex) {
            LOG.error("Error searching for JIRA issue=" + ex.getMessage() + (ex.getCause() != null ? ", Cause=" + ex.getCause().getMessage() : ""), ex);
            throw new AlarmCallbackException("Failed searching for duplicate issue", ex);
        }

        return isDuplicate;
    }

    /**
     * Create a JIRA issue
     */
    @SuppressWarnings("serial")
    private void createJIRAIssue(JiraClient jiraClient) throws AlarmCallbackException {

        try {
            List<String> labels = (StringUtils.isNotBlank(jiraLabels) ? Arrays.asList(StringUtils.split(jiraLabels, ',')) : null);
            List<String> components = (StringUtils.isNotBlank(jiraComponents) ? Arrays.asList(StringUtils.split(jiraComponents, ',')) : null);

            // We create the base issue and then chain all the required fields
            FluentCreate fluentIssueCreate = jiraClient.createIssue(jiraProjectKey, jiraIssueType);

            // add JIRA priority
            fluentIssueCreate.field(Field.PRIORITY, jiraPriority);

            // add assignee - unsure
            //fluentIssueCreate.field(Field.ASSIGNEE, null);

            // add summary / title
            fluentIssueCreate.field(Field.SUMMARY, jiraTitle);

            // add labels
            if (labels != null && !labels.isEmpty()) {
                fluentIssueCreate.field(Field.LABELS, labels);
            }

            // add components
            if (components != null && !components.isEmpty()) {
                fluentIssueCreate.field(Field.COMPONENTS, components);
            }

            String strJIRADescription = jiraDescription;

            // add the MD5 digest
            if (StringUtils.isNotBlank(jiraMessageDigest)) {
                String md5Field = jiraMD5CustomFieldName;

                // if we do not have a configured custom-field, we will try and find it from meta-data
                // this requires that the JIRA user has edit-permissions
                if (StringUtils.isBlank(md5Field)) {
                    md5Field = getJIRACustomMD5Field(jiraClient);
                }

                if (StringUtils.isNotBlank(md5Field)) {
                    fluentIssueCreate.field(md5Field, jiraMessageDigest);
                } else {
                    // If there is no MD5 field defined, we inline the MD5-digest into the JIRA description
                    strJIRADescription = "\n\n" + GRAYLOG_MD5 + "=" + jiraMessageDigest + "\n\n";
                    LOG.warn("It is more efficient to configure '" + JiraAlarmCallback.JIRA_MD5_CUSTOM_FIELD + "' for MD5-hashing instead of embedding the hash in the JIRA description!");
                }
            }

            // add description - we add this last, as the description could have been modified due to the MD5 inlining above
            fluentIssueCreate.field(Field.DESCRIPTION, strJIRADescription);

            // append auto-mapped fields
            if (jiraGraylogMapping != null && !jiraGraylogMapping.isEmpty()) {
                for (final Map.Entry<String, String> arg : jiraGraylogMapping.entrySet()) {
                    if (StringUtils.isNotBlank(arg.getKey()) && StringUtils.isNotBlank(arg.getValue())) {
                        String jiraFieldName = arg.getKey();
                        Object jiraFiedValue = arg.getValue();
                        if (jiraFieldName.endsWith("#i")) {
                            jiraFieldName = jiraFieldName.substring(0, jiraFieldName.length() - 2);
                            jiraFiedValue = new ArrayList<String>() {{
                                add(arg.getValue());
                            }};
                        }

                        LOG.info("JIRA/Graylog automap - JIRA-key=" + jiraFieldName + ", value=" + jiraFiedValue.toString());
                        fluentIssueCreate.field(jiraFieldName, jiraFiedValue);
                    }
                }
            }

            // finally create the issue
            Issue newIssue = fluentIssueCreate.execute();

            LOG.info("Created new issue " + newIssue.getKey() + " for project " + jiraProjectKey);
        } catch (Throwable ex) {
            LOG.error("Error creating JIRA issue=" + ex.getMessage() + (ex.getCause() != null ? ", Cause=" + ex.getCause().getMessage() : ""), ex);
            throw new AlarmCallbackException("Failed creating new issue", ex);
        }
    }

    /**
     * Return the name of the md5 custom field
     */
    @SuppressWarnings("unchecked")
    private String getJIRACustomMD5Field(JiraClient jiraClient) throws AlarmCallbackException {
        String strJIRACustomMD5Field = null;

        LOG.warn("It is more efficient to configure '" + JiraAlarmCallback.JIRA_MD5_CUSTOM_FIELD + "' for MD5-hashing.");

        try {
            JSONObject customfields = Issue.getCreateMetadata(jiraClient.getRestClient(), jiraProjectKey, jiraIssueType);

            for (Iterator<String> iterator = customfields.keySet().iterator(); iterator.hasNext(); ) {
                String key = iterator.next();

                if (key.startsWith("customfield_")) {
                    JSONObject metaFields = customfields.getJSONObject(key);
                    if (metaFields.has("name") && JiraIssueClient.GRAYLOG_MD5.equalsIgnoreCase(metaFields.getString("name"))) {
                        strJIRACustomMD5Field = key;
                        break;
                    }
                }
            }
        } catch (JiraException ex) {
            LOG.error("Error getting JIRA custom MD5 field=" + ex.getMessage() + (ex.getCause() != null ? ", Cause=" + ex.getCause().getMessage() : ""), ex);
            throw new AlarmCallbackException("Failed retrieving MD5-field", ex);
        }

        return strJIRACustomMD5Field;
    }
}
