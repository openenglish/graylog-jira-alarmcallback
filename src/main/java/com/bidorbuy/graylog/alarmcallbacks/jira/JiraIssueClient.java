package com.bidorbuy.graylog.alarmcallbacks.jira;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.rcarz.jiraclient.BasicCredentials;
import net.rcarz.jiraclient.Field;
import net.rcarz.jiraclient.Issue;
import net.rcarz.jiraclient.JiraClient;
import net.rcarz.jiraclient.JiraException;
import net.sf.json.JSONObject;

import java.util.Arrays;
import java.util.Iterator;

import org.graylog2.plugin.alarms.AlertCondition;
import org.graylog2.plugin.alarms.callbacks.AlarmCallbackException;
import org.graylog2.plugin.streams.Stream;

public class JiraIssueClient {

  private static final Logger LOG = LoggerFactory.getLogger(JiraAlarmCallback.class);

  // The JIRA field-name for the MD5 - digest
  protected static final String CONST_GRAYLOGMD5_DIGEST = "graylog_md5";

  private final String JIRAServerURL;
  private final String JIRAUserName;
  private final String JIRAPassword;

  private final String JIRAProjectKey;
  private final String JIRATitle;
  private final String JIRADescription;
  private final String JIRALabels;
  private final String JIRAIssueType;
  private final String JIRAComponents;
  private final String JIRAPriority;
  private final String JIRADuplicateIssueFilterQuery;
  
  private final String JIRAMessageDigest;
  private JiraClient jiraClient = null;

  
  public JiraIssueClient (final String JIRAProjectKey, final String JIRATitle, final String JIRADescription, 
      final String JIRALabels, final String JIRAIssueType, final String JIRAComponents, final String JIRAPriority, 
      final String JIRAServerURL, final String JIRAUserName, final String JIRAPassword, final String JIRADuplicateIssueFilterQuery,
      final String JIRAMessageDigest) {
    
    this.JIRAProjectKey = JIRAProjectKey;
    this.JIRATitle = JIRATitle;
    this.JIRADescription = JIRADescription;
    this.JIRALabels = JIRALabels;
    this.JIRAIssueType = JIRAIssueType;
    this.JIRAComponents = JIRAComponents;
    this.JIRAPriority = JIRAPriority;
    this.JIRAServerURL = JIRAServerURL;
    this.JIRAUserName = JIRAUserName;
    this.JIRAPassword = JIRAPassword;
    this.JIRAMessageDigest = JIRAMessageDigest;
    this.JIRADuplicateIssueFilterQuery = JIRADuplicateIssueFilterQuery;
  }
  
  public void trigger (final Stream stream, final AlertCondition.CheckResult checkResult) throws AlarmCallbackException {
    
    try {
      BasicCredentials creds = new BasicCredentials (JIRAUserName, JIRAPassword);
      
      jiraClient = new JiraClient(JIRAServerURL, creds);
      
      if (isDuplicateJiraIssue() == false) {
        createJIRAIssue();
      }
    } catch (Exception e) {
      throw new AlarmCallbackException(e.getMessage());
    }
  }
  
  /**
   * Checks if a JIRA issue is duplicated.
   * 
   * @return
   * @throws Exception
   */
  private boolean isDuplicateJiraIssue () throws AlarmCallbackException {

    boolean bDuplicateIssue = false;

    if (JIRAMessageDigest == null || JIRAMessageDigest.isEmpty()) {
      return false;
    }

    LOG.info("[JIRA] Checking for duplicate issues with MD5=" + JIRAMessageDigest + 
        (JIRADuplicateIssueFilterQuery != null && !JIRADuplicateIssueFilterQuery.isEmpty() ? ", using filter-query=" + JIRADuplicateIssueFilterQuery : ""));
 
    try {
      // Search for duplicate issues
      Issue.SearchResult srJiraIssues = jiraClient.searchIssues("project = " + JIRAProjectKey 
        + (JIRADuplicateIssueFilterQuery != null && !JIRADuplicateIssueFilterQuery.isEmpty() ? " " + JIRADuplicateIssueFilterQuery + " " : "")
        + " AND (" + CONST_GRAYLOGMD5_DIGEST + " ~ \"" + JIRAMessageDigest + "\" OR"
        + " description ~ \"" + JIRAMessageDigest + "\")",
        "id,key,summary", 1);
      
      if (srJiraIssues != null && srJiraIssues.issues != null && srJiraIssues.issues.isEmpty() == false) {
        bDuplicateIssue = true;
        LOG.info("[JIRA] There " + (srJiraIssues.issues.size() > 1 ? "are " + srJiraIssues.issues.size() + " issues" : "is one issue") + " with the same hash");
      } else {
        LOG.info("[JIRA] No existing open JIRA issue, creating a new one!");
      }
    } catch (JiraException ex) {
      LOG.error("[JIRA] Error searching for JIRA issue=" + ex.getMessage() + (ex.getCause() != null ? ", Cause=" + ex.getCause().getMessage() : ""));
      throw new AlarmCallbackException("[JIRA] Failed searching for duplicate issue", ex);
    } catch (Exception ex) {
      LOG.error("[JIRA] Error searching for JIRA issue=" + ex.getMessage() + (ex.getCause() != null ? ", Cause=" + ex.getCause().getMessage() : ""));
      throw new AlarmCallbackException("[JIRA] Failed searching for duplicate issue", ex);
    }

    return bDuplicateIssue;
  }
  
  /**
   * Create a JIRA issue
   * 
   * @param jiraIssue
   * @return
   * @throws Exception
   */
  public void createJIRAIssue () throws AlarmCallbackException {

    try {
      Issue newIssue = jiraClient.createIssue(JIRAProjectKey, JIRAIssueType)
          .field(Field.PRIORITY, JIRAPriority)
          .field(Field.ASSIGNEE, null)
          .field(Field.SUMMARY, JIRATitle)
          .field(Field.DESCRIPTION, JIRADescription)
          .field(Field.LABELS, Arrays.asList(JIRALabels.split("\\,")))
          .execute();
      
      // components are optional
      if (JIRAComponents != null && !JIRAComponents.isEmpty()) {
        newIssue.update()
          .field(Field.COMPONENTS, Arrays.asList(JIRAComponents.split("\\,")))
          .execute();
      }
      
      // We now check if the JIRA install has the MD5 field configured and if so, we will update it with the digest,
      // otherwise we will update the description
      
      if (JIRAMessageDigest != null && !JIRAMessageDigest.isEmpty()) {
        String md5Field = getJIRACustomMD5Field();
        
        if (md5Field != null) {
          newIssue.update()
            .field(md5Field, JIRAMessageDigest)
            .execute();
        } else {
          String strAppendMessageDigest = "\n\n" + CONST_GRAYLOGMD5_DIGEST + "=" + JIRAMessageDigest + "\n\n";
          newIssue.update()
          .field(Field.DESCRIPTION, JIRADescription + strAppendMessageDigest)
          .execute();
        }
      }
      
      LOG.info("[JIRA] Created new issue " + newIssue.getKey() + " for project " + JIRAProjectKey);
    } catch (JiraException ex) {
      LOG.error("[JIRA] Error creating JIRA issue=" + ex.getMessage() + (ex.getCause() != null ? ", Cause=" + ex.getCause().getMessage() : ""));
      throw new AlarmCallbackException("[JIRA] Failed creating new issue", ex);
    }

    return ;
  }  
   
  /**
   * Return the name of the md5 custom field
   * @param jira
   * @param jiraIssue
   * @return
   * @throws Exception
   */
  @SuppressWarnings("unchecked")
  private String getJIRACustomMD5Field () throws AlarmCallbackException {
    
    String strJIRACustomMD5Field = null;

    try {
      JSONObject customfields = Issue.getCreateMetadata(jiraClient.getRestClient(), JIRAProjectKey, JIRAIssueType);
      
      for (Iterator<String> iterator = customfields.keySet().iterator(); iterator.hasNext();) {
        String key = iterator.next();
        
        if (key.startsWith("customfield_")) {
          JSONObject metaFields = customfields.getJSONObject(key);
          if (metaFields.has("name") && JiraIssueClient.CONST_GRAYLOGMD5_DIGEST.equalsIgnoreCase(metaFields.getString("name"))) {
            strJIRACustomMD5Field = key;
            break;
          }
        }
      }      
    } catch (JiraException ex) {
      LOG.error("[JIRA] Error getting JIRA custom MD5 field=" + ex.getMessage() + (ex.getCause() != null ? ", Cause=" + ex.getCause().getMessage() : ""));
      throw new AlarmCallbackException("[JIRA] Failed retrieving MD5-field", ex);
    }

    return strJIRACustomMD5Field;
  }   
}
