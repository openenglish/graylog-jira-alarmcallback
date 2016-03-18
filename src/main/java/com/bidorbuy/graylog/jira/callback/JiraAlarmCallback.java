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

package com.bidorbuy.graylog.jira.callback;

import com.bidorbuy.graylog.jira.JiraIssue;
import com.bidorbuy.graylog.jira.JiraPluginBase;

import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.graylog2.plugin.alarms.AlertCondition;
import org.graylog2.plugin.alarms.callbacks.*;
import org.graylog2.plugin.configuration.*;
import org.graylog2.plugin.streams.Stream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.Maps;

import net.rcarz.jiraclient.*;
import net.sf.json.JSONObject;

public class JiraAlarmCallback extends JiraPluginBase implements AlarmCallback {

  private static final Logger LOG = LoggerFactory.getLogger(JiraAlarmCallback.class);
  private static final String CONST_GRAYLOGMD5_DIGEST = "graylog_md5";

  private Configuration configuration;

  private static final List<String> SENSITIVE_CONFIGURATION_KEYS = ImmutableList.of(CK_PASSWORD);

  @Override
  public void initialize (final Configuration config) throws AlarmCallbackConfigurationException {

    this.configuration = config;
    try {
      checkConfiguration(config);
    } catch (ConfigurationException e) {
      throw new AlarmCallbackConfigurationException ("Configuration error: " + e.getMessage());
    }
  }

  @Override
  public void call (Stream stream, AlertCondition.CheckResult result) throws AlarmCallbackException {

    JiraIssue jiraIssue = new JiraIssue(configuration,
        buildTitle(stream, result, configuration),
        buildDescription(stream, result, configuration),
        getMessageDigest(stream, result, configuration));
    
    try {
      if (isDuplicateJiraIssue(jiraIssue) == false) {
        createJIRAIssue(jiraIssue);
      }
    } catch (Exception e) {
      throw new RuntimeException(e.getMessage());
    }

    // Create the issue

  }

  /** 
   * @see org.graylog2.plugin.alarms.callbacks.AlarmCallback#getAttributes()
   */
  @Override
  public Map<String, Object> getAttributes () {

    return Maps.transformEntries(configuration.getSource(),
        new Maps.EntryTransformer<String, Object, Object>() {

          @Override
          public Object transformEntry (String key, Object value) {

            if (SENSITIVE_CONFIGURATION_KEYS.contains(key)) {
              return "****";
            }
            return value;
          }
        });
  }

  /**
   * Checks if a JIRA issue is duplicated.
   * 
   * @param jiraIssue
   * @return
   * @throws Exception
   */
  public boolean isDuplicateJiraIssue (JiraIssue jiraIssue) throws Exception {

    boolean bDuplicateIssue = false;

    if (jiraIssue.isMessageDigestAvailable() == false) {
      return false;
    }

    LOG.info("[JIRA] Checking for duplicate issues with MD5=" + jiraIssue.getMessageDigest());
 
    try {
      BasicCredentials creds = new BasicCredentials(
          configuration.getString(CK_USERNAME),
          configuration.getString(CK_PASSWORD));

      JiraClient jira = new JiraClient(configuration.getString(CK_INSTANCE_URL), creds);

      // Search for duplicate issues
      Issue.SearchResult srJiraIssues = jira.searchIssues("project = " + jiraIssue.getProjectKey() 
        + " AND Status not in (Closed, Done, Resolved)"
        + " AND (" + CONST_GRAYLOGMD5_DIGEST + " ~ \"" + jiraIssue.getMessageDigest() + "\" OR"
        + " description ~ \"" + jiraIssue.getMessageDigest() + "\")",
        "id,key,summary", 1);
      
      if (srJiraIssues != null && srJiraIssues.issues != null && srJiraIssues.issues.isEmpty() == false) {
        bDuplicateIssue = true;
        LOG.info("[JIRA] There are " + srJiraIssues.issues.size() + " issue(s) open with the same hash");
      } else {
        LOG.info("[JIRA] No existing open JIRA issue, will create a new one");
      }

    } catch (JiraException ex) {
      LOG.error("[JIRA] Error searching for JIRA issue=" + ex.getMessage() + (ex.getCause() != null ? ex.getCause().getMessage() : ""));
      throw new Exception("[JIRA] Failed searching for duplicate issue", ex);
    } catch (Exception ex) {
      LOG.error("[JIRA] Error searching for JIRA issue=" + ex.getMessage() + (ex.getCause() != null ? ex.getCause().getMessage() : ""));
      throw new Exception("[JIRA] Failed searching for duplicate issue", ex);
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
  public void createJIRAIssue (JiraIssue jiraIssue) throws Exception {

    try {
      BasicCredentials creds = new BasicCredentials(
          configuration.getString(CK_USERNAME),
          configuration.getString(CK_PASSWORD));

      JiraClient jira = new JiraClient(configuration.getString(CK_INSTANCE_URL), creds);
      
      Issue newIssue = jira.createIssue(jiraIssue.getProjectKey(), jiraIssue.getIssueType())
          .field(Field.PRIORITY, jiraIssue.getPriority())
          .field(Field.SUMMARY, jiraIssue.getTitle())
          .field(Field.DESCRIPTION, jiraIssue.getDescription())
          .field(Field.LABELS, Arrays.asList(jiraIssue.getLabels().split("\\,")))
          .field(Field.COMPONENTS, Arrays.asList(jiraIssue.getComponents().split("\\,")))
          .execute();
      
      // We now check if the JIRA install has the MD5 field configured and if so, we will update it with the digest,
      // otherwise we will update the description
      
      if (jiraIssue.isMessageDigestAvailable() == true) {
        String md5Field = getJIRACustomMD5Field(jira, jiraIssue);
        
        if (md5Field != null) {
          newIssue.update()
            .field(md5Field, jiraIssue.getMessageDigest())
            .execute();
        } else {
          String strAppendMessageDigest = "\n\n" + CONST_GRAYLOGMD5_DIGEST + "=" + jiraIssue.getMessageDigest() + "\n\n";
          newIssue.update()
          .field(Field.DESCRIPTION, jiraIssue.getDescription() + strAppendMessageDigest)
          .execute();
        }
      }
      
      LOG.info("[JIRA] Created new issue " + newIssue.getKey() + " for project " + jiraIssue.getProjectKey());
    } catch (JiraException ex) {
      LOG.error("[JIRA] Error creating JIRA issue=" + ex.getMessage() + (ex.getCause() != null ? ex.getCause().getMessage() : ""));
      throw new Exception("[JIRA] Failed creating new issue", ex);
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
  private String getJIRACustomMD5Field (JiraClient jira, JiraIssue jiraIssue) throws Exception {
    
    String strJIRACustomMD5Field = null;

    try {
      JSONObject customfields = Issue.getCreateMetadata(jira.getRestClient(), jiraIssue.getProjectKey(), jiraIssue.getIssueType());
      
      for (Iterator<String> iterator = customfields.keySet().iterator(); iterator.hasNext();) {
        String key = iterator.next();
        
        if (key.startsWith("customfield_")) {
          JSONObject metaFields = customfields.getJSONObject(key);
          if (metaFields.has("name") && CONST_GRAYLOGMD5_DIGEST.equalsIgnoreCase(metaFields.getString("name"))) {
            strJIRACustomMD5Field = key;
            break;
          }
        }
      }      
    } catch (JiraException ex) {
      LOG.error("[JIRA] Error getting JIRA custom MD5 field=" + ex.getMessage() + (ex.getCause() != null ? ex.getCause().getMessage() : ""));
    }

    return strJIRACustomMD5Field;
  }  
  
  @Override
  // Never actually called by Graylog-server
  public void checkConfiguration () throws ConfigurationException {
  }

  @Override
  public ConfigurationRequest getRequestedConfiguration () {
    return configuration();
  }

  @Override
  public String getName () {
    return "Graylog JIRA integration plugin";
  }
}
