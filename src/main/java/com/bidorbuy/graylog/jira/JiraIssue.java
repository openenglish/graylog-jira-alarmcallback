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

package com.bidorbuy.graylog.jira;

import org.graylog2.plugin.configuration.Configuration;

public class JiraIssue {

  private final String title;
  private final String labels;
  private final String priority;
  private final String issueType;
  private final String projectKey;
  private final String components;
  private final String description;
  private final String messageDigest;

  public JiraIssue(Configuration configuration, final String title, final String description, final String messagedigest) {

    this.projectKey = configuration.getString(JiraPluginBase.CK_PROJECT_KEY);
    this.labels = configuration.getString(JiraPluginBase.CK_LABELS);
    this.issueType = configuration.getString(JiraPluginBase.CK_ISSUE_TYPE);
    this.components = configuration.getString(JiraPluginBase.CK_COMPONENTS);
    this.priority = configuration.getString(JiraPluginBase.CK_PRIORITY);

    this.title = title;
    this.description = description;
    this.messageDigest = messagedigest;
  }

  public String getDuplicateIssueJQLString () {

    return "project = " + projectKey
        + " AND Status not in (Closed, Done, Resolved)"
        + " AND description ~ \"" + messageDigest + "\"";
  }

  /**
   * @return the messageDigest
   */
  public String getMessageDigest () {
    return messageDigest;
  }

  public boolean isMessageDigestAvailable () {
    if (messageDigest != null && !messageDigest.isEmpty()) {
      return true;
    } else {
      return false;
    }
  }

  public String getTitle () {
    return title;
  }

  public String getLabels () {
    return labels;
  }

  public String getPriority () {
    return priority;
  }

  public String getIssueType () {
    return issueType;
  }

  public String getProjectKey () {
    return projectKey;
  }

  public String getComponents () {
    return components;
  }

  public String getDescription () {
    return description;
  }

}
