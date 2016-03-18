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

import org.apache.commons.lang3.StringEscapeUtils;
import org.graylog2.plugin.MessageSummary;
import org.graylog2.plugin.Tools;
import org.graylog2.plugin.alarms.AlertCondition;
import org.graylog2.plugin.configuration.Configuration;
import org.graylog2.plugin.configuration.ConfigurationException;
import org.graylog2.plugin.configuration.ConfigurationRequest;
import org.graylog2.plugin.configuration.fields.ConfigurationField;
import org.graylog2.plugin.configuration.fields.TextField;
import org.graylog2.plugin.streams.Stream;
import org.graylog2.plugin.streams.StreamRule;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.MessageDigest;
import java.util.Map;
import java.util.regex.*;

public class JiraPluginBase {
  
  private static final Logger LOG = LoggerFactory.getLogger(JiraPluginBase.class);
  
  public static final String CK_LABELS           = "labels";
  public static final String CK_USERNAME         = "username";
  public static final String CK_PASSWORD         = "password";
  public static final String CK_PRIORITY         = "priority";
  public static final String CK_ISSUE_TYPE       = "issue_type";
  public static final String CK_COMPONENTS       = "components";
  public static final String CK_GRAYLOG_URL      = "graylog_url";
  public static final String CK_PROJECT_KEY      = "project_key";
  public static final String CK_INSTANCE_URL     = "instance_url";
  public static final String CK_MESSAGE_TEMPLATE = "message_template";
  public static final String CK_TITLE_TEMPLATE   = "title_template";
  public static final String CK_MESSAGE_REGEX    = "message_regex";
  
  // The default template for JIRA messages
  private static final String CONST_JIRA_MESSAGE_TEMPLATE = "*Stream title:* \n [STREAM_TITLE]\n\n"
      + " *Stream URL:* \n [STREAM_URL]\n\n"
      + " *Stream rules:* \n [STREAM_RULES]\n\n"
      + " *Alert triggered at:* \n [ALERT_TRIGGERED_AT]\n\n"
      + " *Triggered condition:* \n [ALERT_TRIGGERED_CONDITION]\n\n"
      + " *Source:* \n [LAST_MESSAGE.SOURCE]\n\n"
      + " *Message:* \n [LAST_MESSAGE.MESSAGE]\n\n";

  private static final String CONST_JIRA_TITLE_TEMPLATE = "Jira [MESSAGE_REGEX]";

  private static final String CONST_JIRA_MESSAGE_REGEX = "([a-zA-Z_.]+(?!.*Exception): .+)";
  
  public static ConfigurationRequest configuration () {

    final ConfigurationRequest configurationRequest = new ConfigurationRequest();

    configurationRequest.addField (new TextField (
        CK_INSTANCE_URL, "JIRA Instance URL", "", "JIRA server URL.",
        ConfigurationField.Optional.NOT_OPTIONAL));
    
    configurationRequest.addField (new TextField (
        CK_USERNAME, "Username", "", "Username to login to JIRA.",
        ConfigurationField.Optional.NOT_OPTIONAL));
    
    configurationRequest.addField (new TextField (
        CK_PASSWORD, "Password", "", "Password to login to JIRA.",
        ConfigurationField.Optional.NOT_OPTIONAL, TextField.Attribute.IS_PASSWORD));
    
    configurationRequest.addField (new TextField (
        CK_PROJECT_KEY, "Project Key", "", "Project under which the issue will be created.",
        ConfigurationField.Optional.NOT_OPTIONAL));
    
    configurationRequest.addField (new TextField (
        CK_ISSUE_TYPE, "Issue Type", "Bug", "Type of issue.", 
        ConfigurationField.Optional.NOT_OPTIONAL));
    
    configurationRequest.addField (new TextField (
        CK_GRAYLOG_URL, "Graylog URL", null, "URL to your Graylog web interface. Used to build links in alarm notification.",
        ConfigurationField.Optional.NOT_OPTIONAL));
    
    configurationRequest.addField (new TextField (
        CK_PRIORITY, "Issue Priority", "Minor", "Priority of the issue.", 
        ConfigurationField.Optional.OPTIONAL));
    
    configurationRequest.addField (new TextField (
        CK_LABELS, "Labels", "graylog", "List of comma-separated labels to add to this issue.",
        ConfigurationField.Optional.OPTIONAL));
    
    configurationRequest.addField (new TextField (
        CK_COMPONENTS, "Components", "", "List of comma-separated components to add to this issue.",
        ConfigurationField.Optional.OPTIONAL));
    
    configurationRequest.addField (new TextField (
        CK_MESSAGE_TEMPLATE, "Message template", CONST_JIRA_MESSAGE_TEMPLATE.replaceAll("\n", "\\\n"), "Message template for JIRA",
        ConfigurationField.Optional.NOT_OPTIONAL));

    configurationRequest.addField (new TextField (
        CK_TITLE_TEMPLATE, "JIRA task title", CONST_JIRA_TITLE_TEMPLATE, "Title template for JIRA tasks",
        ConfigurationField.Optional.NOT_OPTIONAL));

    configurationRequest.addField (new TextField (
        CK_MESSAGE_REGEX, "Message regex", CONST_JIRA_MESSAGE_REGEX, "Message regex to store as hash in JIRA",
        ConfigurationField.Optional.NOT_OPTIONAL));
    
    return configurationRequest;
  }

  public static void checkConfiguration (Configuration configuration) throws ConfigurationException {

    if (!configuration.stringIsSet(CK_INSTANCE_URL)) {
      throw new ConfigurationException(
          CK_INSTANCE_URL + " is mandatory and must not be empty.");
    }

    if (configuration.stringIsSet(CK_INSTANCE_URL)
        && !configuration.getString(CK_INSTANCE_URL).equals("null")) {
      try {
        final URI jiraUri = new URI(configuration.getString(CK_INSTANCE_URL));
        if (!"http".equals(jiraUri.getScheme())
            && !"https".equals(jiraUri.getScheme())) {
          throw new ConfigurationException(
              CK_INSTANCE_URL + " must be a valid HTTP or HTTPS URL.");
        }
      } catch (URISyntaxException e) {
        throw new ConfigurationException(
            "Couldn't parse " + CK_INSTANCE_URL + " correctly.", e);
      }
    }

    if (!configuration.stringIsSet(CK_USERNAME)) {
      throw new ConfigurationException(
          CK_USERNAME + " is mandatory and must not be empty.");
    }

    if (!configuration.stringIsSet(CK_PASSWORD)) {
      throw new ConfigurationException(
          CK_PASSWORD + " is mandatory and must not be empty.");
    }

    if (!configuration.stringIsSet(CK_PROJECT_KEY)) {
      throw new ConfigurationException(
          CK_PROJECT_KEY + " is mandatory and must not be empty.");
    }

    if (!configuration.stringIsSet(CK_ISSUE_TYPE)) {
      throw new ConfigurationException(
          CK_ISSUE_TYPE + " is mandatory and must not be empty.");
    }

    if (configuration.stringIsSet(CK_GRAYLOG_URL)
        && !configuration.getString(CK_GRAYLOG_URL).equals("null")) {
      try {
        final URI graylogUri = new URI(configuration.getString(CK_GRAYLOG_URL));
        if (!"http".equals(graylogUri.getScheme())
            && !"https".equals(graylogUri.getScheme())) {
          throw new ConfigurationException(
              CK_GRAYLOG_URL + " must be a valid HTTP or HTTPS URL.");
        }
      } catch (URISyntaxException e) {
        throw new ConfigurationException(
            "Couldn't parse " + CK_GRAYLOG_URL + " correctly.", e);
      }
    }
  }

  protected String buildTitle (Stream stream, AlertCondition.CheckResult checkResult, Configuration configuration) {

    StringBuilder sb = new StringBuilder();
    
    if (configuration.stringIsSet(CK_MESSAGE_REGEX) && !configuration.getString(CK_MESSAGE_REGEX).equals("null")) {
      try {
        if (!checkResult.getMatchingMessages().isEmpty()) {
          // get fields from last message only
          MessageSummary lastMessage = checkResult.getMatchingMessages().get(0);
          
          Map<String, Object> lastMessageFields = lastMessage.getFields();
          
          String strTitle = "[Alert] Graylog alert for stream: " + stream.getTitle();

          if (configuration.stringIsSet(CK_TITLE_TEMPLATE) && !configuration.getString(CK_TITLE_TEMPLATE).equals("null")) {
            strTitle = configuration.getString(CK_TITLE_TEMPLATE);
          }
          
          strTitle = strTitle.replace("[LAST_MESSAGE.SOURCE]", lastMessage.getSource());
          
          for (Map.Entry<String, Object> arg : lastMessageFields.entrySet()) {
            strTitle = strTitle.replace("[LAST_MESSAGE." + arg.getKey().toUpperCase() + "]", arg.getValue().toString());
          }

          Matcher matcher = Pattern.compile(configuration.getString(CK_MESSAGE_REGEX)).matcher(lastMessage.getMessage());
          
          if (matcher.find()) {
            if (configuration.stringIsSet(CK_TITLE_TEMPLATE) && !configuration.getString(CK_TITLE_TEMPLATE).equals("null")) {
              strTitle = strTitle.replace("[MESSAGE_REGEX]", matcher.group());
            } else {
              strTitle = "[Graylog] " + matcher.group();
            }
          }
          
          sb.append(strTitle);
        }
      } catch (Exception ex) {
        ; // can not do anything - we skip
        LOG.error("[JIRA] Error in building title: " + ex.getMessage());
      }
    }
    
    if (sb.length() == 0) {
      sb.append("[Alert] Graylog alert for stream: ").append(stream.getTitle());
    }
    
    return sb.toString();
  }

  protected String buildStreamURL (String baseUrl, Stream stream) {

    if (!baseUrl.endsWith("/")) {
      baseUrl += "/";
    }
    return baseUrl + "streams/" + stream.getId()
        + "/messages?q=*&rangetype=relative&relative=3600";
  }

  protected String buildStreamRules (Stream stream) {

    StringBuilder sb = new StringBuilder();
    for (StreamRule streamRule : stream.getStreamRules()) {
      sb.append("_").append(streamRule.getField()).append("_ ");
      sb.append(streamRule.getType()).append(" _").append(streamRule.getValue())
          .append("_").append("\n");
    }
    return sb.toString();
  }

  protected String buildDescription (Stream stream, AlertCondition.CheckResult checkResult, Configuration configuration) {

    String strMessage = CONST_JIRA_MESSAGE_TEMPLATE;
    
    if (configuration.stringIsSet(CK_MESSAGE_TEMPLATE) &&
        !configuration.getString(CK_MESSAGE_TEMPLATE).equals("null") &&
        !configuration.getString(CK_MESSAGE_TEMPLATE).isEmpty()) {
      strMessage = configuration.getString(CK_MESSAGE_TEMPLATE);
    }
    
    strMessage = StringEscapeUtils.unescapeJava(strMessage);
    
    // Get the last message
    if (!checkResult.getMatchingMessages().isEmpty()) {
      // get fields from last message only
      MessageSummary lastMessage = checkResult.getMatchingMessages().get(0);
      Map<String, Object> lastMessageFields = lastMessage.getFields();

      strMessage = strMessage.replace("[LAST_MESSAGE.MESSAGE]", lastMessage.getMessage());
      strMessage = strMessage.replace("[LAST_MESSAGE.SOURCE]", lastMessage.getSource());
      
      for (Map.Entry<String, Object> arg : lastMessageFields.entrySet()) {
        strMessage = strMessage.replace("[LAST_MESSAGE." + arg.getKey().toUpperCase() + "]", arg.getValue().toString());
      }
    }

    // replace placeholders
    strMessage = strMessage.replace("[CALLBACK_DATE]", Tools.iso8601().toString());
    strMessage = strMessage.replace("[STREAM_ID]", stream.getId());
    strMessage = strMessage.replace("[STREAM_TITLE]", stream.getTitle());
    strMessage = strMessage.replace("[STREAM_URL]", buildStreamURL(configuration.getString(CK_GRAYLOG_URL), stream));
    strMessage = strMessage.replace("[STREAM_RULES]", buildStreamRules(stream));
    strMessage = strMessage.replace("[ALERT_TRIGGERED_AT]", checkResult.getTriggeredAt().toString());
    strMessage = strMessage.replace("[ALERT_TRIGGERED_CONDITION]", checkResult.getTriggeredCondition().toString());
    
    // create final string
    StringBuilder sb = new StringBuilder();
    sb.append(checkResult.getResultDescription());
    sb.append("\n\n");
    sb.append(strMessage).append("\n\n");
    
    return sb.toString();
  }

  protected String getMessageDigest (Stream stream, AlertCondition.CheckResult checkResult, Configuration configuration) {

    String JiraMessageDigest = "";
    
    // Get the last message
    if (!checkResult.getMatchingMessages().isEmpty()) {
      // See if we can get a checksum for the message
      if (configuration.stringIsSet(CK_MESSAGE_REGEX) && !configuration.getString(CK_MESSAGE_REGEX).equals("null")) {
        try {
          MessageSummary lastMessage = checkResult.getMatchingMessages().get(0);

          Matcher matcher = Pattern.compile(configuration.getString(CK_MESSAGE_REGEX)).matcher(lastMessage.getMessage());
          
          if (matcher.find()) {
            String JiraMessage = lastMessage.getMessage().substring(matcher.start());
            
            MessageDigest m = MessageDigest.getInstance("MD5");
            m.update (JiraMessage.getBytes(), 0, JiraMessage.length());
            JiraMessageDigest = new BigInteger(1, m.digest()).toString(16);
          }

        } catch (Exception ex) {
          ; // can not do anything - we skip
        }
      }
    }

    return JiraMessageDigest;
  }
  
}
