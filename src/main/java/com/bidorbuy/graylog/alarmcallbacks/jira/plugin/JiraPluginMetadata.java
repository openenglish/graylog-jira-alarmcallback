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
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
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

package com.bidorbuy.graylog.alarmcallbacks.jira.plugin;

import com.bidorbuy.graylog.alarmcallbacks.jira.JiraAlarmCallback;
import org.graylog2.plugin.PluginMetaData;
import org.graylog2.plugin.ServerStatus;
import org.graylog2.plugin.Version;

import java.net.URI;
import java.util.Collections;
import java.util.Set;

public class JiraPluginMetadata implements PluginMetaData {
    @Override
    public String getUniqueId() {
        return JiraAlarmCallback.class.getCanonicalName();
    }

    @Override
    public String getName() {
        return "JIRA integration plugin";
    }

    @Override
    public String getAuthor() {
        return "Open English (Percy Vega)";
    }

    @Override
    public URI getURL() {
        return URI.create("https://github.com/openenglish/graylog-jira-alarmcallback");
    }

    @Override
    /*
     * @see org.graylog2.plugin.PluginMetaData#getVersion()
     */
    public Version getVersion() {
        return new Version(1, 0, 7);
    }

    @Override
    public String getDescription() {
        return "Graylog stream alert integration plugin for JIRA with templating of JIRA issue title and JIRA issue message";
    }

    @Override
    public Version getRequiredVersion() {
        return new Version(1, 0, 0);
    }

    @Override
    public Set<ServerStatus.Capability> getRequiredCapabilities() {
        return Collections.emptySet();
    }
}
