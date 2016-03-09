package com.bidorbuy.graylog.jira;

import org.graylog2.plugin.PluginConfigBean;
import org.graylog2.plugin.PluginModule;

import java.util.Collections;
import java.util.Set;

import com.bidorbuy.graylog.jira.callback.JiraAlarmCallback;

/**
 * Extend the PluginModule abstract class here to add you plugin to the system.
 */
public class JiraPluginModule extends PluginModule {
    /**
     * Returns all configuration beans required by this plugin.
     *
     * Implementing this method is optional. The default method returns an empty {@link Set}.
     */
    @Override
    public Set<? extends PluginConfigBean> getConfigBeans() {
        return Collections.emptySet();
    }

    @Override
    protected void configure() {
        addAlarmCallback(JiraAlarmCallback.class);
    }
}
