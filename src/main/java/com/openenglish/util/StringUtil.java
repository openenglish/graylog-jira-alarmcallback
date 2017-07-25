package com.openenglish.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public abstract class StringUtil {

    private static final Logger LOG = LoggerFactory.getLogger(StringUtil.class);

    @Nullable
    public static String getCapturedGroup(String container, String regex, String capturedGroupName) {
        if(container == null || regex == null || capturedGroupName == null)
            return null;

        Matcher matcher =  Pattern.compile(regex).matcher(container);

        if(matcher.find()) {
            return matcher.group(capturedGroupName);
        } else {
            return null;
        }
    }

    @Nullable
    public static String replace(String container, String toReplace, String replacement) {
        if(container == null || toReplace == null || replacement == null)
            return null;

        return container.replace(toReplace, replacement);
    }

    @Nullable
    public static String captureGroupAndReplace(String finalContainer, String initialContainer, String regex, String captureGroupName) {
        String capturedGroup = getCapturedGroup(initialContainer, regex, captureGroupName);
        return replace(finalContainer, "${" + captureGroupName + "}", capturedGroup);
    }

    @Nullable
    public static String[] getPlaceholderNames

}
