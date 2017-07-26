package com.openenglish.util;

import javax.annotation.Nullable;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public abstract class StringUtil {

    @Nullable
    public static String getCapturedGroup(String container, String regex, String capturedGroupName) {
        if(container == null || regex == null || capturedGroupName == null)
            return null;

        Matcher matcher =  Pattern.compile(regex).matcher(container);

        if(matcher.find()) {
            try {
                return matcher.group(capturedGroupName);
            } catch (IllegalArgumentException e) {
                return null;
            }
        }

        return null;
    }

    @Nullable
    public static String replace(String container, String toReplace, String replacement) {
        if(container == null || toReplace == null || replacement == null)
            return null;

        return container.replace(toReplace, replacement);
    }

    @Nullable
    public static String captureGroupAndReplace(String finalContainer, String initialContainer, String regex) {
        String finalString = finalContainer;

        for(String name : getPlaceholderNames(finalContainer)) {
            String capturedGroup = getCapturedGroup(initialContainer, regex, name);
            if(capturedGroup != null)
                finalString = replace(finalString, "${" + name + "}", capturedGroup);
        }

        return finalString;
    }

    @Nullable
    public static List<String> getPlaceholderNames(String container) {
        String regex = "\\$\\{([a-zA-Z0-9-_]+)\\}";

        Pattern pattern = Pattern.compile(regex);
        Matcher matcher = pattern.matcher(container);

        Set<String> names = new HashSet<>();
        while(matcher.find()) {
            names.add(matcher.group(1));
        }

        return new ArrayList<>(names);
    }

}
