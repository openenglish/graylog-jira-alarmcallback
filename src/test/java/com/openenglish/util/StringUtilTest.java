package com.openenglish.util;

import org.junit.*;

public class StringUtilTest {

    private static final String TITLE = "Graylog: [LAST_MESSAGE.source] ${relevant}";
    private static final String REGEX = "(: )(?<relevant>([a-zA-Z_.]+(.*(Service|Servlet|Exception|Callback)[a-zA-Z]*\\b)[^\\d]*))";
    private static final String CAPTURED_GROUP_NAME = "relevant";

    @Test
    public void getMatcherGroup() throws Exception {
        process("wolverine1 lp2-wolverine: org.tempuri.TooLongExceptionFaultFaultMessage: Text too long#012 at sun.refl....java:80)#012 at ...");
        process("wolverine1 lp2-wolverine: 2017-07-21 11:32:11,266 WARN : com.oe.lp2.services.course.DBCourseService - Student 382568 has completed all private classes. Adding completed message");
        process("wolverine2 lp2-wolverine: 2017-07-21 12:03:00,715 WARN : com.oe.lp2.services.person.DBPersonService - fetched image from S3 using URL: http://images.openenglish.com/profile/123/405787.jpg");
        process("wolverine2 lp2-wolverine: 2017-07-21 12:02:25,355 ERROR: com.oe.lp2.services.logging.LoggingServiceImpl - [Client logger: profileService], [time: 2017-07-21T12:02:25.355], [user agent: Mozilla/5.0 ...");
    }

    private void process(String message) {
        System.out.println(StringUtil.captureGroupAndReplace(TITLE, message, REGEX, CAPTURED_GROUP_NAME));
        System.out.println();
    }

}