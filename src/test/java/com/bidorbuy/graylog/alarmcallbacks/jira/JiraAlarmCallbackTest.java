package com.bidorbuy.graylog.alarmcallbacks.jira;

import org.junit.*;

public class JiraAlarmCallbackTest {

    @Test
    public void getMatcherGroup() throws Exception {
        String message;
        String regex = "^.*?:\\s*(.*(Exception|Service|Servlet|Error).*\\w)\\sat?.*$";

        message = "wolverine1 lp2-wolverine: org.tempuri.TooLongExceptionFaultFaultMessage: Text too long#012 at sun.refl....java:80)#012 at ...";
        System.out.println(JiraAlarmCallback.getMatcherGroup(message, regex));

        message = "wolverine1 lp2-wolverine: 2017-07-21 11:32:11,266 WARN : com.oe.lp2.services.course.DBCourseService - Student 382568 has completed all private classes. Adding completed message";
        System.out.println(JiraAlarmCallback.getMatcherGroup(message, regex));

        message = "wolverine2 lp2-wolverine: 2017-07-21 12:03:00,715 WARN : com.oe.lp2.services.person.DBPersonService - fetched image from S3 using URL: http://images.openenglish.com/profile/123/405787.jpg";
        System.out.println(JiraAlarmCallback.getMatcherGroup(message, regex));

        message = "wolverine2 lp2-wolverine: 2017-07-21 12:02:25,355 ERROR: com.oe.lp2.services.logging.LoggingServiceImpl - [Client logger: profileService], [time: 2017-07-21T12:02:25.355], [user agent: Mozilla/5.0 ...";
        System.out.println(JiraAlarmCallback.getMatcherGroup(message, regex));

        message = "wolverine2 lp2-wolverine: 2017-07-21 12:00:13,224 WARN : org.hibernate.engine.jdbc.spi.SqlExceptionHelper - SQL Error: 0, SQLState: 23505";
        System.out.println(JiraAlarmCallback.getMatcherGroup(message, regex));
    }

}
