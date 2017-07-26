package com.openenglish.util;

import org.junit.*;

import java.util.List;

import static org.assertj.core.api.Assertions.*;

public class StringUtilTest {

    @Test
    public void testingThisRegex() throws Exception {
        final String TITLE = "Graylog: [LAST_MESSAGE.source] ${relevant}";
        final String REGEX = "(: )(?<relevant>([a-zA-Z_.]+(.*(Service|Servlet|Exception|Callback)[a-zA-Z]*\\b)[^\\d]*))";
        String message;

        message = "wolverine1 lp2-wolverine: org.tempuri.TooLongExceptionFaultFaultMessage: Text too long#012 at sun.refl....java:80)#012 at ...";
        assertThat(StringUtil.captureGroupAndReplace(TITLE, message, REGEX)).isEqualTo("Graylog: [LAST_MESSAGE.source] org.tempuri.TooLongExceptionFaultFaultMessage: Text too long#");

        message = "wolverine1 lp2-wolverine: 2017-07-21 11:32:11,266 WARN : com.oe.lp2.services.course.DBCourseService - Student 382568 has completed all private classes. Adding completed message";
        assertThat(StringUtil.captureGroupAndReplace(TITLE, message, REGEX)).isEqualTo("Graylog: [LAST_MESSAGE.source] com.oe.lp2.services.course.DBCourseService - Student ");

        message = "wolverine2 lp2-wolverine: 2017-07-21 12:03:00,715 WARN : com.oe.lp2.services.person.DBPersonService - fetched image from S3 using URL: http://images.openenglish.com/profile/123/405787.jpg";
        assertThat(StringUtil.captureGroupAndReplace(TITLE, message, REGEX)).isEqualTo("Graylog: [LAST_MESSAGE.source] com.oe.lp2.services.person.DBPersonService - fetched image from S");

        message = "wolverine2 lp2-wolverine: 2017-07-21 12:02:25,355 ERROR: com.oe.lp2.services.logging.LoggingServiceImpl - [Client logger: profileService], [time: 2017-07-21T12:02:25.355], [user agent: Mozilla/5.0 ...";
        assertThat(StringUtil.captureGroupAndReplace(TITLE, message, REGEX)).isEqualTo("Graylog: [LAST_MESSAGE.source] com.oe.lp2.services.logging.LoggingServiceImpl - [Client logger: profileService], [time: ");
    }

    @Test
    public void captureGroupAndReplace_perfectMatch() {
        final String TITLE = "The ${level} log had a data of ${date}, a time of ${time}, and a level of ${level}";
        final String MESSAGE = "wolverine1 lp2-wolverine: 2017-07-21 11:32:11,266 WARN : com.oe.lp2.services.course.DBCourseService";
        final String REGEX = "(?<date>[\\d-]+) (?<time>[\\d:,]+) (?<level>[A-Z]+)";

        final String EXPECTED = "The WARN log had a data of 2017-07-21, a time of 11:32:11,266, and a level of WARN";

        assertThat(StringUtil.captureGroupAndReplace(TITLE, MESSAGE, REGEX)).isEqualTo(EXPECTED);
    }

    @Test
    public void captureGroupAndReplace_titleWithoutPlaceholders() {
        final String TITLE = "This is a title without placeholders";
        final String MESSAGE = "wolverine1 lp2-wolverine: 2017-07-21 11:32:11,266 WARN : com.oe.lp2.services.course.DBCourseService";
        final String REGEX = "(?<date>[\\d-]+) (?<time>[\\d:,]+) (?<level>[A-Z]+)";

        final String EXPECTED = TITLE;

        assertThat(StringUtil.captureGroupAndReplace(TITLE, MESSAGE, REGEX)).isEqualTo(EXPECTED);
    }

    @Test
    public void captureGroupAndReplace_nonMatchingRegex() {
        final String TITLE = "The ${level} log had a data of ${date}, a time of ${time}, and a level of ${level}";
        final String MESSAGE = "wolverine1 lp2-wolverine: 2017-07-21 11:32:11,266 WARN : com.oe.lp2.services.course.DBCourseService";
        final String REGEX = "abcd";

        final String EXPECTED = TITLE;

        assertThat(StringUtil.captureGroupAndReplace(TITLE, MESSAGE, REGEX)).isEqualTo(EXPECTED);
    }

    @Test
    public void captureGroupAndReplace_missingNamedGroupInRegex() {
        final String TITLE = "The ${level} log had a data of ${date}, a time of ${time}, and a level of ${level}";
        final String MESSAGE = "wolverine1 lp2-wolverine: 2017-07-21 11:32:11,266 WARN : com.oe.lp2.services.course.DBCourseService";
        final String REGEX = "(?<date>[\\d-]+) ([\\d:,]+) (?<level>[A-Z]+)";

        final String EXPECTED = "The WARN log had a data of 2017-07-21, a time of ${time}, and a level of WARN";

        assertThat(StringUtil.captureGroupAndReplace(TITLE, MESSAGE, REGEX)).isEqualTo(EXPECTED);
    }

    @Test
    public void captureGroupAndReplace_missingPlaceholderInFinalContainer() {
        final String TITLE = "The ${level} log had a time of ${time}, and a level of ${level}";
        final String MESSAGE = "wolverine1 lp2-wolverine: 2017-07-21 11:32:11,266 WARN : com.oe.lp2.services.course.DBCourseService";
        final String REGEX = "(?<date>[\\d-]+) (?<time>[\\d:,]+) (?<level>[A-Z]+)";

        final String EXPECTED = "The WARN log had a time of 11:32:11,266, and a level of WARN";

        assertThat(StringUtil.captureGroupAndReplace(TITLE, MESSAGE, REGEX)).isEqualTo(EXPECTED);
    }

    @Test
    public void getPlaceholderNames() throws Exception {
        List names;

        names = StringUtil.getPlaceholderNames("This is a string with the following placeholders: ");
        assertThat(names.size()).isEqualTo(0);
        names = StringUtil.getPlaceholderNames("The following placeholders: ${placeholder1}");
        assertThat(names.size()).isEqualTo(1);
        assertThat(names).contains("placeholder1");
        names = StringUtil.getPlaceholderNames("The following placeholders: ${placeholder1} and also ${placeholder2}");
        assertThat(names.size()).isEqualTo(2);
        assertThat(names).contains("placeholder1", "placeholder2");
        names = StringUtil.getPlaceholderNames("The following placeholders: ${p1}, ${p2}, also ${p3} and also again ${p1}");
        assertThat(names.size()).isEqualTo(3);
        assertThat(names).contains("p1", "p2", "p3");
    }

}