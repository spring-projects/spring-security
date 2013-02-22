package org.springframework.security.web.headers.frameoptions;

import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

/**
 * Created with IntelliJ IDEA.
 * User: marten
 * Date: 01-02-13
 * Time: 20:25
 * To change this template use File | Settings | File Templates.
 */
public class RegExpAllowFromStrategyTest {

    @Test(expected = PatternSyntaxException.class)
    public void invalidRegularExpressionShouldLeadToException() {
        new RegExpAllowFromStrategy("[a-z");
    }

    @Test(expected = IllegalArgumentException.class)
    public void nullRegularExpressionShouldLeadToException() {
        new RegExpAllowFromStrategy(null);
    }

    @Test
    public void subdomainMatchingRegularExpression() {
        RegExpAllowFromStrategy strategy = new RegExpAllowFromStrategy("^http://([a-z0-9]*?\\.)test\\.com");
        MockHttpServletRequest request = new MockHttpServletRequest();

        request.setParameter("from", "http://abc.test.com");
        String result1 = strategy.apply(request);
        assertThat(result1, is("ALLOW-FROM http://abc.test.com"));

        request.setParameter("from", "http://foo.test.com");
        String result2 = strategy.apply(request);
        assertThat(result2, is("ALLOW-FROM http://foo.test.com"));

        request.setParameter("from", "http://test.foobar.com");
        String result3 = strategy.apply(request);
        assertThat(result3, is("DENY"));
    }

    @Test
    public void noParameterShouldDeny() {
        RegExpAllowFromStrategy strategy = new RegExpAllowFromStrategy("^http://([a-z0-9]*?\\.)test\\.com");
        MockHttpServletRequest request = new MockHttpServletRequest();
        String result1 = strategy.apply(request);
        assertThat(result1, is("DENY"));
    }

    @Test
    public void test() {
        String pattern = "^http://([a-z0-9]*?\\.)test\\.com";
        Pattern p = Pattern.compile(pattern);
        String url = "http://abc.test.com";
        assertTrue(p.matcher(url).matches());
    }

}
