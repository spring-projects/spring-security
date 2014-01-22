package org.springframework.security.web.header.writers.frameoptions;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

import java.util.regex.PatternSyntaxException;

import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.web.header.writers.frameoptions.RegExpAllowFromStrategy;

/**
 *
 * @author Marten Deinum
 */
public class RegExpAllowFromStrategyTests {

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
        strategy.setAllowFromParameterName("from");
        MockHttpServletRequest request = new MockHttpServletRequest();

        request.setParameter("from", "http://abc.test.com");
        String result1 = strategy.getAllowFromValue(request);
        assertThat(result1, is("ALLOW-FROM http://abc.test.com"));

        request.setParameter("from", "http://foo.test.com");
        String result2 = strategy.getAllowFromValue(request);
        assertThat(result2, is("ALLOW-FROM http://foo.test.com"));

        request.setParameter("from", "http://test.foobar.com");
        String result3 = strategy.getAllowFromValue(request);
        assertThat(result3, is("DENY"));
    }

    @Test
    public void noParameterShouldDeny() {
        RegExpAllowFromStrategy strategy = new RegExpAllowFromStrategy("^http://([a-z0-9]*?\\.)test\\.com");
        MockHttpServletRequest request = new MockHttpServletRequest();
        String result1 = strategy.getAllowFromValue(request);
        assertThat(result1, is("DENY"));
    }
}
