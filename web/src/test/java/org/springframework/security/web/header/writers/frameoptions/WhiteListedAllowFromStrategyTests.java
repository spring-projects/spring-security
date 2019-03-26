package org.springframework.security.web.header.writers.frameoptions;

import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.web.header.writers.frameoptions.WhiteListedAllowFromStrategy;

import java.util.ArrayList;
import java.util.List;

import static org.hamcrest.CoreMatchers.is;
import static org.springframework.test.util.MatcherAssertionErrors.assertThat;

/**
 * Test for the {@code WhiteListedAllowFromStrategy}.
 *
 * @author Marten Deinum
 * @since 3.2
 */
public class WhiteListedAllowFromStrategyTests {

    @Test(expected = IllegalArgumentException.class)
    public void emptyListShouldThrowException() {
        new WhiteListedAllowFromStrategy(new ArrayList<String>());
    }

    @Test(expected = IllegalArgumentException.class)
    public void nullListShouldThrowException() {
        new WhiteListedAllowFromStrategy(null);
    }

    @Test
    public void listWithSingleElementShouldMatch() {
        List<String> allowed = new ArrayList<String>();
        allowed.add("https://www.test.com");
        WhiteListedAllowFromStrategy strategy = new WhiteListedAllowFromStrategy(allowed);
        strategy.setAllowFromParameterName("from");
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setParameter("from", "https://www.test.com");

        String result = strategy.getAllowFromValue(request);
        assertThat(result, is("https://www.test.com"));
    }

    @Test
    public void listWithMultipleElementShouldMatch() {
        List<String> allowed = new ArrayList<String>();
        allowed.add("https://www.test.com");
        allowed.add("https://www.springsource.org");
        WhiteListedAllowFromStrategy strategy = new WhiteListedAllowFromStrategy(allowed);
        strategy.setAllowFromParameterName("from");
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setParameter("from", "https://www.test.com");

        String result = strategy.getAllowFromValue(request);
        assertThat(result, is("https://www.test.com"));
    }

    @Test
    public void listWithSingleElementShouldNotMatch() {
        List<String> allowed = new ArrayList<String>();
        allowed.add("https://www.test.com");
        WhiteListedAllowFromStrategy strategy = new WhiteListedAllowFromStrategy(allowed);
        strategy.setAllowFromParameterName("from");
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setParameter("from", "https://www.test123.com");

        String result = strategy.getAllowFromValue(request);
        assertThat(result, is("DENY"));
    }

    @Test
    public void requestWithoutParameterShouldNotMatch() {
        List<String> allowed = new ArrayList<String>();
        allowed.add("https://www.test.com");
        WhiteListedAllowFromStrategy strategy = new WhiteListedAllowFromStrategy(allowed);
        strategy.setAllowFromParameterName("from");
        MockHttpServletRequest request = new MockHttpServletRequest();

        String result = strategy.getAllowFromValue(request);
        assertThat(result, is("DENY"));

    }


}
