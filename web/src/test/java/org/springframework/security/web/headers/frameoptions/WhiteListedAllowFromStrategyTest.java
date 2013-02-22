package org.springframework.security.web.headers.frameoptions;

import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;

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
public class WhiteListedAllowFromStrategyTest {

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
        allowed.add("http://www.test.com");
        WhiteListedAllowFromStrategy strategy = new WhiteListedAllowFromStrategy(allowed);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setParameter("from", "http://www.test.com");

        String result = strategy.apply(request);
        assertThat(result, is("ALLOW-FROM http://www.test.com"));
    }

    @Test
    public void listWithMultipleElementShouldMatch() {
        List<String> allowed = new ArrayList<String>();
        allowed.add("http://www.test.com");
        allowed.add("http://www.springsource.org");
        WhiteListedAllowFromStrategy strategy = new WhiteListedAllowFromStrategy(allowed);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setParameter("from", "http://www.test.com");

        String result = strategy.apply(request);
        assertThat(result, is("ALLOW-FROM http://www.test.com"));
    }

    @Test
    public void listWithSingleElementShouldNotMatch() {
        List<String> allowed = new ArrayList<String>();
        allowed.add("http://www.test.com");
        WhiteListedAllowFromStrategy strategy = new WhiteListedAllowFromStrategy(allowed);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setParameter("from", "http://www.test123.com");

        String result = strategy.apply(request);
        assertThat(result, is("DENY"));
    }

    @Test
    public void requestWithoutParameterShouldNotMatch() {
        List<String> allowed = new ArrayList<String>();
        allowed.add("http://www.test.com");
        WhiteListedAllowFromStrategy strategy = new WhiteListedAllowFromStrategy(allowed);
        MockHttpServletRequest request = new MockHttpServletRequest();

        String result = strategy.apply(request);
        assertThat(result, is("DENY"));

    }


}
