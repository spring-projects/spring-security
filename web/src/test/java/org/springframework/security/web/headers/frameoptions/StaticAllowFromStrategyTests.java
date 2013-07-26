package org.springframework.security.web.headers.frameoptions;

import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.net.URI;

import static org.junit.Assert.assertEquals;

/**
 * Test for the StaticAllowFromStrategy.
 *
 * @author Marten Deinum
 * @since 3.2
 */
public class StaticAllowFromStrategyTests {

    @Test
    public void shouldReturnUri() {
        String uri = "http://www.test.com";
        StaticAllowFromStrategy strategy = new StaticAllowFromStrategy(URI.create(uri));
        assertEquals(uri, strategy.getAllowFromValue(new MockHttpServletRequest()));
    }
}
