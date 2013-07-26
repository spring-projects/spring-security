package org.springframework.security.web.headers;

import static org.fest.assertions.Assertions.assertThat;

import java.util.Arrays;

import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

/**
 * Test for the {@code StaticHeadersWriter}
 *
 * @author Marten Deinum
 * @since 3.2
 */
public class StaticHeaderWriterTests {
    private MockHttpServletRequest request;
    private MockHttpServletResponse response;

    @Before
    public void setup() {
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
    }

    @Test
    public void sameHeaderShouldBeReturned() {
        String headerName = "X-header";
        String headerValue = "foo";
        StaticHeadersWriter factory = new StaticHeadersWriter(headerName, headerValue);

        factory.writeHeaders(request, response);
        assertThat(response.getHeaderValues(headerName)).isEqualTo(Arrays.asList(headerValue));
    }
}
