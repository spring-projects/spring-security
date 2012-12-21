/*
 * Copyright 2002-2013 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.web.headers;

import org.junit.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.matchers.JUnitMatchers.hasItems;

/**
 * Tests for the {@code HeadersFilter}
 *
 * @author Marten Deinum
 * @since 3.2
 */
public class HeadersFilterTest {

    @Test
    public void noHeadersConfigured() throws Exception {
        HeadersFilter filter = new HeadersFilter();
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain filterChain = new MockFilterChain();

        filter.doFilter(request, response, filterChain);

        assertTrue(response.getHeaderNames().isEmpty());
    }

    @Test
    public void additionalHeadersShouldBeAddedToTheResponse() throws Exception {
        HeadersFilter filter = new HeadersFilter();
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("X-Header1", "foo");
        headers.put("X-Header2", "bar");
        filter.setHeaders(headers);

        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain filterChain = new MockFilterChain();

        filter.doFilter(request, response, filterChain);

        Collection<String> headerNames = response.getHeaderNames();
        assertThat(headerNames.size(), is(2));
        assertThat(headerNames, hasItems("X-Header1", "X-Header2"));
        assertThat(response.getHeader("X-Header1"), is("foo"));
        assertThat(response.getHeader("X-Header2"), is("bar"));

    }
}
