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

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.*;

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
        List<HeaderFactory> factories = new ArrayList();
        HeadersFilter filter = new HeadersFilter(factories);
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain filterChain = new MockFilterChain();

        filter.doFilter(request, response, filterChain);

        assertTrue(response.getHeaderNames().isEmpty());
    }

    @Test
    public void additionalHeadersShouldBeAddedToTheResponse() throws Exception {
        List<HeaderFactory> factories = new ArrayList();
        MockHeaderFactory factory1 = new MockHeaderFactory();
        factory1.setName("X-Header1");
        factory1.setValue("foo");
        MockHeaderFactory factory2 = new MockHeaderFactory();
        factory2.setName("X-Header2");
        factory2.setValue("bar");

        factories.add(factory1);
        factories.add(factory2);

        HeadersFilter filter = new HeadersFilter(factories);

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

    private static final class MockHeaderFactory implements HeaderFactory {

        private String name;
        private String value;

        public Header create(HttpServletRequest request, HttpServletResponse response) {
            return new Header(name, value);
        }

        public void setName(String name) {
            this.name=name;
        }

        public void setValue(String value) {
            this.value=value;
        }

    }
}
