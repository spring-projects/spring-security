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
package org.springframework.security.web.header.writers;

import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.web.header.HeaderWriter;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * @author Rob Winch
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class DelegatingRequestMatcherHeaderWriterTests {
    @Mock
    private RequestMatcher matcher;

    @Mock
    private HeaderWriter delegate;

    private MockHttpServletRequest request;

    private MockHttpServletResponse response;

    private DelegatingRequestMatcherHeaderWriter headerWriter;

    @Before
    public void setup() {
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
        headerWriter = new DelegatingRequestMatcherHeaderWriter(matcher, delegate);
    }

    @Test(expected = IllegalArgumentException.class)
    public void constructorNullRequestMatcher() {
        new DelegatingRequestMatcherHeaderWriter(null, delegate);
    }

    @Test(expected = IllegalArgumentException.class)
    public void constructorNullDelegate() {
        new DelegatingRequestMatcherHeaderWriter(matcher, null);
    }

    @Test
    public void writeHeadersOnMatch() {
        when(matcher.matches(request)).thenReturn(true);

        headerWriter.writeHeaders(request, response);

        verify(delegate).writeHeaders(request, response);
    }

    @Test
    public void writeHeadersOnNoMatch() {
        when(matcher.matches(request)).thenReturn(false);

        headerWriter.writeHeaders(request, response);

        verify(delegate, times(0)).writeHeaders(request, response);
    }
}
