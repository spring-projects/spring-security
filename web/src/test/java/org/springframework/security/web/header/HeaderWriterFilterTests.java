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
package org.springframework.security.web.header;

import static org.fest.assertions.Assertions.assertThat;
import static org.mockito.Mockito.verify;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.web.header.HeaderWriter;
import org.springframework.security.web.header.HeaderWriterFilter;

/**
 * Tests for the {@code HeadersFilter}
 *
 * @author Marten Deinum
 * @author Rob Winch
 * @since 3.2
 */
@RunWith(MockitoJUnitRunner.class)
public class HeaderWriterFilterTests {
    @Mock
    private HeaderWriter writer1;

    @Mock
    private HeaderWriter writer2;

    @Test(expected = IllegalArgumentException.class)
    public void noHeadersConfigured() throws Exception {
        List<HeaderWriter> headerWriters = new ArrayList<HeaderWriter>();
        new HeaderWriterFilter(headerWriters);
    }

    @Test(expected = IllegalArgumentException.class)
    public void constructorNullWriters() throws Exception {
        new HeaderWriterFilter(null);
    }

    @Test
    public void additionalHeadersShouldBeAddedToTheResponse() throws Exception {
        List<HeaderWriter> headerWriters = new ArrayList<HeaderWriter>();
        headerWriters.add(writer1);
        headerWriters.add(writer2);

        HeaderWriterFilter filter = new HeaderWriterFilter(headerWriters);

        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain filterChain = new MockFilterChain();

        filter.doFilter(request, response, filterChain);

        verify(writer1).writeHeaders(request, response);
        verify(writer2).writeHeaders(request, response);
        assertThat(filterChain.getRequest()).isEqualTo(request); // verify the filterChain continued
    }
}
