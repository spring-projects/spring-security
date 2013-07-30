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

import static org.fest.assertions.Assertions.assertThat;

import java.util.Arrays;

import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

/**
 * @author Rob Winch
 *
 */
public class CacheControlHeadersWriterTests {

    private MockHttpServletRequest request;

    private MockHttpServletResponse response;

    private CacheControlHeadersWriter writer;

    @Before
    public void setup() {
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
        writer = new CacheControlHeadersWriter();
    }

    @Test
    public void writeHeaders() {
        writer.writeHeaders(request, response);

        assertThat(response.getHeaderNames().size()).isEqualTo(2);
        assertThat(response.getHeaderValues("Cache-Control")).isEqualTo(Arrays.asList("no-cache","no-store","max-age=0","must-revalidate"));
        assertThat(response.getHeaderValues("Pragma")).isEqualTo(Arrays.asList("no-cache"));
    }
}
