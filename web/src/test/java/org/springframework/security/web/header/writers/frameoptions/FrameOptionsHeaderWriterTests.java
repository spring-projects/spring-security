/*
 * Copyright 2002-2013 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.web.header.writers.frameoptions;

import static org.fest.assertions.Assertions.assertThat;
import static org.mockito.Mockito.when;

import java.util.Collections;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.web.header.writers.frameoptions.AllowFromStrategy;
import org.springframework.security.web.header.writers.frameoptions.XFrameOptionsHeaderWriter;
import org.springframework.security.web.header.writers.frameoptions.XFrameOptionsHeaderWriter.XFrameOptionsMode;

/**
 * @author Rob Winch
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class FrameOptionsHeaderWriterTests {
    @Mock
    private AllowFromStrategy strategy;

    private MockHttpServletResponse response;

    private MockHttpServletRequest request;

    private XFrameOptionsHeaderWriter writer;

    @Before
    public void setup() {
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
    }

    @Test(expected = IllegalArgumentException.class)
    public void constructorNullMode() {
        new XFrameOptionsHeaderWriter((XFrameOptionsMode)null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void constructorAllowFromNoAllowFromStrategy() {
        new XFrameOptionsHeaderWriter(XFrameOptionsMode.ALLOW_FROM);
    }

    @Test(expected = IllegalArgumentException.class)
    public void constructorNullAllowFromStrategy() {
        new XFrameOptionsHeaderWriter((AllowFromStrategy)null);
    }

    @Test
    public void writeHeadersAllowFromReturnsNull() {
        writer = new XFrameOptionsHeaderWriter(strategy);

        writer.writeHeaders(request, response);

        assertThat(response.getHeaderNames().isEmpty()).isTrue();
    }

    @Test
    public void writeHeadersAllowFrom() {
        String allowFromValue = "https://example.com/";
        when(strategy.getAllowFromValue(request)).thenReturn(allowFromValue);
        writer = new XFrameOptionsHeaderWriter(strategy);

        writer.writeHeaders(request, response);

        assertThat(response.getHeaderNames().size()).isEqualTo(1);
        assertThat(response.getHeader(XFrameOptionsHeaderWriter.XFRAME_OPTIONS_HEADER)).isEqualTo("ALLOW-FROM " + allowFromValue);
    }

    @Test
    public void writeHeadersDeny() {
        writer = new XFrameOptionsHeaderWriter(XFrameOptionsMode.DENY);

        writer.writeHeaders(request, response);

        assertThat(response.getHeaderNames().size()).isEqualTo(1);
        assertThat(response.getHeader(XFrameOptionsHeaderWriter.XFRAME_OPTIONS_HEADER)).isEqualTo("DENY");
    }


    @Test
    public void writeHeadersSameOrigin() {
        writer = new XFrameOptionsHeaderWriter(XFrameOptionsMode.SAMEORIGIN);

        writer.writeHeaders(request, response);

        assertThat(response.getHeaderNames().size()).isEqualTo(1);
        assertThat(response.getHeader(XFrameOptionsHeaderWriter.XFRAME_OPTIONS_HEADER)).isEqualTo("SAMEORIGIN");
    }
}
