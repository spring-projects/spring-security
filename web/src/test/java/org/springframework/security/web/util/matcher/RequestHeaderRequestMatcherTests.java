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
package org.springframework.security.web.util.matcher;

import static org.fest.assertions.Assertions.assertThat;

import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.web.util.matcher.RequestHeaderRequestMatcher;

/**
 *
 * @author Rob Winch
 *
 */
public class RequestHeaderRequestMatcherTests {

    private final String headerName = "headerName";

    private final String headerValue = "headerValue";

    private MockHttpServletRequest request;

    @Before
    public void setup() {
        request = new MockHttpServletRequest();
    }

    @Test(expected = IllegalArgumentException.class)
    public void constructorNullHeaderName() {
        new RequestHeaderRequestMatcher(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void constructorNullHeaderNameNonNullHeaderValue() {
        new RequestHeaderRequestMatcher(null,"v");
    }

    @Test
    public void matchesHeaderNameMatches() {
        request.addHeader(headerName, headerValue);
        assertThat(new RequestHeaderRequestMatcher(headerName).matches(request)).isTrue();
    }

    @Test
    public void matchesHeaderNameDoesNotMatch() {
        request.addHeader(headerName+"notMatch", headerValue);
        assertThat(new RequestHeaderRequestMatcher(headerName).matches(request)).isFalse();
    }

    @Test
    public void matchesHeaderNameValueMatches() {
        request.addHeader(headerName, headerValue);
        assertThat(new RequestHeaderRequestMatcher(headerName, headerValue).matches(request)).isTrue();
    }

    @Test
    public void matchesHeaderNameValueHeaderNameNotMatch() {
        request.addHeader(headerName+"notMatch", headerValue);
        assertThat(new RequestHeaderRequestMatcher(headerName, headerValue).matches(request)).isFalse();
    }

    @Test
    public void matchesHeaderNameValueHeaderValueNotMatch() {
        request.addHeader(headerName, headerValue+"notMatch");
        assertThat(new RequestHeaderRequestMatcher(headerName, headerValue).matches(request)).isFalse();
    }

    @Test
    public void matchesHeaderNameValueHeaderValueMultiNotMatch() {
        request.addHeader(headerName, headerValue+"notMatch");
        request.addHeader(headerName, headerValue);
        assertThat(new RequestHeaderRequestMatcher(headerName, headerValue).matches(request)).isFalse();
    }
}
