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
package org.springframework.security.web.util.matchers;

import static org.fest.assertions.Assertions.assertThat;

import java.util.Collections;

import org.junit.Before;
import org.junit.Test;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.web.util.matchers.MediaTypeRequestMatcher;
import org.springframework.web.accept.ContentNegotiationStrategy;
import org.springframework.web.accept.HeaderContentNegotiationStrategy;

/**
 * Verify how integrates with {@link HeaderContentNegotiationStrategy}.
 *
 * @author Rob Winch
 *
 */
public class MediaTypeRequestMatcherRequestHCNSTests {
    private MediaTypeRequestMatcher matcher;
    private MockHttpServletRequest request;

    private ContentNegotiationStrategy negotiationStrategy;

    @Before
    public void setup() {
        negotiationStrategy = new HeaderContentNegotiationStrategy();
        request = new MockHttpServletRequest();
    }

    @Test
    public void mediaAllMatches() {
        request.addHeader("Accept", MediaType.ALL_VALUE);
        matcher = new MediaTypeRequestMatcher(negotiationStrategy, MediaType.TEXT_HTML);

        assertThat(matcher.matches(request)).isTrue();

        matcher = new MediaTypeRequestMatcher(negotiationStrategy, MediaType.APPLICATION_XHTML_XML);
        assertThat(matcher.matches(request)).isTrue();
    }

    // ignoreMediaTypeAll

    @Test
    public void mediaAllIgnoreMediaTypeAll() {
        request.addHeader("Accept", MediaType.ALL_VALUE);
        matcher = new MediaTypeRequestMatcher(negotiationStrategy, MediaType.TEXT_HTML);
        matcher.setIgnoredMediaTypes(Collections.singleton(MediaType.ALL));

        assertThat(matcher.matches(request)).isFalse();
    }

    @Test
    public void mediaAllAndTextHtmlIgnoreMediaTypeAll() {
        request.addHeader("Accept", MediaType.ALL_VALUE + "," + MediaType.TEXT_HTML_VALUE);
        matcher = new MediaTypeRequestMatcher(negotiationStrategy, MediaType.TEXT_HTML);
        matcher.setIgnoredMediaTypes(Collections.singleton(MediaType.ALL));

        assertThat(matcher.matches(request)).isTrue();
    }

    // JavaDoc

    @Test
    public void javadocJsonJson() {
        request.addHeader("Accept", MediaType.APPLICATION_JSON_VALUE);
        MediaTypeRequestMatcher matcher = new MediaTypeRequestMatcher(negotiationStrategy, MediaType.APPLICATION_JSON);

        assertThat(matcher.matches(request)).isTrue();
    }


    @Test
    public void javadocAllJson() {
        request.addHeader("Accept", MediaType.ALL_VALUE);
        MediaTypeRequestMatcher matcher = new MediaTypeRequestMatcher(negotiationStrategy, MediaType.APPLICATION_JSON);

        assertThat(matcher.matches(request)).isTrue();
    }


    @Test
    public void javadocAllJsonIgnoreAll() {
        request.addHeader("Accept", MediaType.ALL_VALUE);
        MediaTypeRequestMatcher matcher = new MediaTypeRequestMatcher(negotiationStrategy, MediaType.APPLICATION_JSON);
        matcher.setIgnoredMediaTypes(Collections.singleton(MediaType.ALL));
        assertThat(matcher.matches(request)).isFalse();
    }


    @Test
    public void javadocJsonJsonIgnoreAll() {
        request.addHeader("Accept", MediaType.APPLICATION_JSON_VALUE);
        MediaTypeRequestMatcher matcher = new MediaTypeRequestMatcher(negotiationStrategy, MediaType.APPLICATION_JSON);
        matcher.setIgnoredMediaTypes(Collections.singleton(MediaType.ALL));
        assertThat(matcher.matches(request)).isTrue();
    }


    @Test
    public void javadocJsonJsonUseEquals() {
        request.addHeader("Accept", MediaType.APPLICATION_JSON_VALUE);
        MediaTypeRequestMatcher matcher = new MediaTypeRequestMatcher(negotiationStrategy, MediaType.APPLICATION_JSON);
        matcher.setUseEquals(true);
        assertThat(matcher.matches(request)).isTrue();
    }

    @Test
    public void javadocAllJsonUseEquals() {
        request.addHeader("Accept", MediaType.ALL_VALUE);
        MediaTypeRequestMatcher matcher = new MediaTypeRequestMatcher(negotiationStrategy, MediaType.APPLICATION_JSON);
        matcher.setUseEquals(true);
        assertThat(matcher.matches(request)).isFalse();
    }


    @Test
    public void javadocApplicationAllJsonUseEquals() {
        request.addHeader("Accept", new MediaType("application","*"));
        MediaTypeRequestMatcher matcher = new MediaTypeRequestMatcher(negotiationStrategy, MediaType.APPLICATION_JSON);
        matcher.setUseEquals(true);
        assertThat(matcher.matches(request)).isFalse();
    }


    @Test
    public void javadocAllJsonUseFalse() {
        request.addHeader("Accept", MediaType.ALL_VALUE);
        MediaTypeRequestMatcher matcher = new MediaTypeRequestMatcher(negotiationStrategy, MediaType.APPLICATION_JSON);
        matcher.setUseEquals(true);
        assertThat(matcher.matches(request)).isFalse();
    }
}