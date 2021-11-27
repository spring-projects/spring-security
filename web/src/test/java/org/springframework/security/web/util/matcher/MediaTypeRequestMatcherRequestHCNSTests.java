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

package org.springframework.security.web.util.matcher;

import java.util.Collections;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.accept.ContentNegotiationStrategy;
import org.springframework.web.accept.HeaderContentNegotiationStrategy;

import static org.assertj.core.api.Assertions.assertThat;

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

	@BeforeEach
	public void setup() {
		this.negotiationStrategy = new HeaderContentNegotiationStrategy();
		this.request = new MockHttpServletRequest();
	}

	@Test
	public void mediaAllMatches() {
		this.request.addHeader("Accept", MediaType.ALL_VALUE);
		this.matcher = new MediaTypeRequestMatcher(this.negotiationStrategy, MediaType.TEXT_HTML);
		assertThat(this.matcher.matches(this.request)).isTrue();
		this.matcher = new MediaTypeRequestMatcher(this.negotiationStrategy, MediaType.APPLICATION_XHTML_XML);
		assertThat(this.matcher.matches(this.request)).isTrue();
	}

	// ignoreMediaTypeAll
	@Test
	public void mediaAllIgnoreMediaTypeAll() {
		this.request.addHeader("Accept", MediaType.ALL_VALUE);
		this.matcher = new MediaTypeRequestMatcher(this.negotiationStrategy, MediaType.TEXT_HTML);
		this.matcher.setIgnoredMediaTypes(Collections.singleton(MediaType.ALL));
		assertThat(this.matcher.matches(this.request)).isFalse();
	}

	@Test
	public void mediaAllAndTextHtmlIgnoreMediaTypeAll() {
		this.request.addHeader("Accept", MediaType.ALL_VALUE + "," + MediaType.TEXT_HTML_VALUE);
		this.matcher = new MediaTypeRequestMatcher(this.negotiationStrategy, MediaType.TEXT_HTML);
		this.matcher.setIgnoredMediaTypes(Collections.singleton(MediaType.ALL));
		assertThat(this.matcher.matches(this.request)).isTrue();
	}

	// JavaDoc
	@Test
	public void javadocJsonJson() {
		this.request.addHeader("Accept", MediaType.APPLICATION_JSON_VALUE);
		MediaTypeRequestMatcher matcher = new MediaTypeRequestMatcher(this.negotiationStrategy,
				MediaType.APPLICATION_JSON);
		assertThat(matcher.matches(this.request)).isTrue();
	}

	@Test
	public void javadocAllJson() {
		this.request.addHeader("Accept", MediaType.ALL_VALUE);
		MediaTypeRequestMatcher matcher = new MediaTypeRequestMatcher(this.negotiationStrategy,
				MediaType.APPLICATION_JSON);
		assertThat(matcher.matches(this.request)).isTrue();
	}

	@Test
	public void javadocAllJsonIgnoreAll() {
		this.request.addHeader("Accept", MediaType.ALL_VALUE);
		MediaTypeRequestMatcher matcher = new MediaTypeRequestMatcher(this.negotiationStrategy,
				MediaType.APPLICATION_JSON);
		matcher.setIgnoredMediaTypes(Collections.singleton(MediaType.ALL));
		assertThat(matcher.matches(this.request)).isFalse();
	}

	@Test
	public void javadocJsonJsonIgnoreAll() {
		this.request.addHeader("Accept", MediaType.APPLICATION_JSON_VALUE);
		MediaTypeRequestMatcher matcher = new MediaTypeRequestMatcher(this.negotiationStrategy,
				MediaType.APPLICATION_JSON);
		matcher.setIgnoredMediaTypes(Collections.singleton(MediaType.ALL));
		assertThat(matcher.matches(this.request)).isTrue();
	}

	@Test
	public void javadocJsonJsonUseEquals() {
		this.request.addHeader("Accept", MediaType.APPLICATION_JSON_VALUE);
		MediaTypeRequestMatcher matcher = new MediaTypeRequestMatcher(this.negotiationStrategy,
				MediaType.APPLICATION_JSON);
		matcher.setUseEquals(true);
		assertThat(matcher.matches(this.request)).isTrue();
	}

	@Test
	public void javadocAllJsonUseEquals() {
		this.request.addHeader("Accept", MediaType.ALL_VALUE);
		MediaTypeRequestMatcher matcher = new MediaTypeRequestMatcher(this.negotiationStrategy,
				MediaType.APPLICATION_JSON);
		matcher.setUseEquals(true);
		assertThat(matcher.matches(this.request)).isFalse();
	}

	@Test
	public void javadocApplicationAllJsonUseEquals() {
		this.request.addHeader("Accept", new MediaType("application", "*"));
		MediaTypeRequestMatcher matcher = new MediaTypeRequestMatcher(this.negotiationStrategy,
				MediaType.APPLICATION_JSON);
		matcher.setUseEquals(true);
		assertThat(matcher.matches(this.request)).isFalse();
	}

	@Test
	public void javadocAllJsonUseFalse() {
		this.request.addHeader("Accept", MediaType.ALL_VALUE);
		MediaTypeRequestMatcher matcher = new MediaTypeRequestMatcher(this.negotiationStrategy,
				MediaType.APPLICATION_JSON);
		matcher.setUseEquals(true);
		assertThat(matcher.matches(this.request)).isFalse();
	}

}
