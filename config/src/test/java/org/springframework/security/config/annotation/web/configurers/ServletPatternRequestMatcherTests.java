/*
 * Copyright 2002-2023 the original author or authors.
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

package org.springframework.security.config.annotation.web.configurers;

import org.junit.jupiter.api.Test;

import org.springframework.mock.web.MockHttpServletRequest;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link ServletPatternRequestMatcher}
 */
class ServletPatternRequestMatcherTests {

	ServletPatternRequestMatcher matcher = new ServletPatternRequestMatcher("*.jsp");

	@Test
	void matchesWhenDefaultServletThenTrue() {
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/a/uri.jsp");
		request.setHttpServletMapping(TestMockHttpServletMappings.extension(request, ".jsp"));
		assertThat(this.matcher.matches(request)).isTrue();
	}

	@Test
	void matchesWhenNotDefaultServletThenFalse() {
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/a/uri.jsp");
		request.setHttpServletMapping(TestMockHttpServletMappings.path(request, "/a"));
		request.setServletPath("/a/uri.jsp");
		assertThat(this.matcher.matches(request)).isFalse();
	}

	@Test
	void matcherWhenDefaultServletThenTrue() {
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/a/uri.jsp");
		request.setHttpServletMapping(TestMockHttpServletMappings.extension(request, ".jsp"));
		request.setServletPath("/a/uri.jsp");
		assertThat(this.matcher.matcher(request).isMatch()).isTrue();
	}

	@Test
	void matcherWhenNotDefaultServletThenFalse() {
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/a/uri.jsp");
		request.setHttpServletMapping(TestMockHttpServletMappings.path(request, "/a"));
		request.setServletPath("/a/uri.jsp");
		assertThat(this.matcher.matcher(request).isMatch()).isFalse();
	}

}
