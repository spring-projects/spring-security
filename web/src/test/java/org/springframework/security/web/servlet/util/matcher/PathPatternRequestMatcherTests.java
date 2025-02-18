/*
 * Copyright 2002-2025 the original author or authors.
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

package org.springframework.security.web.servlet.util.matcher;

import jakarta.servlet.Servlet;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletRegistration;
import org.junit.jupiter.api.Test;

import org.springframework.http.HttpMethod;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.web.servlet.MockServletContext;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.util.ServletRequestPathUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

/**
 * Tests for {@link PathPatternRequestMatcher}
 */
public class PathPatternRequestMatcherTests {

	@Test
	void matcherWhenPatternMatchesRequestThenMatchResult() {
		RequestMatcher matcher = PathPatternRequestMatcher.path().pattern("/uri").matcher();
		assertThat(matcher.matches(request("/uri"))).isTrue();
	}

	@Test
	void matcherWhenPatternContainsPlaceholdersThenMatchResult() {
		RequestMatcher matcher = PathPatternRequestMatcher.path().pattern("/uri/{username}").matcher();
		assertThat(matcher.matcher(request("/uri/bob")).getVariables()).containsEntry("username", "bob");
	}

	@Test
	void matcherWhenOnlyPathInfoMatchesThenMatches() {
		RequestMatcher matcher = PathPatternRequestMatcher.path().pattern("/uri").matcher();
		assertThat(matcher.matches(request("GET", "/mvc/uri", "/mvc"))).isTrue();
	}

	@Test
	void matcherWhenUriContainsServletPathThenNoMatch() {
		RequestMatcher matcher = PathPatternRequestMatcher.path().pattern("/mvc/uri").matcher();
		assertThat(matcher.matches(request("GET", "/mvc/uri", "/mvc"))).isFalse();
	}

	@Test
	void matcherWhenSameMethodThenMatchResult() {
		RequestMatcher matcher = PathPatternRequestMatcher.path().method(HttpMethod.GET).pattern("/uri").matcher();
		assertThat(matcher.matches(request("/uri"))).isTrue();
	}

	@Test
	void matcherWhenDifferentPathThenNoMatch() {
		RequestMatcher matcher = PathPatternRequestMatcher.path().method(HttpMethod.GET).pattern("/uri").matcher();
		assertThat(matcher.matches(request("GET", "/urj", ""))).isFalse();
	}

	@Test
	void matcherWhenDifferentMethodThenNoMatch() {
		RequestMatcher matcher = PathPatternRequestMatcher.path().method(HttpMethod.GET).pattern("/uri").matcher();
		assertThat(matcher.matches(request("POST", "/mvc/uri", "/mvc"))).isFalse();
	}

	@Test
	void matcherWhenNoMethodThenMatches() {
		RequestMatcher matcher = PathPatternRequestMatcher.path().pattern("/uri").matcher();
		assertThat(matcher.matches(request("POST", "/uri", ""))).isTrue();
		assertThat(matcher.matches(request("GET", "/uri", ""))).isTrue();
	}

	@Test
	void matcherWhenServletPathThenMatchesOnlyServletPath() {
		PathPatternRequestMatcher.Builder servlet = PathPatternRequestMatcher.servletPath("/servlet/path");
		RequestMatcher matcher = servlet.method(HttpMethod.GET).pattern("/endpoint").matcher();
		ServletContext servletContext = servletContext("/servlet/path");
		assertThat(matcher
			.matches(get("/servlet/path/endpoint").servletPath("/servlet/path").buildRequest(servletContext))).isTrue();
		assertThat(matcher.matches(get("/endpoint").servletPath("/endpoint").buildRequest(servletContext))).isFalse();
	}

	@Test
	void matcherWhenRequestPathThenIgnoresServletPath() {
		PathPatternRequestMatcher.Builder request = PathPatternRequestMatcher.path();
		RequestMatcher matcher = request.method(HttpMethod.GET).pattern("/endpoint").matcher();
		assertThat(matcher.matches(get("/servlet/path/endpoint").servletPath("/servlet/path").buildRequest(null)))
			.isTrue();
		assertThat(matcher.matches(get("/endpoint").servletPath("/endpoint").buildRequest(null))).isTrue();
	}

	@Test
	void matcherWhenServletPathThenRequiresServletPathToExist() {
		PathPatternRequestMatcher.Builder servlet = PathPatternRequestMatcher.servletPath("/servlet/path");
		RequestMatcher matcher = servlet.method(HttpMethod.GET).pattern("/endpoint").matcher();
		assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(
				() -> matcher.matches(get("/servlet/path/endpoint").servletPath("/servlet/path").buildRequest(null)));
	}

	@Test
	void servletPathWhenEndsWithSlashOrStarThenIllegalArgument() {
		assertThatExceptionOfType(IllegalArgumentException.class)
			.isThrownBy(() -> PathPatternRequestMatcher.servletPath("/path/**"));
		assertThatExceptionOfType(IllegalArgumentException.class)
			.isThrownBy(() -> PathPatternRequestMatcher.servletPath("/path/*"));
		assertThatExceptionOfType(IllegalArgumentException.class)
			.isThrownBy(() -> PathPatternRequestMatcher.servletPath("/path/"));
	}

	MockHttpServletRequest request(String uri) {
		MockHttpServletRequest request = new MockHttpServletRequest("GET", uri);
		ServletRequestPathUtils.parseAndCache(request);
		return request;
	}

	MockHttpServletRequest request(String method, String uri, String servletPath) {
		MockHttpServletRequest request = new MockHttpServletRequest(method, uri);
		request.setServletPath(servletPath);
		ServletRequestPathUtils.parseAndCache(request);
		return request;
	}

	MockServletContext servletContext(String... servletPath) {
		MockServletContext servletContext = new MockServletContext();
		ServletRegistration.Dynamic registration = servletContext.addServlet("servlet", Servlet.class);
		for (String s : servletPath) {
			registration.addMapping(s + "/*");
		}
		return servletContext;
	}

}
