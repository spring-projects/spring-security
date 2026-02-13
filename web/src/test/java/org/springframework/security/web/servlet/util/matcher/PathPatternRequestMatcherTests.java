/*
 * Copyright 2004-present the original author or authors.
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
import static org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher.pathPattern;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

/**
 * Tests for {@link PathPatternRequestMatcher}
 */
public class PathPatternRequestMatcherTests {

	@Test
	void matcherWhenPatternMatchesRequestThenMatchResult() {
		RequestMatcher matcher = pathPattern("/uri");
		assertThat(matcher.matches(request("/uri"))).isTrue();
	}

	@Test
	void matcherWhenPatternContainsPlaceholdersThenMatchResult() {
		RequestMatcher matcher = pathPattern("/uri/{username}");
		assertThat(matcher.matcher(request("/uri/bob")).getVariables()).containsEntry("username", "bob");
	}

	@Test
	void matcherWhenOnlyPathInfoMatchesThenNoMatch() {
		RequestMatcher matcher = pathPattern("/uri");
		assertThat(matcher.matches(request("GET", "/mvc/uri", "/mvc"))).isFalse();
	}

	@Test
	void matcherWhenUriContainsServletPathThenMatch() {
		RequestMatcher matcher = pathPattern("/mvc/uri");
		assertThat(matcher.matches(request("GET", "/mvc/uri", "/mvc"))).isTrue();
	}

	@Test
	void matcherWhenSameMethodThenMatchResult() {
		RequestMatcher matcher = pathPattern(HttpMethod.GET, "/uri");
		assertThat(matcher.matches(request("/uri"))).isTrue();
	}

	@Test
	void matcherWhenDifferentPathThenNoMatch() {
		RequestMatcher matcher = pathPattern(HttpMethod.GET, "/uri");
		assertThat(matcher.matches(request("GET", "/urj", ""))).isFalse();
	}

	@Test
	void matcherWhenDifferentMethodThenNoMatch() {
		RequestMatcher matcher = pathPattern(HttpMethod.GET, "/uri");
		assertThat(matcher.matches(request("POST", "/mvc/uri", "/mvc"))).isFalse();
	}

	@Test
	void matcherWhenNoMethodThenMatches() {
		RequestMatcher matcher = pathPattern("/uri");
		assertThat(matcher.matches(request("POST", "/uri", ""))).isTrue();
		assertThat(matcher.matches(request("GET", "/uri", ""))).isTrue();
	}

	@Test
	void matcherWhenServletPathThenMatchesOnlyServletPath() {
		PathPatternRequestMatcher.Builder servlet = PathPatternRequestMatcher.withDefaults().basePath("/servlet/path");
		RequestMatcher matcher = servlet.matcher(HttpMethod.GET, "/endpoint");
		ServletContext servletContext = servletContext("/servlet/path");
		MockHttpServletRequest mock = get("/servlet/path/endpoint").servletPath("/servlet/path")
			.buildRequest(servletContext);
		ServletRequestPathUtils.parseAndCache(mock);
		assertThat(matcher.matches(mock)).isTrue();
		mock = get("/endpoint").servletPath("/endpoint").buildRequest(servletContext);
		ServletRequestPathUtils.parseAndCache(mock);
		assertThat(matcher.matches(mock)).isFalse();
	}

	@Test
	void matcherWhenRequestPathThenRequiresServletPath() {
		PathPatternRequestMatcher.Builder request = PathPatternRequestMatcher.withDefaults();
		RequestMatcher matcher = request.matcher(HttpMethod.GET, "/endpoint");
		MockHttpServletRequest mock = get("/servlet/path/endpoint").servletPath("/servlet/path").buildRequest(null);
		ServletRequestPathUtils.parseAndCache(mock);
		assertThat(matcher.matches(mock)).isFalse();
		mock = get("/endpoint").servletPath("/endpoint").buildRequest(null);
		ServletRequestPathUtils.parseAndCache(mock);
		assertThat(matcher.matches(mock)).isTrue();
	}

	@Test
	void matcherWhenMultiServletPathThenMatches() {
		PathPatternRequestMatcher.Builder servlet = PathPatternRequestMatcher.withDefaults().basePath("/servlet/path");
		RequestMatcher matcher = servlet.matcher(HttpMethod.GET, "/endpoint");
		MockHttpServletRequest mock = get("/servlet/path/endpoint").servletPath("/servlet/path").buildRequest(null);
		assertThat(matcher.matches(mock)).isTrue();
	}

	@Test
	void matcherWhenMultiContextPathThenMatches() {
		PathPatternRequestMatcher.Builder servlet = PathPatternRequestMatcher.withDefaults().basePath("/servlet/path");
		RequestMatcher matcher = servlet.matcher(HttpMethod.GET, "/endpoint");
		assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> matcher.matches(
				get("/servlet/path/endpoint").servletPath("/servlet/path").contextPath("/app").buildRequest(null)));
	}

	@Test
	void servletPathWhenEndsWithSlashOrStarThenIllegalArgument() {
		assertThatExceptionOfType(IllegalArgumentException.class)
			.isThrownBy(() -> PathPatternRequestMatcher.withDefaults().basePath("/path/**"));
		assertThatExceptionOfType(IllegalArgumentException.class)
			.isThrownBy(() -> PathPatternRequestMatcher.withDefaults().basePath("/path/*"));
		assertThatExceptionOfType(IllegalArgumentException.class)
			.isThrownBy(() -> PathPatternRequestMatcher.withDefaults().basePath("/path/"));
	}

	@Test
	void matcherWhenBasePathIsRootThenNoDoubleSlash() {
		PathPatternRequestMatcher.Builder builder = PathPatternRequestMatcher.withDefaults().basePath("/");
		RequestMatcher matcher = builder.matcher(HttpMethod.GET, "/path");
		MockHttpServletRequest mock = get("/path").servletPath("/path").buildRequest(null);
		assertThat(matcher.matches(mock)).isTrue();
	}

	@Test
	void matcherWhenRequestMethodIsNullThenNoNullPointerException() {
		RequestMatcher matcher = pathPattern(HttpMethod.GET, "/");
		MockHttpServletRequest mock = new MockHttpServletRequest(null, "/");
		ServletRequestPathUtils.parseAndCache(mock);
		assertThat(matcher.matches(mock)).isFalse();
	}

	@Test
	void matcherWhenRequestPathNotParsedThenDoesNotLeaveParsedRequestPath() {
		RequestMatcher matcher = pathPattern("/uri");
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/uri");
		assertThat(ServletRequestPathUtils.hasParsedRequestPath(request)).isFalse();
		assertThat(matcher.matches(request)).isTrue();
		assertThat(ServletRequestPathUtils.hasParsedRequestPath(request)).isFalse();
	}

	@Test
	void matcherWhenRequestPathAlreadyParsedThenLeavesParsedRequestPath() {
		RequestMatcher matcher = pathPattern("/uri");
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/uri");
		ServletRequestPathUtils.parseAndCache(request);
		assertThat(ServletRequestPathUtils.hasParsedRequestPath(request)).isTrue();
		assertThat(matcher.matches(request)).isTrue();
		assertThat(ServletRequestPathUtils.hasParsedRequestPath(request)).isTrue();
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
