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
import jakarta.servlet.ServletRegistration.Dynamic;
import org.junit.jupiter.api.Test;

import org.springframework.http.HttpMethod;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.web.servlet.MockServletContext;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcherBuilder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

/**
 * Tests for {@link ServletRequestMatcherBuilders}
 */
class ServletRequestMatcherBuildersTests {

	@Test
	void matcherWhenServletPathThenMatchesOnlyServletPath() {
		RequestMatcherBuilder builder = ServletRequestMatcherBuilders.servletPath("/servlet/path");
		RequestMatcher requestMatcher = builder.matcher(HttpMethod.GET, "/endpoint");
		assertThat(requestMatcher.matches(request("/servlet/path/endpoint", "/servlet/path"))).isTrue();
		assertThat(requestMatcher.matches(request("/endpoint", "/endpoint", "/servlet/path/*"))).isFalse();
	}

	@Test
	void matcherWhenRequestPathThenIgnoresServletPath() {
		RequestMatcherBuilder builder = ServletRequestMatcherBuilders.requestPath();
		RequestMatcher requestMatcher = builder.matcher(HttpMethod.GET, "/endpoint");
		assertThat(requestMatcher.matches(request("/servlet/path/endpoint", "/servlet/path", "/endpoint"))).isFalse();
		assertThat(requestMatcher.matches(request("/endpoint", "/endpoint"))).isTrue();
	}

	@Test
	void matcherWhenServletPathThenRequiresServletPathToExist() {
		RequestMatcherBuilder builder = ServletRequestMatcherBuilders.servletPath("/servlet/path");
		RequestMatcher requestMatcher = builder.matcher(HttpMethod.GET, "/endpoint");
		assertThatExceptionOfType(IllegalArgumentException.class)
			.isThrownBy(() -> requestMatcher.matches(request("/servlet/path/endpoint", "/servlet/path", "")));
	}

	@Test
	void servletPathWhenEndsWithSlashOrStarThenIllegalArgument() {
		assertThatExceptionOfType(IllegalArgumentException.class)
			.isThrownBy(() -> ServletRequestMatcherBuilders.servletPath("/path/**"));
		assertThatExceptionOfType(IllegalArgumentException.class)
			.isThrownBy(() -> ServletRequestMatcherBuilders.servletPath("/path/*"));
		assertThatExceptionOfType(IllegalArgumentException.class)
			.isThrownBy(() -> ServletRequestMatcherBuilders.servletPath("/path/"));
	}

	MockHttpServletRequest request(String uri, String servletPath) {
		MockServletContext servletContext = new MockServletContext();
		Dynamic registration = servletContext.addServlet("servlet", Servlet.class);
		registration.addMapping(servletPath + "/*");
		MockHttpServletRequest request = new MockHttpServletRequest(servletContext, "GET", uri);
		request.setServletPath(servletPath);
		return request;
	}

	MockHttpServletRequest request(String uri, String servletPath, String... servlets) {
		MockServletContext servletContext = new MockServletContext();
		Dynamic registration = servletContext.addServlet("servlet", Servlet.class);
		registration.addMapping(servlets);
		MockHttpServletRequest request = new MockHttpServletRequest(servletContext, "GET", uri);
		request.setServletPath(servletPath);
		return request;
	}

}
