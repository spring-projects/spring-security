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

package org.springframework.security.web.util.matcher;

import jakarta.servlet.Servlet;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletRegistration;
import org.junit.jupiter.api.Test;

import org.springframework.http.HttpMethod;
import org.springframework.security.web.servlet.MockServletContext;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

/**
 * Tests for {@link RequestMatchers}.
 *
 * @author Christian Schuster
 */
class RequestMatchersTests {

	@Test
	void checkAnyOfWhenOneMatchThenMatch() {
		RequestMatcher composed = RequestMatchers.anyOf((r) -> false, (r) -> true);
		boolean match = composed.matches(null);
		assertThat(match).isTrue();
	}

	@Test
	void checkAnyOfWhenNoneMatchThenNotMatch() {
		RequestMatcher composed = RequestMatchers.anyOf((r) -> false, (r) -> false);
		boolean match = composed.matches(null);
		assertThat(match).isFalse();
	}

	@Test
	void checkAnyOfWhenEmptyThenNotMatch() {
		RequestMatcher composed = RequestMatchers.anyOf();
		boolean match = composed.matches(null);
		assertThat(match).isFalse();
	}

	@Test
	void checkAllOfWhenOneNotMatchThenNotMatch() {
		RequestMatcher composed = RequestMatchers.allOf((r) -> false, (r) -> true);
		boolean match = composed.matches(null);
		assertThat(match).isFalse();
	}

	@Test
	void checkAllOfWhenAllMatchThenMatch() {
		RequestMatcher composed = RequestMatchers.allOf((r) -> true, (r) -> true);
		boolean match = composed.matches(null);
		assertThat(match).isTrue();
	}

	@Test
	void checkAllOfWhenEmptyThenMatch() {
		RequestMatcher composed = RequestMatchers.allOf();
		boolean match = composed.matches(null);
		assertThat(match).isTrue();
	}

	@Test
	void checkNotWhenMatchThenNotMatch() {
		RequestMatcher composed = RequestMatchers.not((r) -> true);
		boolean match = composed.matches(null);
		assertThat(match).isFalse();
	}

	@Test
	void checkNotWhenNotMatchThenMatch() {
		RequestMatcher composed = RequestMatchers.not((r) -> false);
		boolean match = composed.matches(null);
		assertThat(match).isTrue();
	}

	@Test
	void matcherWhenServletPathThenMatchesOnlyServletPath() {
		RequestMatchers.Builder servlet = RequestMatchers.servletPath("/servlet/path");
		RequestMatcher matcher = servlet.methods(HttpMethod.GET).pathPatterns("/endpoint").matcher();
		ServletContext servletContext = servletContext("/servlet/path");
		assertThat(matcher
			.matches(get("/servlet/path/endpoint").servletPath("/servlet/path").buildRequest(servletContext))).isTrue();
		assertThat(matcher.matches(get("/endpoint").servletPath("/endpoint").buildRequest(servletContext))).isFalse();
	}

	@Test
	void matcherWhenRequestPathThenIgnoresServletPath() {
		RequestMatchers.Builder request = RequestMatchers.request();
		RequestMatcher matcher = request.methods(HttpMethod.GET).pathPatterns("/endpoint").matcher();
		assertThat(matcher.matches(get("/servlet/path/endpoint").servletPath("/servlet/path").buildRequest(null)))
			.isTrue();
		assertThat(matcher.matches(get("/endpoint").servletPath("/endpoint").buildRequest(null))).isTrue();
	}

	@Test
	void matcherWhenServletPathThenRequiresServletPathToExist() {
		RequestMatchers.Builder servlet = RequestMatchers.servletPath("/servlet/path");
		RequestMatcher matcher = servlet.methods(HttpMethod.GET).pathPatterns("/endpoint").matcher();
		assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(
				() -> matcher.matches(get("/servlet/path/endpoint").servletPath("/servlet/path").buildRequest(null)));
	}

	@Test
	void servletPathWhenEndsWithSlashOrStarThenIllegalArgument() {
		assertThatExceptionOfType(IllegalArgumentException.class)
			.isThrownBy(() -> RequestMatchers.servletPath("/path/**"));
		assertThatExceptionOfType(IllegalArgumentException.class)
			.isThrownBy(() -> RequestMatchers.servletPath("/path/*"));
		assertThatExceptionOfType(IllegalArgumentException.class)
			.isThrownBy(() -> RequestMatchers.servletPath("/path/"));
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
