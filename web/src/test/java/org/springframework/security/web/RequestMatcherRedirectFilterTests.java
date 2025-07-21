/*
 * Copyright 2002-2021 the original author or authors.
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

package org.springframework.security.web;

import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.Test;

import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.springframework.security.web.servlet.TestMockHttpServletRequests.get;
import static org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher.pathPattern;

/**
 * Tests for {@link RequestMatcherRedirectFilter}.
 *
 * @author Evgeniy Cheban
 */
public class RequestMatcherRedirectFilterTests {

	@Test
	public void doFilterWhenRequestMatchThenRedirectToSpecifiedUrl() throws Exception {
		RequestMatcherRedirectFilter filter = new RequestMatcherRedirectFilter(pathPattern("/context"), "/test");

		MockHttpServletRequest request = get("/context").build();
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		filter.doFilter(request, response, filterChain);

		assertThat(response.getStatus()).isEqualTo(HttpStatus.FOUND.value());
		assertThat(response.getRedirectedUrl()).isEqualTo("/test");

		verifyNoInteractions(filterChain);
	}

	@Test
	public void doFilterWhenRequestNotMatchThenNextFilter() throws Exception {
		RequestMatcherRedirectFilter filter = new RequestMatcherRedirectFilter(pathPattern("/context"), "/test");

		MockHttpServletRequest request = get("/test").build();

		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		filter.doFilter(request, response, filterChain);

		assertThat(response.getStatus()).isEqualTo(HttpStatus.OK.value());

		verify(filterChain).doFilter(request, response);
	}

	@Test
	public void constructWhenRequestMatcherNull() {
		assertThatIllegalArgumentException().isThrownBy(() -> new RequestMatcherRedirectFilter(null, "/test"))
			.withMessage("requestMatcher cannot be null");
	}

	@Test
	public void constructWhenRedirectUrlNull() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> new RequestMatcherRedirectFilter(pathPattern("/**"), null))
			.withMessage("redirectUrl cannot be empty");
	}

	@Test
	public void constructWhenRedirectUrlEmpty() {
		assertThatIllegalArgumentException().isThrownBy(() -> new RequestMatcherRedirectFilter(pathPattern("/**"), ""))
			.withMessage("redirectUrl cannot be empty");
	}

	@Test
	public void constructWhenRedirectUrlBlank() {
		assertThatIllegalArgumentException().isThrownBy(() -> new RequestMatcherRedirectFilter(pathPattern("/**"), " "))
			.withMessage("redirectUrl cannot be empty");
	}

}
