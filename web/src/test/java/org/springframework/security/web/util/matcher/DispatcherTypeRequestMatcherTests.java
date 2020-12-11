/*
 * Copyright 2002-2020 the original author or authors.
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

import javax.servlet.DispatcherType;
import javax.servlet.http.HttpServletRequest;

import org.junit.Test;

import org.springframework.http.HttpMethod;
import org.springframework.mock.web.MockHttpServletRequest;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Nick McKinney
 */
public class DispatcherTypeRequestMatcherTests {

	@Test
	public void matches_dispatcher_type() {
		HttpServletRequest request = mockHttpServletRequest(DispatcherType.ERROR, HttpMethod.GET);
		DispatcherTypeRequestMatcher matcher = new DispatcherTypeRequestMatcher(DispatcherType.ERROR);

		assertThat(matcher.matches(request)).isTrue();
	}

	@Test
	public void matches_dispatcher_type_and_http_method() {
		HttpServletRequest request = mockHttpServletRequest(DispatcherType.ERROR, HttpMethod.GET);
		DispatcherTypeRequestMatcher matcher = new DispatcherTypeRequestMatcher(DispatcherType.ERROR, HttpMethod.GET);

		assertThat(matcher.matches(request)).isTrue();
	}

	@Test
	public void does_not_match_wrong_type() {
		HttpServletRequest request = mockHttpServletRequest(DispatcherType.FORWARD, HttpMethod.GET);
		DispatcherTypeRequestMatcher matcher = new DispatcherTypeRequestMatcher(DispatcherType.ERROR);

		assertThat(matcher.matches(request)).isFalse();
	}

	@Test
	public void does_not_match_with_wrong_http_method() {
		HttpServletRequest request = mockHttpServletRequest(DispatcherType.ERROR, HttpMethod.GET);
		DispatcherTypeRequestMatcher matcher = new DispatcherTypeRequestMatcher(DispatcherType.ERROR, HttpMethod.POST);

		assertThat(matcher.matches(request)).isFalse();
	}

	@Test
	public void null_http_method_matches_any_http_method() {
		HttpServletRequest request = mockHttpServletRequest(DispatcherType.ERROR, HttpMethod.POST);
		DispatcherTypeRequestMatcher matcher = new DispatcherTypeRequestMatcher(DispatcherType.ERROR, null);

		assertThat(matcher.matches(request)).isTrue();
	}

	private HttpServletRequest mockHttpServletRequest(DispatcherType dispatcherType, HttpMethod httpMethod) {
		MockHttpServletRequest mockHttpServletRequest = new MockHttpServletRequest();
		mockHttpServletRequest.setDispatcherType(dispatcherType);
		mockHttpServletRequest.setMethod(httpMethod.name());
		return mockHttpServletRequest;
	}

}
