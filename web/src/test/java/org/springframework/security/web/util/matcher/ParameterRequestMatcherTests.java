/*
 * Copyright 2002-2024 the original author or authors.
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

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import org.springframework.mock.web.MockHttpServletRequest;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link ParameterRequestMatcher}
 *
 * @author Josh Cummings
 */
@ExtendWith(MockitoExtension.class)
public class ParameterRequestMatcherTests {

	@Test
	public void matchesWhenNameThenMatchesOnParameterName() {
		ParameterRequestMatcher matcher = new ParameterRequestMatcher("name");
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/foo/bar");
		assertThat(matcher.matches(request)).isFalse();
		request.setParameter("name", "value");
		assertThat(matcher.matches(request)).isTrue();
	}

	@Test
	public void matchesWhenNameAndValueThenMatchesOnBoth() {
		ParameterRequestMatcher matcher = new ParameterRequestMatcher("name", "value");
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/foo/bar");
		request.setParameter("name", "value");
		assertThat(matcher.matches(request)).isTrue();
		request.setParameter("name", "wrong");
		assertThat(matcher.matches(request)).isFalse();
	}

	@Test
	public void matchesWhenValuePlaceholderThenMatchesOnName() {
		ParameterRequestMatcher matcher = new ParameterRequestMatcher("name", "{placeholder}");
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/foo/bar");
		request.setParameter("name", "value");
		RequestMatcher.MatchResult result = matcher.matcher(request);
		assertThat(result.isMatch()).isTrue();
		assertThat(result.getVariables().get("placeholder")).isEqualTo("value");
	}

}
