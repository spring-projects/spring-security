/*
 * Copyright 2002-2016 the original author or authors.
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
package org.springframework.security.web.util.matcher;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.mock.web.MockHttpServletRequest;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * JavascriptOriginRequestMatcher Tests
 *
 * @author Shazin Sadakath
 */
@RunWith(MockitoJUnitRunner.class)
public class JavascriptOriginRequestMatcherTests {

	private RequestMatcher matcher = new JavascriptOriginRequestMatcher();

	@Test
	public void javascriptOriginRequest() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addHeader(JavascriptOriginRequestMatcher.HTTP_X_REQUESTED_WITH, "XMLHttpRequest");

		assertThat(matcher.matches(request)).isTrue();
	}

	@Test
	public void nonJavascriptOriginRequest_EmptyHeader() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addHeader(JavascriptOriginRequestMatcher.HTTP_X_REQUESTED_WITH, "");

		assertThat(matcher.matches(request)).isFalse();
	}

	@Test
	public void nonJavascriptOriginRequest_NotSetHeader() {
		MockHttpServletRequest request = new MockHttpServletRequest();

		assertThat(matcher.matches(request)).isFalse();
	}

}
