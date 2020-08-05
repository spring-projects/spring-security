/*
 * Copyright 2002-2016 the original author or authors.
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
package org.springframework.security.web.authentication;

import org.junit.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * <p>
 * Forward Authentication Failure Handler Tests
 * </p>
 *
 * @author Shazin Sadakath
 * @since 4.1
 */
public class ForwardAuthenticaionSuccessHandlerTests {

	@Test(expected = IllegalArgumentException.class)
	public void invalidForwardUrl() {
		new ForwardAuthenticationSuccessHandler("aaa");
	}

	@Test(expected = IllegalArgumentException.class)
	public void emptyForwardUrl() {
		new ForwardAuthenticationSuccessHandler("");
	}

	@Test
	public void responseIsForwarded() throws Exception {
		ForwardAuthenticationSuccessHandler fash = new ForwardAuthenticationSuccessHandler("/forwardUrl");

		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		Authentication authentication = mock(Authentication.class);

		fash.onAuthenticationSuccess(request, response, authentication);

		assertThat(response.getForwardedUrl()).isEqualTo("/forwardUrl");
	}

}
