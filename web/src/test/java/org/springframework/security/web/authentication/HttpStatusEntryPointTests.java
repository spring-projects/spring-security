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

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.Before;
import org.junit.Test;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.AuthenticationException;

/**
 *
 * @author Rob Winch
 * @since 4.0
 */
public class HttpStatusEntryPointTests {
	MockHttpServletRequest request;
	MockHttpServletResponse response;
	AuthenticationException authException;

	HttpStatusEntryPoint entryPoint;

	@SuppressWarnings("serial")
	@Before
	public void setup() {
		request = new MockHttpServletRequest();
		response = new MockHttpServletResponse();
		authException = new AuthenticationException("") {
		};
		entryPoint = new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED);
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorNullStatus() {
		new HttpStatusEntryPoint(null);
	}

	@Test
	public void unauthorized() throws Exception {
		entryPoint.commence(request, response, authException);

		assertThat(response.getStatus()).isEqualTo(HttpStatus.UNAUTHORIZED.value());
	}

}