/*
 * Copyright 2002-2013 the original author or authors.
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
package org.springframework.security.web.csrf;

import static org.mockito.Mockito.verify;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.TestingAuthenticationToken;

/**
 * @author Rob Winch
 * @since 3.2
 */
@RunWith(MockitoJUnitRunner.class)
public class CsrfLogoutHandlerTests {

	@Mock
	private CsrfTokenRepository csrfTokenRepository;

	private MockHttpServletRequest request;

	private MockHttpServletResponse response;

	private CsrfLogoutHandler handler;

	@Before
	public void setup() {
		request = new MockHttpServletRequest();
		response = new MockHttpServletResponse();
		handler = new CsrfLogoutHandler(csrfTokenRepository);
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorNullCsrfTokenRepository() {
		new CsrfLogoutHandler(null);
	}

	@Test
	public void logoutRemovesCsrfToken() {
		handler.logout(request, response, new TestingAuthenticationToken("user", "password", "ROLE_USER"));

		verify(csrfTokenRepository).saveToken(null, request, response);
	}

}
