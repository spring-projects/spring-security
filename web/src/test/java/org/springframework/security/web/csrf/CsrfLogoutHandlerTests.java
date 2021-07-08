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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.TestingAuthenticationToken;

import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.Mockito.verify;

/**
 * @author Rob Winch
 * @since 3.2
 */
@ExtendWith(MockitoExtension.class)
public class CsrfLogoutHandlerTests {

	@Mock
	private CsrfTokenRepository csrfTokenRepository;

	private MockHttpServletRequest request;

	private MockHttpServletResponse response;

	private CsrfLogoutHandler handler;

	@BeforeEach
	public void setup() {
		this.request = new MockHttpServletRequest();
		this.response = new MockHttpServletResponse();
		this.handler = new CsrfLogoutHandler(this.csrfTokenRepository);
	}

	@Test
	public void constructorNullCsrfTokenRepository() {
		assertThatIllegalArgumentException().isThrownBy(() -> new CsrfLogoutHandler(null));
	}

	@Test
	public void logoutRemovesCsrfToken() {
		this.handler.logout(this.request, this.response,
				new TestingAuthenticationToken("user", "password", "ROLE_USER"));
		verify(this.csrfTokenRepository).saveToken(null, this.request, this.response);
	}

}
