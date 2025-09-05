/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.oauth2.server.authorization.oidc.web.authentication;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcLogoutAuthenticationToken;
import org.springframework.security.web.authentication.logout.LogoutHandler;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * Tests for {@link OidcLogoutAuthenticationSuccessHandler}.
 *
 * @author Joe Grandja
 */
public class OidcLogoutAuthenticationSuccessHandlerTests {

	private TestingAuthenticationToken principal;

	private final OidcLogoutAuthenticationSuccessHandler authenticationSuccessHandler = new OidcLogoutAuthenticationSuccessHandler();

	@BeforeEach
	public void setUp() {
		this.principal = new TestingAuthenticationToken("principal", "credentials");
		this.principal.setAuthenticated(true);
	}

	@Test
	public void setLogoutHandlerWhenNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatThrownBy(() -> this.authenticationSuccessHandler.setLogoutHandler(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("logoutHandler cannot be null");
		// @formatter:on
	}

	@Test
	public void onAuthenticationSuccessWhenInvalidAuthenticationTypeThenThrowOAuth2AuthenticationException() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();

		assertThatThrownBy(
				() -> this.authenticationSuccessHandler.onAuthenticationSuccess(request, response, this.principal))
			.isInstanceOf(OAuth2AuthenticationException.class)
			.extracting((ex) -> ((OAuth2AuthenticationException) ex).getError())
			.extracting("errorCode")
			.isEqualTo(OAuth2ErrorCodes.SERVER_ERROR);
	}

	@Test
	public void onAuthenticationSuccessWhenLogoutHandlerSetThenUsed() throws Exception {
		LogoutHandler logoutHandler = mock(LogoutHandler.class);
		this.authenticationSuccessHandler.setLogoutHandler(logoutHandler);

		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpSession session = (MockHttpSession) request.getSession(true);
		MockHttpServletResponse response = new MockHttpServletResponse();

		OidcLogoutAuthenticationToken authentication = new OidcLogoutAuthenticationToken("id-token", this.principal,
				session.getId(), null, null, null);
		this.authenticationSuccessHandler.onAuthenticationSuccess(request, response, authentication);

		verify(logoutHandler).logout(any(HttpServletRequest.class), any(HttpServletResponse.class),
				any(Authentication.class));
	}

}
