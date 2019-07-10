/*
 * Copyright 2002-2018 the original author or authors.
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

package org.springframework.security.oauth2.server.resource.web.access;

import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AbstractOAuth2Token;
import org.springframework.security.oauth2.server.resource.authentication.AbstractOAuth2TokenAuthenticationToken;

import java.util.Collections;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

/**
 * Tests for {@link BearerTokenAccessDeniedHandlerTests}
 *
 * @author Josh Cummings
 */
public class BearerTokenAccessDeniedHandlerTests {
	private BearerTokenAccessDeniedHandler accessDeniedHandler;

	@Before
	public void setUp() {
		this.accessDeniedHandler = new BearerTokenAccessDeniedHandler();
	}

	@Test
	public void handleWhenNotOAuth2AuthenticatedThenStatus403()
			throws Exception {

		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();

		Authentication authentication = new TestingAuthenticationToken("user", "pass");
		request.setUserPrincipal(authentication);

		this.accessDeniedHandler.handle(request, response, null);

		assertThat(response.getStatus()).isEqualTo(403);
		assertThat(response.getHeader("WWW-Authenticate")).isEqualTo("Bearer");
	}

	@Test
	public void handleWhenNotOAuth2AuthenticatedAndRealmSetThenStatus403AndAuthHeaderWithRealm()
			throws Exception {

		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();

		Authentication authentication = new TestingAuthenticationToken("user", "pass");
		request.setUserPrincipal(authentication);

		this.accessDeniedHandler.setRealmName("test");
		this.accessDeniedHandler.handle(request, response, null);

		assertThat(response.getStatus()).isEqualTo(403);
		assertThat(response.getHeader("WWW-Authenticate")).isEqualTo("Bearer realm=\"test\"");
	}

	@Test
	public void handleWhenOAuth2AuthenticatedThenStatus403AndAuthHeaderWithInsufficientScopeErrorAttribute()
			throws Exception {

		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();

		Authentication token = new TestingOAuth2TokenAuthenticationToken(Collections.emptyMap());
		request.setUserPrincipal(token);

		this.accessDeniedHandler.handle(request, response, null);

		assertThat(response.getStatus()).isEqualTo(403);
		assertThat(response.getHeader("WWW-Authenticate")).isEqualTo("Bearer error=\"insufficient_scope\", " +
				"error_description=\"The request requires higher privileges than provided by the access token.\", " +
				"error_uri=\"https://tools.ietf.org/html/rfc6750#section-3.1\"");
	}

	@Test
	public void setRealmNameWhenNullRealmNameThenNoExceptionThrown() {
		assertThatCode(() -> this.accessDeniedHandler.setRealmName(null))
				.doesNotThrowAnyException();
	}

	static class TestingOAuth2TokenAuthenticationToken
			extends AbstractOAuth2TokenAuthenticationToken<TestingOAuth2TokenAuthenticationToken.TestingOAuth2Token> {

		private Map<String, Object> attributes;

		protected TestingOAuth2TokenAuthenticationToken(Map<String, Object> attributes) {
			super(new TestingOAuth2Token("token"));
			this.attributes = attributes;
		}

		@Override
		public Map<String, Object> getTokenAttributes() {
			return this.attributes;
		}

		static class TestingOAuth2Token extends AbstractOAuth2Token {
			public TestingOAuth2Token(String tokenValue) {
				super(tokenValue);
			}
		}
	}
}
