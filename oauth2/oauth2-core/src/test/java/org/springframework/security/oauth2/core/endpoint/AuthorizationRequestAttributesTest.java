/*
 * Copyright 2012-2017 the original author or authors.
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
package org.springframework.security.oauth2.core.endpoint;

import org.junit.Test;

import java.util.Collections;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

/**
 * Tests {@link AuthorizationRequestAttributes}
 *
 * @author Luander Ribeiro
 */
public class AuthorizationRequestAttributesTest {
	private static final String AUTHORIZE_URI = "http://authorize.uri/";
	private static final String CLIENT_ID = "client id";
	private static final String REDIRECT_URI = "http://redirect.uri/";
	private static final Set<String> SCOPES = Collections.singleton("scope");
	private static final String STATE = "xyz";

	@Test(expected = IllegalArgumentException.class)
	public void buildWhenAuthorizationUriIsNullThenThrowIllegalArgumentException() {
		AuthorizationRequestAttributes.withAuthorizationCode()
			.authorizeUri(null)
			.clientId(CLIENT_ID)
			.redirectUri(REDIRECT_URI)
			.scopes(SCOPES)
			.state(STATE)
			.build();
	}

	@Test(expected = IllegalArgumentException.class)
	public void buildWhenAuthorizeUriNotSetThenThrowIllegalArgumentException() {
		AuthorizationRequestAttributes.withAuthorizationCode()
			.clientId(CLIENT_ID)
			.redirectUri(REDIRECT_URI)
			.scopes(SCOPES)
			.state(STATE)
			.build();
	}

	@Test(expected = IllegalArgumentException.class)
	public void buildWhenClientIdIsNullThenThrowIllegalArgumentException() {
		AuthorizationRequestAttributes.withAuthorizationCode()
			.authorizeUri(AUTHORIZE_URI)
			.clientId(null)
			.redirectUri(REDIRECT_URI)
			.scopes(SCOPES)
			.state(STATE)
			.build();
	}

	@Test(expected = IllegalArgumentException.class)
	public void buildWhenClientIdNotSetThenThrowIllegalArgumentException() {
		AuthorizationRequestAttributes.withAuthorizationCode()
			.authorizeUri(AUTHORIZE_URI)
			.redirectUri(REDIRECT_URI)
			.scopes(SCOPES)
			.state(STATE)
			.build();
	}

	@Test
	public void buildWhenGetResponseTypeIsCalledThenReturnCode() {
		AuthorizationRequestAttributes attributes;
		attributes = AuthorizationRequestAttributes.withAuthorizationCode()
			.authorizeUri(AUTHORIZE_URI)
			.clientId(CLIENT_ID)
			.redirectUri(REDIRECT_URI)
			.scopes(SCOPES)
			.state(STATE)
			.build();

		assertThat(attributes.getResponseType()).isEqualTo(ResponseType.CODE);
	}

	@Test
	public void buildWhenRedirectUriIsNullThenDoesNotThrowAnyException() {
		assertThatCode(() -> AuthorizationRequestAttributes.withAuthorizationCode()
			.authorizeUri(AUTHORIZE_URI)
			.clientId(CLIENT_ID)
			.redirectUri(null)
			.scopes(SCOPES)
			.state(STATE)
			.build()).doesNotThrowAnyException();
	}

	@Test
	public void buildWhenRedirectUriNotSetThenDoesNotThrowAnyException() {
		assertThatCode(() -> AuthorizationRequestAttributes.withAuthorizationCode()
			.authorizeUri(AUTHORIZE_URI)
			.clientId(CLIENT_ID)
			.scopes(SCOPES)
			.state(STATE)
			.build()).doesNotThrowAnyException();
	}

	@Test
	public void buildWhenScopesIsNullThenDoesNotThrowAnyException() {
		assertThatCode(() -> AuthorizationRequestAttributes.withAuthorizationCode()
			.authorizeUri(AUTHORIZE_URI)
			.clientId(CLIENT_ID)
			.redirectUri(REDIRECT_URI)
			.scopes(null)
			.state(STATE)
			.build()).doesNotThrowAnyException();
	}

	@Test
	public void buildWhenScopesNotSetThenDoesNotThrowAnyException() {
		assertThatCode(() -> AuthorizationRequestAttributes.withAuthorizationCode()
			.authorizeUri(AUTHORIZE_URI)
			.clientId(CLIENT_ID)
			.redirectUri(REDIRECT_URI)
			.state(STATE)
			.build()).doesNotThrowAnyException();
	}

	@Test
	public void buildWhenStateIsNullThenDoesNotThrowAnyException() {
		assertThatCode(() -> AuthorizationRequestAttributes.withAuthorizationCode()
			.authorizeUri(AUTHORIZE_URI)
			.clientId(CLIENT_ID)
			.redirectUri(REDIRECT_URI)
			.scopes(SCOPES)
			.state(null)
			.build()).doesNotThrowAnyException();
	}

	@Test
	public void buildWhenStateNotSetThenDoesNotThrowAnyException() {
		assertThatCode(() -> AuthorizationRequestAttributes.withAuthorizationCode()
			.authorizeUri(AUTHORIZE_URI)
			.clientId(CLIENT_ID)
			.redirectUri(REDIRECT_URI)
			.scopes(SCOPES)
			.build()).doesNotThrowAnyException();
	}
}
