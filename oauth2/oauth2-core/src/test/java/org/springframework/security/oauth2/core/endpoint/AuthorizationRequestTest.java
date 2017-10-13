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
 * Tests {@link AuthorizationRequest}
 *
 * @author Luander Ribeiro
 */
public class AuthorizationRequestTest {
	private static final String AUTHORIZE_URI = "http://authorize.uri/";
	private static final String CLIENT_ID = "client id";
	private static final String REDIRECT_URI = "http://redirect.uri/";
	private static final Set<String> SCOPE = Collections.singleton("scope");
	private static final String STATE = "xyz";
	private static final String NONCE = "1234-456-0393";

	@Test(expected = IllegalArgumentException.class)
	public void buildWhenAuthorizationUriIsNullThenThrowIllegalArgumentException() {
		AuthorizationRequest.authorizationCode()
			.authorizationUri(null)
			.clientId(CLIENT_ID)
			.redirectUri(REDIRECT_URI)
			.scope(SCOPE)
			.state(STATE)
			.nonce(NONCE)
			.build();
	}

	@Test(expected = IllegalArgumentException.class)
	public void buildWhenAuthorizeUriNotSetThenThrowIllegalArgumentException() {
		AuthorizationRequest.authorizationCode()
			.clientId(CLIENT_ID)
			.redirectUri(REDIRECT_URI)
			.scope(SCOPE)
			.state(STATE)
			.nonce(NONCE)
			.build();
	}

	@Test(expected = IllegalArgumentException.class)
	public void buildWhenClientIdIsNullThenThrowIllegalArgumentException() {
		AuthorizationRequest.authorizationCode()
			.authorizationUri(AUTHORIZE_URI)
			.clientId(null)
			.redirectUri(REDIRECT_URI)
			.scope(SCOPE)
			.state(STATE)
			.nonce(NONCE)
			.build();
	}

	@Test(expected = IllegalArgumentException.class)
	public void buildWhenClientIdNotSetThenThrowIllegalArgumentException() {
		AuthorizationRequest.authorizationCode()
			.authorizationUri(AUTHORIZE_URI)
			.redirectUri(REDIRECT_URI)
			.scope(SCOPE)
			.state(STATE)
			.nonce(NONCE)
			.build();
	}

	@Test
	public void buildWhenGetResponseTypeIsCalledThenReturnCode() {
		AuthorizationRequest authorizationRequest;
		authorizationRequest = AuthorizationRequest.authorizationCode()
			.authorizationUri(AUTHORIZE_URI)
			.clientId(CLIENT_ID)
			.redirectUri(REDIRECT_URI)
			.scope(SCOPE)
			.state(STATE)
			.nonce(NONCE)
			.build();

		assertThat(authorizationRequest.getResponseType()).isEqualTo(ResponseType.CODE);
	}

	@Test
	public void buildWhenRedirectUriIsNullThenDoesNotThrowAnyException() {
		assertThatCode(() -> AuthorizationRequest.authorizationCode()
			.authorizationUri(AUTHORIZE_URI)
			.clientId(CLIENT_ID)
			.redirectUri(null)
			.scope(SCOPE)
			.state(STATE)
			.nonce(NONCE)
			.build()).doesNotThrowAnyException();
	}

	@Test
	public void buildWhenRedirectUriNotSetThenDoesNotThrowAnyException() {
		assertThatCode(() -> AuthorizationRequest.authorizationCode()
			.authorizationUri(AUTHORIZE_URI)
			.clientId(CLIENT_ID)
			.scope(SCOPE)
			.state(STATE)
			.nonce(NONCE)
			.build()).doesNotThrowAnyException();
	}

	@Test
	public void buildWhenScopesIsNullThenDoesNotThrowAnyException() {
		assertThatCode(() -> AuthorizationRequest.authorizationCode()
			.authorizationUri(AUTHORIZE_URI)
			.clientId(CLIENT_ID)
			.redirectUri(REDIRECT_URI)
			.scope(null)
			.state(STATE)
			.nonce(NONCE)
			.build()).doesNotThrowAnyException();
	}

	@Test
	public void buildWhenScopesNotSetThenDoesNotThrowAnyException() {
		assertThatCode(() -> AuthorizationRequest.authorizationCode()
			.authorizationUri(AUTHORIZE_URI)
			.clientId(CLIENT_ID)
			.redirectUri(REDIRECT_URI)
			.state(STATE)
			.nonce(NONCE)
			.build()).doesNotThrowAnyException();
	}

	@Test
	public void buildWhenStateIsNullThenDoesNotThrowAnyException() {
		assertThatCode(() -> AuthorizationRequest.authorizationCode()
			.authorizationUri(AUTHORIZE_URI)
			.clientId(CLIENT_ID)
			.redirectUri(REDIRECT_URI)
			.scope(SCOPE)
			.state(null)
			.nonce(NONCE)
			.build()).doesNotThrowAnyException();
	}

	@Test
	public void buildWhenNonceIsNullThenDoesNotThrowAnyException() {
		assertThatCode(() -> AuthorizationRequest.authorizationCode()
			.authorizationUri(AUTHORIZE_URI)
			.clientId(CLIENT_ID)
			.redirectUri(REDIRECT_URI)
			.scope(SCOPE)
			.state(STATE)
			.nonce(null)
			.build()).doesNotThrowAnyException();
	}

	@Test
	public void buildWhenStateNotSetThenDoesNotThrowAnyException() {
		assertThatCode(() -> AuthorizationRequest.authorizationCode()
			.authorizationUri(AUTHORIZE_URI)
			.clientId(CLIENT_ID)
			.redirectUri(REDIRECT_URI)
			.scope(SCOPE)
			.nonce(NONCE)
			.build()).doesNotThrowAnyException();
	}
}
