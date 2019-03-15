/*
 * Copyright 2002-2017 the original author or authors.
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
package org.springframework.security.oauth2.core.endpoint;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

/**
 * Tests for {@link OAuth2AuthorizationRequest}.
 *
 * @author Luander Ribeiro
 * @author Joe Grandja
 */
@RunWith(PowerMockRunner.class)
@PrepareForTest(OAuth2AuthorizationRequest.class)
public class OAuth2AuthorizationRequestTests {
	private static final String AUTHORIZATION_URI = "https://provider.com/oauth2/authorize";
	private static final String CLIENT_ID = "client-id";
	private static final String REDIRECT_URI = "http://example.com";
	private static final Set<String> SCOPES = new LinkedHashSet<>(Arrays.asList("scope1", "scope2"));
	private static final String STATE = "state";

	@Test(expected = IllegalArgumentException.class)
	public void buildWhenAuthorizationUriIsNullThenThrowIllegalArgumentException() {
		OAuth2AuthorizationRequest.authorizationCode()
			.authorizationUri(null)
			.clientId(CLIENT_ID)
			.redirectUri(REDIRECT_URI)
			.scopes(SCOPES)
			.state(STATE)
			.build();
	}

	@Test(expected = IllegalArgumentException.class)
	public void buildWhenClientIdIsNullThenThrowIllegalArgumentException() {
		OAuth2AuthorizationRequest.authorizationCode()
			.authorizationUri(AUTHORIZATION_URI)
			.clientId(null)
			.redirectUri(REDIRECT_URI)
			.scopes(SCOPES)
			.state(STATE)
			.build();
	}

	@Test(expected = IllegalArgumentException.class)
	public void buildWhenRedirectUriIsNullForImplicitThenThrowIllegalArgumentException() {
		OAuth2AuthorizationRequest.implicit()
			.authorizationUri(AUTHORIZATION_URI)
			.clientId(CLIENT_ID)
			.redirectUri(null)
			.scopes(SCOPES)
			.state(STATE)
			.build();
	}

	@Test
	public void buildWhenRedirectUriIsNullForAuthorizationCodeThenDoesNotThrowAnyException() {
		assertThatCode(() -> OAuth2AuthorizationRequest.authorizationCode()
			.authorizationUri(AUTHORIZATION_URI)
			.clientId(CLIENT_ID)
			.redirectUri(null)
			.scopes(SCOPES)
			.state(STATE)
			.build()).doesNotThrowAnyException();
	}

	@Test
	public void buildWhenImplicitThenGrantTypeResponseTypeIsSet() {
		OAuth2AuthorizationRequest authorizationRequest = OAuth2AuthorizationRequest.implicit()
			.authorizationUri(AUTHORIZATION_URI)
			.clientId(CLIENT_ID)
			.redirectUri(REDIRECT_URI)
			.scopes(SCOPES)
			.state(STATE)
			.build();
		assertThat(authorizationRequest.getGrantType()).isEqualTo(AuthorizationGrantType.IMPLICIT);
		assertThat(authorizationRequest.getResponseType()).isEqualTo(OAuth2AuthorizationResponseType.TOKEN);
	}

	@Test
	public void buildWhenAuthorizationCodeThenGrantTypeResponseTypeIsSet() {
		OAuth2AuthorizationRequest authorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
			.authorizationUri(AUTHORIZATION_URI)
			.clientId(CLIENT_ID)
			.redirectUri(null)
			.scopes(SCOPES)
			.state(STATE)
			.build();
		assertThat(authorizationRequest.getGrantType()).isEqualTo(AuthorizationGrantType.AUTHORIZATION_CODE);
		assertThat(authorizationRequest.getResponseType()).isEqualTo(OAuth2AuthorizationResponseType.CODE);
	}

	@Test
	public void buildWhenAllAttributesProvidedThenAllAttributesAreSet() {
		Map<String, Object> additionalParameters = new HashMap<>();
		additionalParameters.put("param1", "value1");
		additionalParameters.put("param2", "value2");

		OAuth2AuthorizationRequest authorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
			.authorizationUri(AUTHORIZATION_URI)
			.clientId(CLIENT_ID)
			.redirectUri(REDIRECT_URI)
			.scopes(SCOPES)
			.state(STATE)
			.additionalParameters(additionalParameters)
			.build();

		assertThat(authorizationRequest.getAuthorizationUri()).isEqualTo(AUTHORIZATION_URI);
		assertThat(authorizationRequest.getGrantType()).isEqualTo(AuthorizationGrantType.AUTHORIZATION_CODE);
		assertThat(authorizationRequest.getResponseType()).isEqualTo(OAuth2AuthorizationResponseType.CODE);
		assertThat(authorizationRequest.getClientId()).isEqualTo(CLIENT_ID);
		assertThat(authorizationRequest.getRedirectUri()).isEqualTo(REDIRECT_URI);
		assertThat(authorizationRequest.getScopes()).isEqualTo(SCOPES);
		assertThat(authorizationRequest.getState()).isEqualTo(STATE);
		assertThat(authorizationRequest.getAdditionalParameters()).isEqualTo(additionalParameters);
	}

	@Test
	public void buildWhenScopesIsNullThenDoesNotThrowAnyException() {
		assertThatCode(() -> OAuth2AuthorizationRequest.authorizationCode()
			.authorizationUri(AUTHORIZATION_URI)
			.clientId(CLIENT_ID)
			.redirectUri(REDIRECT_URI)
			.scopes(null)
			.state(STATE)
			.build()).doesNotThrowAnyException();
	}

	@Test
	public void buildWhenStateIsNullThenDoesNotThrowAnyException() {
		assertThatCode(() -> OAuth2AuthorizationRequest.authorizationCode()
			.authorizationUri(AUTHORIZATION_URI)
			.clientId(CLIENT_ID)
			.redirectUri(REDIRECT_URI)
			.scopes(SCOPES)
			.state(null)
			.build()).doesNotThrowAnyException();
	}

	@Test
	public void buildWhenAdditionalParametersIsNullThenDoesNotThrowAnyException() {
		assertThatCode(() -> OAuth2AuthorizationRequest.authorizationCode()
			.authorizationUri(AUTHORIZATION_URI)
			.clientId(CLIENT_ID)
			.redirectUri(REDIRECT_URI)
			.scopes(SCOPES)
			.state(STATE)
			.additionalParameters(null)
			.build()).doesNotThrowAnyException();
	}
}
