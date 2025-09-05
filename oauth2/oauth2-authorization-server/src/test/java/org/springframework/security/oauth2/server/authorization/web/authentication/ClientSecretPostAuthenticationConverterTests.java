/*
 * Copyright 2020-2023 the original author or authors.
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
package org.springframework.security.oauth2.server.authorization.web.authentication;

import org.junit.jupiter.api.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.entry;

/**
 * Tests for {@link ClientSecretPostAuthenticationConverter}.
 *
 * @author Anoop Garlapati
 */
public class ClientSecretPostAuthenticationConverterTests {

	private final ClientSecretPostAuthenticationConverter converter = new ClientSecretPostAuthenticationConverter();

	@Test
	public void convertWhenMissingClientIdThenReturnNull() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		Authentication authentication = this.converter.convert(request);
		assertThat(authentication).isNull();
	}

	@Test
	public void convertWhenMultipleClientIdsThenInvalidRequestError() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addParameter(OAuth2ParameterNames.CLIENT_ID, "client-1");
		request.addParameter(OAuth2ParameterNames.CLIENT_ID, "client-2");
		assertThatThrownBy(() -> this.converter.convert(request)).isInstanceOf(OAuth2AuthenticationException.class)
			.extracting((ex) -> ((OAuth2AuthenticationException) ex).getError())
			.extracting("errorCode")
			.isEqualTo(OAuth2ErrorCodes.INVALID_REQUEST);
	}

	@Test
	public void convertWhenMissingClientSecretThenReturnNull() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addParameter(OAuth2ParameterNames.CLIENT_ID, "client-1");
		Authentication authentication = this.converter.convert(request);
		assertThat(authentication).isNull();
	}

	@Test
	public void convertWhenMultipleClientSecretsThenInvalidRequestError() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addParameter(OAuth2ParameterNames.CLIENT_ID, "client-1");
		request.addParameter(OAuth2ParameterNames.CLIENT_SECRET, "client-secret-1");
		request.addParameter(OAuth2ParameterNames.CLIENT_SECRET, "client-secret-2");
		assertThatThrownBy(() -> this.converter.convert(request)).isInstanceOf(OAuth2AuthenticationException.class)
			.extracting((ex) -> ((OAuth2AuthenticationException) ex).getError())
			.extracting("errorCode")
			.isEqualTo(OAuth2ErrorCodes.INVALID_REQUEST);
	}

	@Test
	public void convertWhenPostWithValidCredentialsThenReturnClientAuthenticationToken() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addParameter(OAuth2ParameterNames.CLIENT_ID, "client-1");
		request.addParameter(OAuth2ParameterNames.CLIENT_SECRET, "client-secret");
		OAuth2ClientAuthenticationToken authentication = (OAuth2ClientAuthenticationToken) this.converter
			.convert(request);
		assertThat(authentication.getPrincipal()).isEqualTo("client-1");
		assertThat(authentication.getCredentials()).isEqualTo("client-secret");
		assertThat(authentication.getClientAuthenticationMethod())
			.isEqualTo(ClientAuthenticationMethod.CLIENT_SECRET_POST);
	}

	@Test
	public void convertWhenConfidentialClientWithPkceParametersThenAdditionalParametersIncluded() {
		MockHttpServletRequest request = createPkceTokenRequest();
		request.addParameter(OAuth2ParameterNames.CLIENT_ID, "client-1");
		request.addParameter(OAuth2ParameterNames.CLIENT_SECRET, "client-secret");
		request.addParameter("custom-param", "custom-value-1", "custom-value-2");
		OAuth2ClientAuthenticationToken authentication = (OAuth2ClientAuthenticationToken) this.converter
			.convert(request);
		assertThat(authentication.getPrincipal()).isEqualTo("client-1");
		assertThat(authentication.getCredentials()).isEqualTo("client-secret");
		assertThat(authentication.getClientAuthenticationMethod())
			.isEqualTo(ClientAuthenticationMethod.CLIENT_SECRET_POST);
		assertThat(authentication.getAdditionalParameters()).containsOnly(
				entry(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.AUTHORIZATION_CODE.getValue()),
				entry(OAuth2ParameterNames.CODE, "code"), entry(PkceParameterNames.CODE_VERIFIER, "code-verifier-1"),
				entry("custom-param", new String[] { "custom-value-1", "custom-value-2" }));
	}

	private static MockHttpServletRequest createPkceTokenRequest() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addParameter(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.AUTHORIZATION_CODE.getValue());
		request.addParameter(OAuth2ParameterNames.CODE, "code");
		request.addParameter(PkceParameterNames.CODE_VERIFIER, "code-verifier-1");
		return request;
	}

}
