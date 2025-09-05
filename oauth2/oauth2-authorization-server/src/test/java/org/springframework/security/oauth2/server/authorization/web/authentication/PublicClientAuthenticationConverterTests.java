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
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.entry;

/**
 * Tests for {@link PublicClientAuthenticationConverter}.
 *
 * @author Joe Grandja
 */
public class PublicClientAuthenticationConverterTests {

	private PublicClientAuthenticationConverter converter = new PublicClientAuthenticationConverter();

	@Test
	public void convertWhenNotPublicClientThenReturnNull() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		Authentication authentication = this.converter.convert(request);
		assertThat(authentication).isNull();
	}

	@Test
	public void convertWhenMissingClientIdThenInvalidRequestError() {
		MockHttpServletRequest request = createPkceTokenRequest();
		request.removeParameter(OAuth2ParameterNames.CLIENT_ID);
		assertThatExceptionOfType(OAuth2AuthenticationException.class).isThrownBy(() -> this.converter.convert(request))
			.extracting(OAuth2AuthenticationException::getError)
			.extracting("errorCode")
			.isEqualTo(OAuth2ErrorCodes.INVALID_REQUEST);
	}

	@Test
	public void convertWhenMultipleClientIdThenInvalidRequestError() {
		MockHttpServletRequest request = createPkceTokenRequest();
		request.addParameter(OAuth2ParameterNames.CLIENT_ID, "client-2");
		assertThatExceptionOfType(OAuth2AuthenticationException.class).isThrownBy(() -> this.converter.convert(request))
			.extracting(OAuth2AuthenticationException::getError)
			.extracting("errorCode")
			.isEqualTo(OAuth2ErrorCodes.INVALID_REQUEST);
	}

	@Test
	public void convertWhenMultipleCodeVerifierThenInvalidRequestError() {
		MockHttpServletRequest request = createPkceTokenRequest();
		request.addParameter(PkceParameterNames.CODE_VERIFIER, "code-verifier-2");
		assertThatExceptionOfType(OAuth2AuthenticationException.class).isThrownBy(() -> this.converter.convert(request))
			.extracting(OAuth2AuthenticationException::getError)
			.extracting("errorCode")
			.isEqualTo(OAuth2ErrorCodes.INVALID_REQUEST);
	}

	@Test
	public void convertWhenPublicClientThenReturnClientAuthenticationToken() {
		MockHttpServletRequest request = createPkceTokenRequest();
		request.addParameter("custom-param-1", "custom-value-1");
		request.addParameter("custom-param-2", "custom-value-1", "custom-value-2");
		OAuth2ClientAuthenticationToken authentication = (OAuth2ClientAuthenticationToken) this.converter
			.convert(request);
		assertThat(authentication.getPrincipal()).isEqualTo("client-1");
		assertThat(authentication.getClientAuthenticationMethod()).isEqualTo(ClientAuthenticationMethod.NONE);
		assertThat(authentication.getAdditionalParameters()).containsOnly(
				entry(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.AUTHORIZATION_CODE.getValue()),
				entry(OAuth2ParameterNames.CODE, "code"), entry(PkceParameterNames.CODE_VERIFIER, "code-verifier-1"),
				entry("custom-param-1", "custom-value-1"),
				entry("custom-param-2", new String[] { "custom-value-1", "custom-value-2" }));
	}

	private static MockHttpServletRequest createPkceTokenRequest() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addParameter(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.AUTHORIZATION_CODE.getValue());
		request.addParameter(OAuth2ParameterNames.CODE, "code");
		request.addParameter(OAuth2ParameterNames.CLIENT_ID, "client-1");
		request.addParameter(PkceParameterNames.CODE_VERIFIER, "code-verifier-1");
		return request;
	}

}
