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
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.entry;

/**
 * Tests for {@link JwtClientAssertionAuthenticationConverter}.
 *
 * @author Rafal Lewczuk
 */
public class JwtClientAssertionAuthenticationConverterTests {

	private static final String JWT_BEARER_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

	private final JwtClientAssertionAuthenticationConverter converter = new JwtClientAssertionAuthenticationConverter();

	@Test
	public void convertWhenMissingClientAssertionTypeThenReturnNull() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addParameter(OAuth2ParameterNames.CLIENT_ASSERTION, "jwt-assertion");
		Authentication authentication = this.converter.convert(request);
		assertThat(authentication).isNull();
	}

	@Test
	public void convertWhenMissingClientAssertionThenReturnNull() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addParameter(OAuth2ParameterNames.CLIENT_ASSERTION_TYPE, JWT_BEARER_TYPE);
		Authentication authentication = this.converter.convert(request);
		assertThat(authentication).isNull();
	}

	@Test
	public void convertWhenMultipleClientAssertionTypeThenInvalidRequestError() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addParameter(OAuth2ParameterNames.CLIENT_ASSERTION_TYPE, JWT_BEARER_TYPE);
		request.addParameter(OAuth2ParameterNames.CLIENT_ASSERTION_TYPE, "other-client-assertion-type");
		request.addParameter(OAuth2ParameterNames.CLIENT_ASSERTION, "jwt-assertion");
		assertThrown(request, OAuth2ErrorCodes.INVALID_REQUEST);
	}

	@Test
	public void convertWhenNotJwtAssertionTypeThenReturnNull() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addParameter(OAuth2ParameterNames.CLIENT_ASSERTION_TYPE, "other-client-assertion-type");
		request.addParameter(OAuth2ParameterNames.CLIENT_ASSERTION, "other-assertion");
		Authentication authentication = this.converter.convert(request);
		assertThat(authentication).isNull();
	}

	@Test
	public void convertWhenMultipleClientAssertionThenInvalidRequestError() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addParameter(OAuth2ParameterNames.CLIENT_ASSERTION_TYPE, JWT_BEARER_TYPE);
		request.addParameter(OAuth2ParameterNames.CLIENT_ASSERTION, "jwt-assertion");
		request.addParameter(OAuth2ParameterNames.CLIENT_ASSERTION, "other-jwt-assertion");
		assertThrown(request, OAuth2ErrorCodes.INVALID_REQUEST);
	}

	@Test
	public void convertWhenMissingClientIdThenInvalidRequestError() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addParameter(OAuth2ParameterNames.CLIENT_ASSERTION_TYPE, JWT_BEARER_TYPE);
		request.addParameter(OAuth2ParameterNames.CLIENT_ASSERTION, "jwt-assertion");
		assertThrown(request, OAuth2ErrorCodes.INVALID_REQUEST);
	}

	@Test
	public void convertWhenMultipleClientIdThenInvalidRequestError() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addParameter(OAuth2ParameterNames.CLIENT_ASSERTION_TYPE, JWT_BEARER_TYPE);
		request.addParameter(OAuth2ParameterNames.CLIENT_ASSERTION, "jwt-assertion");
		request.addParameter(OAuth2ParameterNames.CLIENT_ID, "client-1");
		request.addParameter(OAuth2ParameterNames.CLIENT_ID, "client-2");
		assertThrown(request, OAuth2ErrorCodes.INVALID_REQUEST);
	}

	@Test
	public void convertWhenJwtAssertionThenReturnClientAuthenticationToken() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addParameter(OAuth2ParameterNames.CLIENT_ASSERTION_TYPE, JWT_BEARER_TYPE);
		request.addParameter(OAuth2ParameterNames.CLIENT_ASSERTION, "jwt-assertion");
		request.addParameter(OAuth2ParameterNames.CLIENT_ID, "client-1");
		request.addParameter(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.AUTHORIZATION_CODE.getValue());
		request.addParameter(OAuth2ParameterNames.CODE, "code");
		request.addParameter("custom-param-1", "custom-value-1");
		request.addParameter("custom-param-2", "custom-value-1", "custom-value-2");
		OAuth2ClientAuthenticationToken authentication = (OAuth2ClientAuthenticationToken) this.converter
			.convert(request);
		assertThat(authentication.getPrincipal()).isEqualTo("client-1");
		assertThat(authentication.getCredentials()).isEqualTo("jwt-assertion");
		assertThat(authentication.getClientAuthenticationMethod().getValue()).isEqualTo(JWT_BEARER_TYPE);
		assertThat(authentication.getAdditionalParameters()).containsOnly(
				entry(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.AUTHORIZATION_CODE.getValue()),
				entry(OAuth2ParameterNames.CODE, "code"), entry("custom-param-1", "custom-value-1"),
				entry("custom-param-2", new String[] { "custom-value-1", "custom-value-2" }));
	}

	private void assertThrown(MockHttpServletRequest request, String errorCode) {
		assertThatThrownBy(() -> this.converter.convert(request)).isInstanceOf(OAuth2AuthenticationException.class)
			.extracting((ex) -> ((OAuth2AuthenticationException) ex).getError())
			.extracting("errorCode")
			.isEqualTo(errorCode);
	}

}
