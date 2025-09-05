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

import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.http.HttpMethod;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2DeviceCodeAuthenticationToken;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

/**
 * Tests for {@link OAuth2DeviceCodeAuthenticationConverter}.
 *
 * @author Steve Riesenberg
 */
public class OAuth2DeviceCodeAuthenticationConverterTests {

	private static final String CLIENT_ID = "client-1";

	private static final String TOKEN_URI = "/oauth2/token";

	private static final String DEVICE_CODE = "EfYu_0jEL";

	private OAuth2DeviceCodeAuthenticationConverter converter;

	@BeforeEach
	public void setUp() {
		this.converter = new OAuth2DeviceCodeAuthenticationConverter();
	}

	@AfterEach
	public void tearDown() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void convertWhenMissingGrantTypeThenReturnNull() {
		MockHttpServletRequest request = createRequest();
		Authentication authentication = this.converter.convert(request);
		assertThat(authentication).isNull();
	}

	@Test
	public void convertWhenMissingDeviceCodeThenInvalidRequestError() {
		MockHttpServletRequest request = createRequest();
		request.addParameter(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.DEVICE_CODE.getValue());
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> this.converter.convert(request))
				.withMessageContaining(OAuth2ParameterNames.DEVICE_CODE)
				.extracting(OAuth2AuthenticationException::getError)
				.extracting(OAuth2Error::getErrorCode)
				.isEqualTo(OAuth2ErrorCodes.INVALID_REQUEST);
		// @formatter:on
	}

	@Test
	public void convertWhenMultipleDeviceCodeParametersThenInvalidRequestError() {
		MockHttpServletRequest request = createRequest();
		request.addParameter(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.DEVICE_CODE.getValue());
		request.addParameter(OAuth2ParameterNames.DEVICE_CODE, DEVICE_CODE);
		request.addParameter(OAuth2ParameterNames.DEVICE_CODE, "another");
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> this.converter.convert(request))
				.withMessageContaining(OAuth2ParameterNames.DEVICE_CODE)
				.extracting(OAuth2AuthenticationException::getError)
				.extracting(OAuth2Error::getErrorCode)
				.isEqualTo(OAuth2ErrorCodes.INVALID_REQUEST);
		// @formatter:on
	}

	@Test
	public void convertWhenAllParametersThenReturnDeviceCodeAuthenticationToken() {
		MockHttpServletRequest request = createRequest();
		request.addParameter(OAuth2ParameterNames.CLIENT_ID, CLIENT_ID);
		request.addParameter(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.DEVICE_CODE.getValue());
		request.addParameter(OAuth2ParameterNames.DEVICE_CODE, DEVICE_CODE);
		request.addParameter("param-1", "value-1");
		request.addParameter("param-2", "value-1", "value-2");
		request.addHeader(OAuth2AccessToken.TokenType.DPOP.getValue(), "dpop-proof-jwt");

		SecurityContextImpl securityContext = new SecurityContextImpl();
		securityContext.setAuthentication(new TestingAuthenticationToken(CLIENT_ID, null));
		SecurityContextHolder.setContext(securityContext);

		OAuth2DeviceCodeAuthenticationToken authentication = (OAuth2DeviceCodeAuthenticationToken) this.converter
			.convert(request);
		assertThat(authentication).isNotNull();
		assertThat(authentication.getDeviceCode()).isEqualTo(DEVICE_CODE);
		assertThat(authentication.getPrincipal()).isInstanceOf(TestingAuthenticationToken.class);
		Map<String, Object> expectedAdditionalParameters = new HashMap<>();
		expectedAdditionalParameters.put("param-1", "value-1");
		expectedAdditionalParameters.put("param-2", new String[] { "value-1", "value-2" });
		expectedAdditionalParameters.put("dpop_proof", "dpop-proof-jwt");
		expectedAdditionalParameters.put("dpop_method", "POST");
		expectedAdditionalParameters.put("dpop_target_uri", "http://localhost/oauth2/token");
		assertThat(authentication.getAdditionalParameters())
			.containsExactlyInAnyOrderEntriesOf(expectedAdditionalParameters);
	}

	private static MockHttpServletRequest createRequest() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setMethod(HttpMethod.POST.name());
		request.setRequestURI(TOKEN_URI);
		return request;
	}

}
