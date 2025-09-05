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

import java.util.Map;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.http.HttpMethod;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2DeviceAuthorizationRequestAuthenticationToken;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

/**
 * Tests for {@link OAuth2DeviceAuthorizationRequestAuthenticationConverter}.
 *
 * @author Steve Riesenberg
 */
public class OAuth2DeviceAuthorizationRequestAuthenticationConverterTests {

	private static final String AUTHORIZATION_URI = "/oauth2/device_authorization";

	private static final String CLIENT_ID = "client-1";

	private OAuth2DeviceAuthorizationRequestAuthenticationConverter converter;

	@BeforeEach
	public void setUp() {
		this.converter = new OAuth2DeviceAuthorizationRequestAuthenticationConverter();
	}

	@AfterEach
	public void tearDown() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void convertWhenMultipleScopeParametersThenInvalidRequestError() {
		MockHttpServletRequest request = createRequest();
		request.addParameter(OAuth2ParameterNames.CLIENT_ID, CLIENT_ID);
		request.addParameter(OAuth2ParameterNames.SCOPE, "message.read");
		request.addParameter(OAuth2ParameterNames.SCOPE, "message.write");
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> this.converter.convert(request))
				.withMessageContaining(OAuth2ParameterNames.SCOPE)
				.extracting(OAuth2AuthenticationException::getError)
				.extracting(OAuth2Error::getErrorCode)
				.isEqualTo(OAuth2ErrorCodes.INVALID_REQUEST);
		// @formatter:on
	}

	@Test
	public void convertWhenMissingScopeThenReturnDeviceAuthorizationRequestAuthenticationToken() {
		MockHttpServletRequest request = createRequest();
		request.addParameter(OAuth2ParameterNames.CLIENT_ID, CLIENT_ID);

		SecurityContextImpl securityContext = new SecurityContextImpl();
		securityContext.setAuthentication(new TestingAuthenticationToken(CLIENT_ID, null));
		SecurityContextHolder.setContext(securityContext);

		OAuth2DeviceAuthorizationRequestAuthenticationToken authentication = (OAuth2DeviceAuthorizationRequestAuthenticationToken) this.converter
			.convert(request);
		assertThat(authentication).isNotNull();
		assertThat(authentication.getPrincipal()).isInstanceOf(TestingAuthenticationToken.class);
		assertThat(authentication.getAuthorizationUri()).endsWith(AUTHORIZATION_URI);
		assertThat(authentication.getScopes()).isEmpty();
		assertThat(authentication.getAdditionalParameters()).isEmpty();
	}

	@Test
	public void convertWhenAllParametersThenReturnDeviceAuthorizationRequestAuthenticationToken() {
		MockHttpServletRequest request = createRequest();
		request.addParameter(OAuth2ParameterNames.CLIENT_ID, CLIENT_ID);
		request.addParameter(OAuth2ParameterNames.SCOPE, "message.read message.write");
		request.addParameter("param-1", "value-1");
		request.addParameter("param-2", "value-1", "value-2");

		SecurityContextImpl securityContext = new SecurityContextImpl();
		securityContext.setAuthentication(new TestingAuthenticationToken(CLIENT_ID, null));
		SecurityContextHolder.setContext(securityContext);

		OAuth2DeviceAuthorizationRequestAuthenticationToken authentication = (OAuth2DeviceAuthorizationRequestAuthenticationToken) this.converter
			.convert(request);
		assertThat(authentication).isNotNull();
		assertThat(authentication.getPrincipal()).isInstanceOf(TestingAuthenticationToken.class);
		assertThat(authentication.getAuthorizationUri()).endsWith(AUTHORIZATION_URI);
		assertThat(authentication.getScopes()).containsExactly("message.read", "message.write");
		assertThat(authentication.getAdditionalParameters()).containsExactly(Map.entry("param-1", "value-1"),
				Map.entry("param-2", new String[] { "value-1", "value-2" }));
	}

	private static MockHttpServletRequest createRequest() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setMethod(HttpMethod.POST.name());
		request.setRequestURI(AUTHORIZATION_URI);
		return request;
	}

}
