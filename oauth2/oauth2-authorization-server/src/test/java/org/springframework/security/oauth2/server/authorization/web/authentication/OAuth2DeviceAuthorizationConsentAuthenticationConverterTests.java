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

import java.util.Map;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.http.HttpMethod;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2DeviceAuthorizationConsentAuthenticationToken;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

/**
 * Tests for {@link OAuth2DeviceAuthorizationConsentAuthenticationConverter}.
 *
 * @author Steve Riesenberg
 */
public class OAuth2DeviceAuthorizationConsentAuthenticationConverterTests {

	private static final String VERIFICATION_URI = "/oauth2/device_verification";

	private static final String USER_CODE = "BCDF-GHJK";

	private static final String CLIENT_ID = "client-1";

	private static final String STATE = "abc123";

	private OAuth2DeviceAuthorizationConsentAuthenticationConverter converter;

	@BeforeEach
	public void setUp() {
		this.converter = new OAuth2DeviceAuthorizationConsentAuthenticationConverter();
	}

	@AfterEach
	public void tearDown() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void convertWhenGetThenReturnNull() {
		MockHttpServletRequest request = createRequest();
		request.setMethod(HttpMethod.GET.name());
		assertThat(this.converter.convert(request)).isNull();
	}

	@Test
	public void convertWhenMissingStateThenReturnNull() {
		MockHttpServletRequest request = createRequest();
		assertThat(this.converter.convert(request)).isNull();
	}

	@Test
	public void convertWhenMissingClientIdThenInvalidRequestError() {
		MockHttpServletRequest request = createRequest();
		request.addParameter(OAuth2ParameterNames.STATE, STATE);
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> this.converter.convert(request))
				.withMessageContaining(OAuth2ParameterNames.CLIENT_ID)
				.extracting(OAuth2AuthenticationException::getError)
				.extracting(OAuth2Error::getErrorCode)
				.isEqualTo(OAuth2ErrorCodes.INVALID_REQUEST);
		// @formatter:on
	}

	@Test
	public void convertWhenEmptyClientIdThenInvalidRequestError() {
		MockHttpServletRequest request = createRequest();
		request.addParameter(OAuth2ParameterNames.STATE, STATE);
		request.addParameter(OAuth2ParameterNames.CLIENT_ID, "");
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> this.converter.convert(request))
				.withMessageContaining(OAuth2ParameterNames.CLIENT_ID)
				.extracting(OAuth2AuthenticationException::getError)
				.extracting(OAuth2Error::getErrorCode)
				.isEqualTo(OAuth2ErrorCodes.INVALID_REQUEST);
		// @formatter:on
	}

	@Test
	public void convertWhenMultipleClientIdParametersThenInvalidRequestError() {
		MockHttpServletRequest request = createRequest();
		request.addParameter(OAuth2ParameterNames.STATE, STATE);
		request.addParameter(OAuth2ParameterNames.CLIENT_ID, CLIENT_ID);
		request.addParameter(OAuth2ParameterNames.CLIENT_ID, "another");
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> this.converter.convert(request))
				.withMessageContaining(OAuth2ParameterNames.CLIENT_ID)
				.extracting(OAuth2AuthenticationException::getError)
				.extracting(OAuth2Error::getErrorCode)
				.isEqualTo(OAuth2ErrorCodes.INVALID_REQUEST);
		// @formatter:on
	}

	@Test
	public void convertWhenMissingUserCodeThenInvalidRequestError() {
		MockHttpServletRequest request = createRequest();
		request.addParameter(OAuth2ParameterNames.STATE, STATE);
		request.addParameter(OAuth2ParameterNames.CLIENT_ID, CLIENT_ID);
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> this.converter.convert(request))
				.withMessageContaining(OAuth2ParameterNames.USER_CODE)
				.extracting(OAuth2AuthenticationException::getError)
				.extracting(OAuth2Error::getErrorCode)
				.isEqualTo(OAuth2ErrorCodes.INVALID_REQUEST);
		// @formatter:on
	}

	@Test
	public void convertWhenEmptyUserCodeThenInvalidRequestError() {
		MockHttpServletRequest request = createRequest();
		request.addParameter(OAuth2ParameterNames.STATE, STATE);
		request.addParameter(OAuth2ParameterNames.CLIENT_ID, CLIENT_ID);
		request.addParameter(OAuth2ParameterNames.USER_CODE, "");
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> this.converter.convert(request))
				.withMessageContaining(OAuth2ParameterNames.USER_CODE)
				.extracting(OAuth2AuthenticationException::getError)
				.extracting(OAuth2Error::getErrorCode)
				.isEqualTo(OAuth2ErrorCodes.INVALID_REQUEST);
		// @formatter:on
	}

	@Test
	public void convertWhenInvalidUserCodeThenInvalidRequestError() {
		MockHttpServletRequest request = createRequest();
		request.addParameter(OAuth2ParameterNames.STATE, STATE);
		request.addParameter(OAuth2ParameterNames.CLIENT_ID, CLIENT_ID);
		request.addParameter(OAuth2ParameterNames.USER_CODE, "LONG-USER-CODE");
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> this.converter.convert(request))
				.withMessageContaining(OAuth2ParameterNames.USER_CODE)
				.extracting(OAuth2AuthenticationException::getError)
				.extracting(OAuth2Error::getErrorCode)
				.isEqualTo(OAuth2ErrorCodes.INVALID_REQUEST);
		// @formatter:on
	}

	@Test
	public void convertWhenMultipleUserCodeParametersThenInvalidRequestError() {
		MockHttpServletRequest request = createRequest();
		request.addParameter(OAuth2ParameterNames.STATE, STATE);
		request.addParameter(OAuth2ParameterNames.CLIENT_ID, CLIENT_ID);
		request.addParameter(OAuth2ParameterNames.USER_CODE, USER_CODE);
		request.addParameter(OAuth2ParameterNames.USER_CODE, "another");
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> this.converter.convert(request))
				.withMessageContaining(OAuth2ParameterNames.USER_CODE)
				.extracting(OAuth2AuthenticationException::getError)
				.extracting(OAuth2Error::getErrorCode)
				.isEqualTo(OAuth2ErrorCodes.INVALID_REQUEST);
		// @formatter:on
	}

	@Test
	public void convertWhenEmptyStateParameterThenInvalidRequestError() {
		MockHttpServletRequest request = createRequest();
		request.addParameter(OAuth2ParameterNames.STATE, "");
		request.addParameter(OAuth2ParameterNames.CLIENT_ID, CLIENT_ID);
		request.addParameter(OAuth2ParameterNames.USER_CODE, USER_CODE);
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> this.converter.convert(request))
				.withMessageContaining(OAuth2ParameterNames.STATE)
				.extracting(OAuth2AuthenticationException::getError)
				.extracting(OAuth2Error::getErrorCode)
				.isEqualTo(OAuth2ErrorCodes.INVALID_REQUEST);
		// @formatter:on
	}

	@Test
	public void convertWhenMultipleStateParametersThenInvalidRequestError() {
		MockHttpServletRequest request = createRequest();
		request.addParameter(OAuth2ParameterNames.STATE, STATE);
		request.addParameter(OAuth2ParameterNames.STATE, "another");
		request.addParameter(OAuth2ParameterNames.CLIENT_ID, CLIENT_ID);
		request.addParameter(OAuth2ParameterNames.USER_CODE, USER_CODE);
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> this.converter.convert(request))
				.withMessageContaining(OAuth2ParameterNames.STATE)
				.extracting(OAuth2AuthenticationException::getError)
				.extracting(OAuth2Error::getErrorCode)
				.isEqualTo(OAuth2ErrorCodes.INVALID_REQUEST);
		// @formatter:on
	}

	@Test
	public void convertWhenMissingPrincipalThenReturnDeviceAuthorizationConsentAuthentication() {
		MockHttpServletRequest request = createRequest();
		request.addParameter(OAuth2ParameterNames.STATE, STATE);
		request.addParameter(OAuth2ParameterNames.CLIENT_ID, CLIENT_ID);
		request.addParameter(OAuth2ParameterNames.USER_CODE, USER_CODE);

		OAuth2DeviceAuthorizationConsentAuthenticationToken authentication = (OAuth2DeviceAuthorizationConsentAuthenticationToken) this.converter
			.convert(request);
		assertThat(authentication).isNotNull();
		assertThat(authentication.getAuthorizationUri()).endsWith(VERIFICATION_URI);
		assertThat(authentication.getClientId()).isEqualTo(CLIENT_ID);
		assertThat(authentication.getPrincipal()).isInstanceOf(AnonymousAuthenticationToken.class);
		assertThat(authentication.getUserCode()).isEqualTo(USER_CODE);
		assertThat(authentication.getScopes()).isEmpty();
		assertThat(authentication.getAdditionalParameters()).isEmpty();
	}

	@Test
	public void convertWhenMissingScopeThenReturnDeviceAuthorizationConsentAuthentication() {
		MockHttpServletRequest request = createRequest();
		request.addParameter(OAuth2ParameterNames.STATE, STATE);
		request.addParameter(OAuth2ParameterNames.CLIENT_ID, CLIENT_ID);
		request.addParameter(OAuth2ParameterNames.USER_CODE, USER_CODE);

		SecurityContextImpl securityContext = new SecurityContextImpl();
		securityContext.setAuthentication(new TestingAuthenticationToken("user", null));
		SecurityContextHolder.setContext(securityContext);

		OAuth2DeviceAuthorizationConsentAuthenticationToken authentication = (OAuth2DeviceAuthorizationConsentAuthenticationToken) this.converter
			.convert(request);
		assertThat(authentication).isNotNull();
		assertThat(authentication.getAuthorizationUri()).endsWith(VERIFICATION_URI);
		assertThat(authentication.getClientId()).isEqualTo(CLIENT_ID);
		assertThat(authentication.getPrincipal()).isInstanceOf(TestingAuthenticationToken.class);
		assertThat(authentication.getUserCode()).isEqualTo(USER_CODE);
		assertThat(authentication.getScopes()).isEmpty();
		assertThat(authentication.getAdditionalParameters()).isEmpty();
	}

	@Test
	public void convertWhenAllParametersThenReturnDeviceAuthorizationConsentAuthentication() {
		MockHttpServletRequest request = createRequest();
		request.addParameter(OAuth2ParameterNames.CLIENT_ID, CLIENT_ID);
		request.addParameter(OAuth2ParameterNames.STATE, STATE);
		request.addParameter(OAuth2ParameterNames.USER_CODE, USER_CODE);
		request.addParameter(OAuth2ParameterNames.SCOPE, "message.read");
		request.addParameter(OAuth2ParameterNames.SCOPE, "message.write");
		request.addParameter("param-1", "value-1");
		request.addParameter("param-2", "value-1", "value-2");

		SecurityContextImpl securityContext = new SecurityContextImpl();
		securityContext.setAuthentication(new TestingAuthenticationToken("user", null));
		SecurityContextHolder.setContext(securityContext);

		OAuth2DeviceAuthorizationConsentAuthenticationToken authentication = (OAuth2DeviceAuthorizationConsentAuthenticationToken) this.converter
			.convert(request);
		assertThat(authentication).isNotNull();
		assertThat(authentication.getAuthorizationUri()).endsWith(VERIFICATION_URI);
		assertThat(authentication.getClientId()).isEqualTo(CLIENT_ID);
		assertThat(authentication.getPrincipal()).isInstanceOf(TestingAuthenticationToken.class);
		assertThat(authentication.getUserCode()).isEqualTo(USER_CODE);
		assertThat(authentication.getScopes()).containsExactly("message.read", "message.write");
		assertThat(authentication.getAdditionalParameters()).containsExactly(Map.entry("param-1", "value-1"),
				Map.entry("param-2", new String[] { "value-1", "value-2" }));
	}

	@Test
	public void convertWhenNonNormalizedUserCodeThenReturnDeviceAuthorizationConsentAuthentication() {
		MockHttpServletRequest request = createRequest();
		request.addParameter(OAuth2ParameterNames.CLIENT_ID, CLIENT_ID);
		request.addParameter(OAuth2ParameterNames.STATE, STATE);
		request.addParameter(OAuth2ParameterNames.USER_CODE, USER_CODE.toLowerCase().replace("-", " . "));

		SecurityContextImpl securityContext = new SecurityContextImpl();
		securityContext.setAuthentication(new TestingAuthenticationToken("user", null));
		SecurityContextHolder.setContext(securityContext);

		OAuth2DeviceAuthorizationConsentAuthenticationToken authentication = (OAuth2DeviceAuthorizationConsentAuthenticationToken) this.converter
			.convert(request);
		assertThat(authentication).isNotNull();
		assertThat(authentication.getAuthorizationUri()).endsWith(VERIFICATION_URI);
		assertThat(authentication.getClientId()).isEqualTo(CLIENT_ID);
		assertThat(authentication.getPrincipal()).isInstanceOf(TestingAuthenticationToken.class);
		assertThat(authentication.getUserCode()).isEqualTo(USER_CODE);
		assertThat(authentication.getScopes()).isEmpty();
		assertThat(authentication.getAdditionalParameters()).isEmpty();
	}

	private static MockHttpServletRequest createRequest() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setMethod(HttpMethod.POST.name());
		request.setRequestURI(VERIFICATION_URI);
		return request;
	}

}
