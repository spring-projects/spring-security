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
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2DeviceVerificationAuthenticationToken;
import org.springframework.web.util.UriComponentsBuilder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

/**
 * Tests for {@link OAuth2DeviceVerificationAuthenticationConverter}.
 *
 * @author Steve Riesenberg
 */
public class OAuth2DeviceVerificationAuthenticationConverterTests {

	private static final String VERIFICATION_URI = "/oauth2/device_verification";

	private static final String USER_CODE = "BCDF-GHJK";

	private OAuth2DeviceVerificationAuthenticationConverter converter;

	@BeforeEach
	public void setUp() {
		this.converter = new OAuth2DeviceVerificationAuthenticationConverter();
	}

	@AfterEach
	public void tearDown() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void convertWhenPutThenReturnNull() {
		MockHttpServletRequest request = createRequest();
		request.setMethod(HttpMethod.PUT.name());
		Authentication authentication = this.converter.convert(request);
		assertThat(authentication).isNull();
	}

	@Test
	public void convertWhenStateThenReturnNull() {
		MockHttpServletRequest request = createRequest();
		request.addParameter(OAuth2ParameterNames.STATE, "abc123");
		updateQueryString(request);
		Authentication authentication = this.converter.convert(request);
		assertThat(authentication).isNull();
	}

	@Test
	public void convertWhenMissingUserCodeThenReturnNull() {
		MockHttpServletRequest request = createRequest();
		Authentication authentication = this.converter.convert(request);
		assertThat(authentication).isNull();
	}

	@Test
	public void convertWhenEmptyUserCodeParameterThenInvalidRequestError() {
		MockHttpServletRequest request = createRequest();
		request.addParameter(OAuth2ParameterNames.USER_CODE, "");
		updateQueryString(request);
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
	public void convertWhenInvalidUserCodeParameterThenInvalidRequestError() {
		MockHttpServletRequest request = createRequest();
		request.addParameter(OAuth2ParameterNames.USER_CODE, "LONG-USER-CODE");
		updateQueryString(request);
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
	public void convertWhenMultipleUserCodeParameterThenInvalidRequestError() {
		MockHttpServletRequest request = createRequest();
		request.addParameter(OAuth2ParameterNames.USER_CODE, USER_CODE);
		request.addParameter(OAuth2ParameterNames.USER_CODE, "another");
		updateQueryString(request);
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
	public void convertWhenMissingPrincipalThenReturnDeviceVerificationAuthentication() {
		MockHttpServletRequest request = createRequest();
		request.addParameter(OAuth2ParameterNames.USER_CODE, USER_CODE.toLowerCase().replace("-", " . "));
		updateQueryString(request);

		OAuth2DeviceVerificationAuthenticationToken authentication = (OAuth2DeviceVerificationAuthenticationToken) this.converter
			.convert(request);
		assertThat(authentication).isNotNull();
		assertThat(authentication.getPrincipal()).isInstanceOf(AnonymousAuthenticationToken.class);
		assertThat(authentication.getUserCode()).isEqualTo(USER_CODE);
		assertThat(authentication.getAdditionalParameters()).isEmpty();
	}

	@Test
	public void convertWhenNonNormalizedUserCodeThenReturnDeviceVerificationAuthentication() {
		MockHttpServletRequest request = createRequest();
		request.addParameter(OAuth2ParameterNames.USER_CODE, USER_CODE.toLowerCase().replace("-", " . "));
		updateQueryString(request);

		SecurityContextImpl securityContext = new SecurityContextImpl();
		securityContext.setAuthentication(new TestingAuthenticationToken("user", null));
		SecurityContextHolder.setContext(securityContext);

		OAuth2DeviceVerificationAuthenticationToken authentication = (OAuth2DeviceVerificationAuthenticationToken) this.converter
			.convert(request);
		assertThat(authentication).isNotNull();
		assertThat(authentication.getPrincipal()).isInstanceOf(TestingAuthenticationToken.class);
		assertThat(authentication.getUserCode()).isEqualTo(USER_CODE);
		assertThat(authentication.getAdditionalParameters()).isEmpty();
	}

	@Test
	public void convertWhenAllParametersThenReturnDeviceVerificationAuthentication() {
		MockHttpServletRequest request = createRequest();
		request.addParameter(OAuth2ParameterNames.USER_CODE, USER_CODE);
		request.addParameter("param-1", "value-1");
		request.addParameter("param-2", "value-1", "value-2");
		updateQueryString(request);

		SecurityContextImpl securityContext = new SecurityContextImpl();
		securityContext.setAuthentication(new TestingAuthenticationToken("user", null));
		SecurityContextHolder.setContext(securityContext);

		OAuth2DeviceVerificationAuthenticationToken authentication = (OAuth2DeviceVerificationAuthenticationToken) this.converter
			.convert(request);
		assertThat(authentication).isNotNull();
		assertThat(authentication.getPrincipal()).isInstanceOf(TestingAuthenticationToken.class);
		assertThat(authentication.getUserCode()).isEqualTo(USER_CODE);
		assertThat(authentication.getAdditionalParameters()).containsExactly(Map.entry("param-1", "value-1"),
				Map.entry("param-2", new String[] { "value-1", "value-2" }));
	}

	private static MockHttpServletRequest createRequest() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setMethod(HttpMethod.GET.name());
		request.setRequestURI(VERIFICATION_URI);
		return request;
	}

	private static void updateQueryString(MockHttpServletRequest request) {
		UriComponentsBuilder uriBuilder = UriComponentsBuilder.fromUriString(request.getRequestURI());
		request.getParameterMap().forEach((key, values) -> {
			if (values.length > 0) {
				for (String value : values) {
					uriBuilder.queryParam(key, value);
				}
			}
		});
		request.setQueryString(uriBuilder.build().getQuery());
	}

}
