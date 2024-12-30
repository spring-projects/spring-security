/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.web.authentication;

import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.test.web.CodecTestUtils;
import org.springframework.security.web.authentication.www.BasicAuthenticationConverter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

/**
 * Tests for {@link DelegatingAuthenticationConverter}.
 *
 * @author Max Batischev
 */
@ExtendWith(MockitoExtension.class)
public class DelegatingAuthenticationConverterTests {

	private static final String X_AUTH_TOKEN_HEADER = "X-Auth-Token";

	private static final String TEST_X_AUTH_TOKEN = "test-x-auth-token";

	private static final String TEST_CUSTOM_PRINCIPAL = "test_custom_principal";

	private static final String TEST_CUSTOM_CREDENTIALS = "test_custom_credentials";

	private static final String TEST_BASIC_CREDENTIALS = "username:password";

	private static final String INVALID_BASIC_CREDENTIALS = "invalid_credentials";

	private DelegatingAuthenticationConverter converter;

	@Mock
	private AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource;

	@Test
	public void requestWhenBasicAuthorizationHeaderIsPresentThenAuthenticates() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addHeader(HttpHeaders.AUTHORIZATION, "Basic " + CodecTestUtils.encodeBase64(TEST_BASIC_CREDENTIALS));
		this.converter = new DelegatingAuthenticationConverter(
				new BasicAuthenticationConverter(this.authenticationDetailsSource),
				new TestNullableAuthenticationConverter());

		Authentication authentication = this.converter.convert(request);

		assertThat(authentication).isNotNull();
		assertThat(authentication.getName()).isEqualTo("username");
	}

	@Test
	public void requestWhenXAuthHeaderIsPresentThenAuthenticates() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addHeader(X_AUTH_TOKEN_HEADER, TEST_X_AUTH_TOKEN);
		this.converter = new DelegatingAuthenticationConverter(new TestAuthenticationConverter(),
				new TestNullableAuthenticationConverter());

		Authentication authentication = this.converter.convert(request);

		assertThat(authentication).isNotNull();
		assertThat(authentication.getName()).isEqualTo(TEST_CUSTOM_PRINCIPAL);
	}

	@Test
	public void requestWhenXAuthHeaderIsPresentThenDoesntAuthenticate() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addHeader(X_AUTH_TOKEN_HEADER, TEST_X_AUTH_TOKEN);
		this.converter = new DelegatingAuthenticationConverter(new TestNullableAuthenticationConverter());

		Authentication authentication = this.converter.convert(request);

		assertThat(authentication).isNull();
	}

	@Test
	public void requestWhenInvalidBasicAuthorizationTokenThenError() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addHeader(HttpHeaders.AUTHORIZATION, "Basic " + CodecTestUtils.encodeBase64(INVALID_BASIC_CREDENTIALS));
		this.converter = new DelegatingAuthenticationConverter(
				new BasicAuthenticationConverter(this.authenticationDetailsSource),
				new TestNullableAuthenticationConverter());

		assertThatExceptionOfType(BadCredentialsException.class).isThrownBy(() -> this.converter.convert(request));
	}

	private static class TestAuthenticationConverter implements AuthenticationConverter {

		@Override
		public Authentication convert(HttpServletRequest request) {
			String header = request.getHeader(X_AUTH_TOKEN_HEADER);
			if (header != null) {
				return new TestingAuthenticationToken(TEST_CUSTOM_PRINCIPAL, TEST_CUSTOM_CREDENTIALS);
			}
			else {
				return null;
			}
		}

	}

	private static class TestNullableAuthenticationConverter implements AuthenticationConverter {

		@Override
		public Authentication convert(HttpServletRequest request) {
			return null;
		}

	}

}
