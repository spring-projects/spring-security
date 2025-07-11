/*
 * Copyright 2002-2025 the original author or authors.
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

package org.springframework.security.oauth2.server.resource.web.authentication;

import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;

/**
 * Tests for {@link BearerTokenAuthenticationConverter}
 *
 * @author Max Batischev
 */
public class BearerTokenAuthenticationConverterTests {

	private static final String X_AUTH_TOKEN_HEADER = "X-Auth-Token";

	private static final String TEST_X_AUTH_TOKEN = "test-x-auth-token";

	private static final String BEARER_TOKEN = "test_bearer_token";

	private final DefaultBearerTokenResolver resolver = new DefaultBearerTokenResolver();

	private final BearerTokenAuthenticationConverter converter = new BearerTokenAuthenticationConverter();

	{
		this.converter.setBearerTokenResolver(this.resolver);
	}

	@Test
	public void convertWhenAuthorizationHeaderIsPresentThenTokenIsConverted() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addHeader(HttpHeaders.AUTHORIZATION, "Bearer " + BEARER_TOKEN);

		Authentication authentication = this.converter.convert(request);

		assertThat(authentication).isNotNull();
	}

	@Test
	public void convertWhenQueryParameterIsPresentThenTokenIsConverted() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setMethod(HttpMethod.GET.name());
		request.addParameter("access_token", BEARER_TOKEN);

		this.resolver.setAllowUriQueryParameter(true);

		Authentication authentication = this.converter.convert(request);
		assertThat(authentication).isNotNull();
	}

	@Test
	public void convertWhenAuthorizationHeaderNotIsPresentThenTokenIsNotConverted() {
		MockHttpServletRequest request = new MockHttpServletRequest();

		Authentication authentication = this.converter.convert(request);

		assertThat(authentication).isNull();
	}

	@Test
	public void convertWhenAuthorizationHeaderIsPresentTogetherWithQueryParameterThenAuthenticationExceptionIsThrown() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addParameter("access_token", BEARER_TOKEN);
		request.setMethod(HttpMethod.GET.name());
		request.addHeader(HttpHeaders.AUTHORIZATION, "Bearer " + BEARER_TOKEN);

		this.resolver.setAllowUriQueryParameter(true);
		assertThatExceptionOfType(OAuth2AuthenticationException.class).isThrownBy(() -> this.converter.convert(request))
			.withMessageContaining("Found multiple bearer tokens in the request");
	}

	@Test
	public void convertWhenXAuthTokenHeaderIsPresentAndBearerTokenHeaderNameSetThenTokenIsConverted() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addHeader(X_AUTH_TOKEN_HEADER, "Bearer " + TEST_X_AUTH_TOKEN);

		this.resolver.setBearerTokenHeaderName(X_AUTH_TOKEN_HEADER);

		Authentication authentication = this.converter.convert(request);
		assertThat(authentication).isNotNull();
	}

	@Test
	public void convertWhenHeaderWithMissingTokenIsPresentThenAuthenticationExceptionIsThrown() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addHeader(HttpHeaders.AUTHORIZATION, "Bearer ");

		assertThatExceptionOfType(OAuth2AuthenticationException.class).isThrownBy(() -> this.converter.convert(request))
			.withMessageContaining(("Bearer token is malformed"));
	}

	@Test
	public void convertWhenHeaderWithInvalidCharactersIsPresentThenAuthenticationExceptionIsThrown() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addHeader(HttpHeaders.AUTHORIZATION, "Bearer an\"invalid\"token");

		assertThatExceptionOfType(OAuth2AuthenticationException.class).isThrownBy(() -> this.converter.convert(request))
			.withMessageContaining(("Bearer token is malformed"));
	}

	@Test
	@SuppressWarnings("unchecked")
	public void convertWhenCustomAuthenticationDetailsSourceSetThenTokenIsConverted() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addHeader(HttpHeaders.AUTHORIZATION, "Bearer " + BEARER_TOKEN);
		AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource = Mockito
			.mock(AuthenticationDetailsSource.class);
		this.converter.setAuthenticationDetailsSource(authenticationDetailsSource);

		Authentication authentication = this.converter.convert(request);

		verify(authenticationDetailsSource).buildDetails(any());
		assertThat(authentication).isNotNull();
	}

	@Test
	public void convertWhenFormParameterIsPresentAndAllowFormEncodedBodyParameterThenConverted() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setMethod(HttpMethod.POST.name());
		request.setContentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE);
		request.addParameter("access_token", BEARER_TOKEN);
		this.resolver.setAllowFormEncodedBodyParameter(true);

		assertThat(this.converter.convert(request)).isNotNull();
	}

}
