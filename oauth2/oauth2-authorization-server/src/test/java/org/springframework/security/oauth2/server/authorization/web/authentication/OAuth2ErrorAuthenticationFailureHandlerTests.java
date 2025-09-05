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

import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * Tests for {@link OAuth2ErrorAuthenticationFailureHandler}.
 *
 * @author Dmitriy Dubson
 */
public class OAuth2ErrorAuthenticationFailureHandlerTests {

	private final OAuth2ErrorAuthenticationFailureHandler authenticationFailureHandler = new OAuth2ErrorAuthenticationFailureHandler();

	@Test
	public void setErrorResponseConverterWhenNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatThrownBy(() -> this.authenticationFailureHandler.setErrorResponseConverter(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("errorResponseConverter cannot be null");
		// @formatter:on
	}

	@Test
	public void onAuthenticationFailureWhenValidExceptionThenErrorResponse() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST, "error description", "error uri");
		AuthenticationException authenticationException = new OAuth2AuthenticationException(error);

		this.authenticationFailureHandler.onAuthenticationFailure(request, response, authenticationException);

		assertThat(response.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST.value());
		assertThat(response.getContentAsString()).contains("invalid_request");
		assertThat(response.getContentAsString()).contains("error description");
		assertThat(response.getContentAsString()).contains("error uri");
	}

	@Test
	public void onAuthenticationFailureWhenInvalidExceptionThenStatusResponse() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		AuthenticationException authenticationException = new BadCredentialsException("Not a valid exception.");

		HttpMessageConverter<OAuth2Error> errorResponseConverter = mock(HttpMessageConverter.class);
		this.authenticationFailureHandler.setErrorResponseConverter(errorResponseConverter);

		this.authenticationFailureHandler.onAuthenticationFailure(request, response, authenticationException);

		verifyNoInteractions(errorResponseConverter);
		assertThat(response.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST.value());
		assertThat(response.getContentAsString()).doesNotContain(OAuth2ParameterNames.ERROR);
		assertThat(response.getContentAsString()).doesNotContain(OAuth2ParameterNames.ERROR_DESCRIPTION);
		assertThat(response.getContentAsString()).doesNotContain(OAuth2ParameterNames.ERROR_URI);
	}

}
