/*
 * Copyright 2002-2022 the original author or authors.
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

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.jupiter.api.Test;

import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * @author Daniel Garnier-Moiroux
 * @since 5.8
 */
class AuthenticationEntryPointFailureHandlerAdapterTest {

	private final AuthenticationEntryPoint authenticationEntryPoint = mock(AuthenticationEntryPoint.class);

	private final HttpServletRequest request = mock(HttpServletRequest.class);

	private final HttpServletResponse response = mock(HttpServletResponse.class);

	@Test
	void onAuthenticationFailureThenCommenceAuthentication() throws ServletException, IOException {
		AuthenticationEntryPointFailureHandlerAdapter failureHandler = new AuthenticationEntryPointFailureHandlerAdapter(
				this.authenticationEntryPoint);
		AuthenticationException failure = new AuthenticationException("failed") {
		};
		failureHandler.onAuthenticationFailure(this.request, this.response, failure);
		verify(this.authenticationEntryPoint).commence(this.request, this.response, failure);
	}

	@Test
	void onAuthenticationFailureWithAuthenticationServiceExceptionThenRethrows() {
		AuthenticationEntryPointFailureHandlerAdapter failureHandler = new AuthenticationEntryPointFailureHandlerAdapter(
				this.authenticationEntryPoint);
		AuthenticationException failure = new AuthenticationServiceException("failed");
		assertThatExceptionOfType(AuthenticationServiceException.class)
				.isThrownBy(() -> failureHandler.onAuthenticationFailure(this.request, this.response, failure))
				.isSameAs(failure);
		verifyNoInteractions(this.authenticationEntryPoint);
	}

}
