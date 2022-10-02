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

package org.springframework.security.web.server.authentication;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;

import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilterChain;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * @author Daniel Garnier-Moiroux
 * @since 5.8
 */
class ServerAuthenticationEntryPointFailureHandlerAdapterTest {

	private final ServerAuthenticationEntryPoint serverAuthenticationEntryPoint = mock(
			ServerAuthenticationEntryPoint.class);

	private final ServerWebExchange serverWebExchange = mock(ServerWebExchange.class);

	private final WebFilterExchange webFilterExchange = new WebFilterExchange(this.serverWebExchange,
			mock(WebFilterChain.class));

	@BeforeEach
	void setUp() {
		given(this.serverAuthenticationEntryPoint.commence(any(), any())).willReturn(Mono.empty());
	}

	@Test
	void onAuthenticationFailureThenCommenceAuthentication() {
		ServerAuthenticationEntryPointFailureHandlerAdapter failureHandler = new ServerAuthenticationEntryPointFailureHandlerAdapter(
				this.serverAuthenticationEntryPoint);
		AuthenticationException failure = new AuthenticationException("failed") {
		};
		failureHandler.onAuthenticationFailure(this.webFilterExchange, failure).block();
		verify(this.serverAuthenticationEntryPoint).commence(this.serverWebExchange, failure);
	}

	@Test
	void onAuthenticationFailureWithAuthenticationServiceExceptionThenRethrows() {
		ServerAuthenticationEntryPointFailureHandlerAdapter failureHandler = new ServerAuthenticationEntryPointFailureHandlerAdapter(
				this.serverAuthenticationEntryPoint);
		AuthenticationException failure = new AuthenticationServiceException("failed");
		assertThatExceptionOfType(AuthenticationServiceException.class)
				.isThrownBy(() -> failureHandler.onAuthenticationFailure(this.webFilterExchange, failure).block())
				.isSameAs(failure);
		verifyNoInteractions(this.serverWebExchange);
	}

}
