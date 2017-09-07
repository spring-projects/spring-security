/*
 *
 *  * Copyright 2002-2017 the original author or authors.
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *      http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */

package org.springframework.security.web.server.authentication;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.server.RedirectStrategy;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.net.URI;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.*;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyZeroInteractions;
import static org.mockito.Mockito.when;

/**
 * @author Rob Winch
 * @since 5.0
 */
@RunWith(MockitoJUnitRunner.class)
public class RedirectAuthenticationSuccessHandlerTests {

	@Mock
	private ServerWebExchange exchange;
	@Mock
	private WebFilterChain chain;
	@Mock
	private RedirectStrategy redirectStrategy;
	@Mock
	private Authentication authentication;

	private URI location = URI.create("/");

	private RedirectAuthenticationSuccessHandler handler =
		new RedirectAuthenticationSuccessHandler();

	@Test(expected = IllegalArgumentException.class)
	public void constructorStringWhenNullLocationThenException() {
		new RedirectAuthenticationEntryPoint((String) null);
	}

	@Test
	public void successWhenNoSubscribersThenNoActions() {
		this.handler.success(this.authentication, new WebFilterExchange(this.exchange,
			this.chain));

		verifyZeroInteractions(this.exchange);
	}

	@Test
	public void successWhenSubscribeThenStatusAndLocationSet() {
		this.exchange = MockServerHttpRequest.get("/").toExchange();

		this.handler.success(this.authentication, new WebFilterExchange(this.exchange,
			this.chain)).block();

		assertThat(this.exchange.getResponse().getStatusCode()).isEqualTo(
			HttpStatus.FOUND);
		assertThat(this.exchange.getResponse().getHeaders().getLocation()).isEqualTo(this.location);
	}

	@Test
	public void successWhenCustomLocationThenCustomLocationUsed() {
		Mono<Void> result = Mono.empty();
		when(this.redirectStrategy.sendRedirect(any(), any())).thenReturn(result);
		this.handler.setRedirectStrategy(this.redirectStrategy);
		this.exchange = MockServerHttpRequest.get("/").toExchange();

		assertThat(this.handler.success(this.authentication, new WebFilterExchange(this.exchange,
			this.chain))).isEqualTo(result);
		verify(this.redirectStrategy).sendRedirect(any(), eq(this.location));
	}

	@Test(expected = IllegalArgumentException.class)
	public void setRedirectStrategyWhenNullThenException() {
		this.handler.setRedirectStrategy(null);
	}

	@Test(expected = IllegalArgumentException.class)
	public void setLocationWhenNullThenException() {
		this.handler.setLocation(null);
	}
}
