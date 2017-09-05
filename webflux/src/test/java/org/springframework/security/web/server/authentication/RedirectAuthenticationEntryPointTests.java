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
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.server.RedirectStrategy;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.verifyZeroInteractions;
import static org.mockito.Mockito.when;

/**
 * @author Rob Winch
 * @since 5.0
 */
@RunWith(MockitoJUnitRunner.class)
public class RedirectAuthenticationEntryPointTests {

	@Mock
	private ServerWebExchange exchange;
	@Mock
	private RedirectStrategy redirectStrategy;

	private String location = "/login";

	private RedirectAuthenticationEntryPoint entryPoint =
		new RedirectAuthenticationEntryPoint("/login");

	private AuthenticationException exception = new AuthenticationCredentialsNotFoundException("Authentication Required");


	@Test(expected = IllegalArgumentException.class)
	public void constructorStringWhenNullLocationThenException() {
		new RedirectAuthenticationEntryPoint((String) null);
	}

	@Test
	public void commenceWhenNoSubscribersThenNoActions() {
		this.entryPoint.commence(this.exchange,
			this.exception);

		verifyZeroInteractions(this.exchange);
	}

	@Test
	public void commenceWhenSubscribeThenStatusAndLocationSet() {
		this.exchange = MockServerHttpRequest.get("/").toExchange();

		this.entryPoint.commence(this.exchange, this.exception).block();

		assertThat(this.exchange.getResponse().getStatusCode()).isEqualTo(
			HttpStatus.FOUND);
		assertThat(this.exchange.getResponse().getHeaders().getLocation()).hasPath(this.location);
	}

	@Test
	public void commenceWhenCustomStatusThenStatusSet() {
		Mono<Void> result = Mono.empty();
		when(this.redirectStrategy.sendRedirect(any(), any())).thenReturn(result);
		HttpStatus status = HttpStatus.MOVED_PERMANENTLY;
		this.entryPoint.setRedirectStrategy(this.redirectStrategy);
		this.exchange = MockServerHttpRequest.get("/").toExchange();

		assertThat(this.entryPoint.commence(this.exchange, this.exception)).isEqualTo(result);
	}

	@Test(expected = IllegalArgumentException.class)
	public void setRedirectStrategyWhenNullThenException() {
		this.entryPoint.setRedirectStrategy(null);
	}
}
