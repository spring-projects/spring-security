/*
 * Copyright 2002-2017 the original author or authors.
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

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.server.ServerRedirectStrategy;
import org.springframework.web.server.ServerWebExchange;
import reactor.test.publisher.PublisherProbe;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

/**
 * @author Rob Winch
 * @since 5.0
 */
@RunWith(MockitoJUnitRunner.class)
public class RedirectServerAuthenticationEntryPointTests {

	@Mock
	private ServerWebExchange exchange;

	@Mock
	private ServerRedirectStrategy redirectStrategy;

	private String location = "/login";

	private RedirectServerAuthenticationEntryPoint entryPoint = new RedirectServerAuthenticationEntryPoint(
			this.location);

	private AuthenticationException exception = new AuthenticationCredentialsNotFoundException(
			"Authentication Required");

	@Test(expected = IllegalArgumentException.class)
	public void constructorStringWhenNullLocationThenException() {
		new RedirectServerAuthenticationEntryPoint(null);
	}

	@Test
	public void commenceWhenNoSubscribersThenNoActions() {
		this.exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/").build());
		this.entryPoint.commence(this.exchange, this.exception);

		assertThat(this.exchange.getResponse().getHeaders().getLocation()).isNull();
		assertThat(this.exchange.getSession().block().isStarted()).isFalse();
	}

	@Test
	public void commenceWhenSubscribeThenStatusAndLocationSet() {
		this.exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/").build());

		this.entryPoint.commence(this.exchange, this.exception).block();

		assertThat(this.exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.FOUND);
		assertThat(this.exchange.getResponse().getHeaders().getLocation()).hasPath(this.location);
	}

	@Test
	public void commenceWhenCustomServerRedirectStrategyThenCustomServerRedirectStrategyUsed() {
		PublisherProbe<Void> redirectResult = PublisherProbe.empty();
		when(this.redirectStrategy.sendRedirect(any(), any())).thenReturn(redirectResult.mono());
		this.entryPoint.setRedirectStrategy(this.redirectStrategy);
		this.exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/").build());

		this.entryPoint.commence(this.exchange, this.exception).block();

		redirectResult.assertWasSubscribed();
	}

	@Test(expected = IllegalArgumentException.class)
	public void setRedirectStrategyWhenNullThenException() {
		this.entryPoint.setRedirectStrategy(null);
	}

}
