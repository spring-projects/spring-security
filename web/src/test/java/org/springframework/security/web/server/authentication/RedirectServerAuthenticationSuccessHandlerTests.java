/*
 * Copyright 2002-2023 the original author or authors.
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

import java.net.URI;
import java.util.Collections;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.publisher.PublisherProbe;

import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.server.ServerRedirectStrategy;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.web.server.WebSession;
import org.springframework.web.server.handler.DefaultWebFilterChain;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.verify;

/**
 * @author Rob Winch
 * @since 5.0
 */
@ExtendWith(MockitoExtension.class)
public class RedirectServerAuthenticationSuccessHandlerTests {

	private WebFilterExchange exchange;

	@Mock
	private ServerRedirectStrategy redirectStrategy;

	@Mock
	private Authentication authentication;

	private URI location = URI.create("/");

	private RedirectServerAuthenticationSuccessHandler handler = new RedirectServerAuthenticationSuccessHandler();

	@Test
	public void constructorStringWhenNullLocationThenException() {
		assertThatIllegalArgumentException().isThrownBy(() -> new RedirectServerAuthenticationEntryPoint(null));
	}

	@Test
	public void successWhenNoSubscribersThenNoActions() {
		this.exchange = createExchange();
		this.handler.onAuthenticationSuccess(this.exchange, this.authentication);
		assertThat(this.exchange.getExchange().getResponse().getHeaders().getLocation()).isNull();
		assertThat(this.exchange.getExchange().getSession().block().isStarted()).isFalse();
	}

	@Test
	public void successWhenSubscribeThenStatusAndLocationSet() {
		this.exchange = createExchange();
		this.handler.onAuthenticationSuccess(this.exchange, this.authentication).block();
		assertThat(this.exchange.getExchange().getResponse().getStatusCode()).isEqualTo(HttpStatus.FOUND);
		assertThat(this.exchange.getExchange().getResponse().getHeaders().getLocation()).isEqualTo(this.location);
	}

	@Test
	public void successWhenCustomLocationThenCustomLocationUsed() {
		PublisherProbe<Void> redirectResult = PublisherProbe.empty();
		given(this.redirectStrategy.sendRedirect(any(), any())).willReturn(redirectResult.mono());
		this.handler.setRedirectStrategy(this.redirectStrategy);
		this.exchange = createExchange();
		this.handler.onAuthenticationSuccess(this.exchange, this.authentication).block();
		redirectResult.assertWasSubscribed();
		verify(this.redirectStrategy).sendRedirect(any(), eq(this.location));
	}

	@Test
	public void setRedirectStrategyWhenNullThenException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.handler.setRedirectStrategy(null));
	}

	@Test
	public void setLocationWhenNullThenException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.handler.setLocation(null));
	}

	@Test
	public void shouldRemoveAuthenticationAttributeWhenOnAuthenticationSuccess() {
		this.exchange = createExchange();
		WebSession session = this.exchange.getExchange().getSession().block();
		assertThat(session).isNotNull();
		AuthenticationException exception = new BadCredentialsException("Invalid credentials");
		session.getAttributes().put(WebAttributes.AUTHENTICATION_EXCEPTION, exception);
		this.handler.onAuthenticationSuccess(this.exchange, this.authentication).block();
		AuthenticationException authAttribute = session.getAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
		assertThat(authAttribute).isNull();
	}

	private WebFilterExchange createExchange() {
		return new WebFilterExchange(MockServerWebExchange.from(MockServerHttpRequest.get("/").build()),
				new DefaultWebFilterChain((e) -> Mono.empty(), Collections.emptyList()));
	}

}
