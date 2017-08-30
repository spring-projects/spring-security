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

package org.springframework.security.web.server.authorization;

import java.security.Principal;
import java.util.concurrent.atomic.AtomicBoolean;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.server.AuthenticationEntryPoint;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilterChain;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.when;

/**
 * @author Rob Winch
 * @since 5.0
 */
@RunWith(MockitoJUnitRunner.class)
public class ExceptionTranslationWebFilterTests {
	@Mock
	private Principal principal;
	@Mock
	private ServerWebExchange exchange;
	@Mock
	private WebFilterChain chain;
	@Mock
	private AccessDeniedHandler deniedHandler;
	@Mock
	private AuthenticationEntryPoint entryPoint;

	private TestMono<Void> deniedMono = TestMono.create();
	private TestMono<Void> entryPointMono = TestMono.create();

	private ExceptionTranslationWebFilter filter = new ExceptionTranslationWebFilter();

	@Before
	public void setup() {
		when(this.exchange.getResponse()).thenReturn(new MockServerHttpResponse());
		when(this.deniedHandler.handle(any(), any())).thenReturn(this.deniedMono.mono());
		when(this.entryPoint.commence(any(), any())).thenReturn(this.entryPointMono.mono());

		this.filter.setAuthenticationEntryPoint(this.entryPoint);
		this.filter.setAccessDeniedHandler(this.deniedHandler);
	}

	@Test
	public void filterWhenNoExceptionThenNotHandled() {
		when(this.chain.filter(this.exchange)).thenReturn(Mono.empty());

		StepVerifier.create(this.filter.filter(this.exchange, this.chain))
			.expectComplete()
			.verify();

		assertThat(this.deniedMono.isInvoked()).isFalse();
		assertThat(this.entryPointMono.isInvoked()).isFalse();
	}

	@Test
	public void filterWhenNotAccessDeniedExceptionThenNotHandled() {
		when(this.chain.filter(this.exchange)).thenReturn(Mono.error(new IllegalArgumentException("oops")));

		StepVerifier.create(this.filter.filter(this.exchange, this.chain))
			.expectError(IllegalArgumentException.class)
			.verify();

		assertThat(this.deniedMono.isInvoked()).isFalse();
		assertThat(this.entryPointMono.isInvoked()).isFalse();
	}

	@Test
	public void filterWhenAccessDeniedExceptionAndNotAuthenticatedThenHandled() {
		when(this.exchange.getPrincipal()).thenReturn(Mono.empty());
		when(this.chain.filter(this.exchange)).thenReturn(Mono.error(new AccessDeniedException("Not Authorized")));

		StepVerifier.create(this.filter.filter(this.exchange, this.chain))
			.expectComplete()
			.verify();

		assertThat(this.deniedMono.isInvoked()).isFalse();
		assertThat(this.entryPointMono.isInvoked()).isTrue();
	}

	@Test
	public void filterWhenDefaultsAndAccessDeniedExceptionAndAuthenticatedThenForbidden() {
		this.filter = new ExceptionTranslationWebFilter();
		when(this.exchange.getPrincipal()).thenReturn(Mono.just(this.principal));
		when(this.chain.filter(this.exchange)).thenReturn(Mono.error(new AccessDeniedException("Not Authorized")));

		StepVerifier.create(this.filter.filter(this.exchange, this.chain))
			.expectComplete()
			.verify();

		assertThat(this.exchange.getResponse().getStatusCode()).isEqualTo(
			HttpStatus.FORBIDDEN);
	}

	@Test
	public void filterWhenDefaultsAndAccessDeniedExceptionAndNotAuthenticatedThenUnauthorized() {
		this.filter = new ExceptionTranslationWebFilter();
		when(this.exchange.getPrincipal()).thenReturn(Mono.empty());
		when(this.chain.filter(this.exchange)).thenReturn(Mono.error(new AccessDeniedException("Not Authorized")));

		StepVerifier.create(this.filter.filter(this.exchange, this.chain))
			.expectComplete()
			.verify();

		assertThat(this.exchange.getResponse().getStatusCode()).isEqualTo(
			HttpStatus.UNAUTHORIZED);
	}

	@Test
	public void filterWhenAccessDeniedExceptionAndAuthenticatedThenHandled() {
		when(this.exchange.getPrincipal()).thenReturn(Mono.just(this.principal));
		when(this.chain.filter(this.exchange)).thenReturn(Mono.error(new AccessDeniedException("Not Authorized")));

		StepVerifier.create(this.filter.filter(this.exchange, this.chain))
			.expectComplete()
			.verify();

		assertThat(this.deniedMono.isInvoked()).isTrue();
		assertThat(this.entryPointMono.isInvoked()).isFalse();
	}

	@Test(expected = IllegalArgumentException.class)
	public void setAccessDeniedHandlerWhenNullThenException() {
		this.filter.setAccessDeniedHandler(null);
	}

	@Test(expected = IllegalArgumentException.class)
	public void setAuthenticationEntryPointWhenNullThenException() {
		this.filter.setAuthenticationEntryPoint(null);
	}

	static class TestMono<T> {
		private final AtomicBoolean invoked = new AtomicBoolean();

		public Mono<T> mono() {
			return Mono.<T>empty().doOnSubscribe(s -> this.invoked.set(true));
		}

		public boolean isInvoked() {
			return this.invoked.get();
		}

		public static <T> TestMono<T> create() {
			return new TestMono<T>();
		}
	}
}
