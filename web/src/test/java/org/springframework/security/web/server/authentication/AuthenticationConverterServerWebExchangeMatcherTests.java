/*
 * Copyright 2002-2020 the original author or authors.
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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.core.Authentication;

import reactor.core.publisher.Mono;

/**
 * @author David Kovac
 * @since 5.4
 */
@RunWith(MockitoJUnitRunner.class)
public class AuthenticationConverterServerWebExchangeMatcherTests {
	private MockServerWebExchange exchange;
	private AuthenticationConverterServerWebExchangeMatcher matcher;
	@Mock
	private ServerAuthenticationConverter converter;
	@Mock
	private Authentication authentication;

	@Before
	public void setup() {
		MockServerHttpRequest request = MockServerHttpRequest.get("/path").build();
		exchange = MockServerWebExchange.from(request);
		matcher = new AuthenticationConverterServerWebExchangeMatcher(converter);
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorConverterWhenConverterNullThenThrowsException() {
		new AuthenticationConverterServerWebExchangeMatcher(null);
	}

	@Test
	public void matchesWhenNotEmptyThenReturnTrue() {
		when(converter.convert(any())).thenReturn(Mono.just(authentication));

		assertThat(matcher.matches(exchange).block().isMatch()).isTrue();
	}

	@Test
	public void matchesWhenEmptyThenReturnFalse() {
		when(converter.convert(any())).thenReturn(Mono.empty());

		assertThat(matcher.matches(exchange).block().isMatch()).isFalse();
	}

	@Test
	public void matchesWhenErrorThenReturnFalse() {
		when(converter.convert(any())).thenReturn(Mono.error(new RuntimeException()));

		assertThat(matcher.matches(exchange).block().isMatch()).isFalse();
	}

	@Test
	public void matchesWhenNullThenThrowsException() {
		when(this.converter.convert(any())).thenReturn(null);

		assertThatCode(() -> matcher.matches(exchange).block())
				.isInstanceOf(NullPointerException.class);
	}

	@Test
	public void matchesWhenExceptionThenPropagates() {
		when(this.converter.convert(any())).thenThrow(RuntimeException.class);

		assertThatCode(() -> matcher.matches(exchange).block())
				.isInstanceOf(RuntimeException.class);
	}
}
