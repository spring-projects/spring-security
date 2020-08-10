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

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import reactor.core.publisher.Mono;

import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

/**
 * @author David Kovac
 * @since 5.4
 */
@RunWith(MockitoJUnitRunner.class)
public class AuthenticationConverterServerWebExchangeMatcherTests {

	private MockServerWebExchange exchange;

	private AuthenticationConverterServerWebExchangeMatcher matcher;

	private Authentication authentication = new TestingAuthenticationToken("user", "password");

	@Mock
	private ServerAuthenticationConverter converter;

	@Before
	public void setup() {
		MockServerHttpRequest request = MockServerHttpRequest.get("/path").build();
		this.exchange = MockServerWebExchange.from(request);
		this.matcher = new AuthenticationConverterServerWebExchangeMatcher(this.converter);
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorConverterWhenConverterNullThenThrowsException() {
		new AuthenticationConverterServerWebExchangeMatcher(null);
	}

	@Test
	public void matchesWhenNotEmptyThenReturnTrue() {
		when(this.converter.convert(any())).thenReturn(Mono.just(this.authentication));

		assertThat(this.matcher.matches(this.exchange).block().isMatch()).isTrue();
	}

	@Test
	public void matchesWhenEmptyThenReturnFalse() {
		when(this.converter.convert(any())).thenReturn(Mono.empty());

		assertThat(this.matcher.matches(this.exchange).block().isMatch()).isFalse();
	}

	@Test
	public void matchesWhenErrorThenReturnFalse() {
		when(this.converter.convert(any())).thenReturn(Mono.error(new RuntimeException()));

		assertThat(this.matcher.matches(this.exchange).block().isMatch()).isFalse();
	}

	@Test
	public void matchesWhenNullThenThrowsException() {
		when(this.converter.convert(any())).thenReturn(null);

		assertThatCode(() -> this.matcher.matches(this.exchange).block()).isInstanceOf(NullPointerException.class);
	}

	@Test
	public void matchesWhenExceptionThenPropagates() {
		when(this.converter.convert(any())).thenThrow(RuntimeException.class);

		assertThatCode(() -> this.matcher.matches(this.exchange).block()).isInstanceOf(RuntimeException.class);
	}

}
