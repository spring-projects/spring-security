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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;

import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatNullPointerException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;

/**
 * @author David Kovac
 * @since 5.4
 */
@ExtendWith(MockitoExtension.class)
public class AuthenticationConverterServerWebExchangeMatcherTests {

	private MockServerWebExchange exchange;

	private AuthenticationConverterServerWebExchangeMatcher matcher;

	private Authentication authentication = new TestingAuthenticationToken("user", "password");

	@Mock
	private ServerAuthenticationConverter converter;

	@BeforeEach
	public void setup() {
		MockServerHttpRequest request = MockServerHttpRequest.get("/path").build();
		this.exchange = MockServerWebExchange.from(request);
		this.matcher = new AuthenticationConverterServerWebExchangeMatcher(this.converter);
	}

	@Test
	public void constructorConverterWhenConverterNullThenThrowsException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new AuthenticationConverterServerWebExchangeMatcher(null));
	}

	@Test
	public void matchesWhenNotEmptyThenReturnTrue() {
		given(this.converter.convert(any())).willReturn(Mono.just(this.authentication));
		assertThat(this.matcher.matches(this.exchange).block().isMatch()).isTrue();
	}

	@Test
	public void matchesWhenEmptyThenReturnFalse() {
		given(this.converter.convert(any())).willReturn(Mono.empty());
		assertThat(this.matcher.matches(this.exchange).block().isMatch()).isFalse();
	}

	@Test
	public void matchesWhenErrorThenReturnFalse() {
		given(this.converter.convert(any())).willReturn(Mono.error(new RuntimeException()));
		assertThat(this.matcher.matches(this.exchange).block().isMatch()).isFalse();
	}

	@Test
	public void matchesWhenNullThenThrowsException() {
		given(this.converter.convert(any())).willReturn(null);
		assertThatNullPointerException().isThrownBy(() -> this.matcher.matches(this.exchange).block());
	}

	@Test
	public void matchesWhenExceptionThenPropagates() {
		given(this.converter.convert(any())).willThrow(RuntimeException.class);
		assertThatExceptionOfType(RuntimeException.class).isThrownBy(() -> this.matcher.matches(this.exchange).block());
	}

}
