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

import org.junit.jupiter.api.Test;

import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.util.matcher.PathPatternParserServerWebExchangeMatcher;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.Mockito.mock;

/**
 * Tests for {@link ServerWebExchangeDelegatingReactiveAuthenticationManagerResolver}
 *
 * @author Josh Cummings
 */
public class ServerWebExchangeDelegatingReactiveAuthenticationManagerResolverTests {

	private ReactiveAuthenticationManager one = mock(ReactiveAuthenticationManager.class);

	private ReactiveAuthenticationManager two = mock(ReactiveAuthenticationManager.class);

	@Test
	public void resolveWhenMatchesThenReturnsReactiveAuthenticationManager() {
		ServerWebExchangeDelegatingReactiveAuthenticationManagerResolver resolver = ServerWebExchangeDelegatingReactiveAuthenticationManagerResolver
				.builder().add(new PathPatternParserServerWebExchangeMatcher("/one/**"), this.one)
				.add(new PathPatternParserServerWebExchangeMatcher("/two/**"), this.two).build();

		MockServerHttpRequest request = MockServerHttpRequest.get("/one/location").build();
		assertThat(resolver.resolve(MockServerWebExchange.from(request)).block()).isEqualTo(this.one);
	}

	@Test
	public void resolveWhenDoesNotMatchThenReturnsDefaultReactiveAuthenticationManager() {
		ServerWebExchangeDelegatingReactiveAuthenticationManagerResolver resolver = ServerWebExchangeDelegatingReactiveAuthenticationManagerResolver
				.builder().add(new PathPatternParserServerWebExchangeMatcher("/one/**"), this.one)
				.add(new PathPatternParserServerWebExchangeMatcher("/two/**"), this.two).build();

		MockServerHttpRequest request = MockServerHttpRequest.get("/wrong/location").build();
		ReactiveAuthenticationManager authenticationManager = resolver.resolve(MockServerWebExchange.from(request))
				.block();

		Authentication authentication = new TestingAuthenticationToken("principal", "creds");
		assertThatExceptionOfType(AuthenticationServiceException.class)
				.isThrownBy(() -> authenticationManager.authenticate(authentication).block());
	}

}
