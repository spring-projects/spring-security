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

package org.springframework.security.web.server.util.matcher;

import org.junit.jupiter.api.Test;

import org.springframework.http.HttpMethod;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoMoreInteractions;

/**
 * @author Rob Winch
 * @since 5.0
 */
public class ServerWebExchangeMatchersTests {

	ServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/").build());

	@Test
	public void pathMatchersWhenSingleAndSamePatternThenMatches() {
		assertThat(ServerWebExchangeMatchers.pathMatchers("/").matches(this.exchange).block().isMatch()).isTrue();
	}

	@Test
	public void pathMatchersWhenSingleAndSamePatternAndMethodThenMatches() {
		assertThat(ServerWebExchangeMatchers.pathMatchers(HttpMethod.GET, "/").matches(this.exchange).block().isMatch())
				.isTrue();
	}

	@Test
	public void pathMatchersWhenSingleAndSamePatternAndDiffMethodThenDoesNotMatch() {
		assertThat(
				ServerWebExchangeMatchers.pathMatchers(HttpMethod.POST, "/").matches(this.exchange).block().isMatch())
						.isFalse();
	}

	@Test
	public void pathMatchersWhenSingleAndDifferentPatternThenDoesNotMatch() {
		assertThat(ServerWebExchangeMatchers.pathMatchers("/foobar").matches(this.exchange).block().isMatch())
				.isFalse();
	}

	@Test
	public void pathMatchersWhenMultiThenMatches() {
		assertThat(ServerWebExchangeMatchers.pathMatchers("/foobar", "/").matches(this.exchange).block().isMatch())
				.isTrue();
	}

	@Test
	public void anyExchangeWhenMockThenMatches() {
		ServerWebExchange mockExchange = mock(ServerWebExchange.class);
		assertThat(ServerWebExchangeMatchers.anyExchange().matches(mockExchange).block().isMatch()).isTrue();
		verifyNoMoreInteractions(mockExchange);
	}

	/**
	 * If a LinkedMap is used and anyRequest equals anyRequest then the following is
	 * added: anyRequest() -> authenticated() pathMatchers("/admin/**") ->
	 * hasRole("ADMIN") anyRequest() -> permitAll
	 *
	 * will result in the first entry being overridden
	 */
	@Test
	public void anyExchangeWhenTwoCreatedThenDifferentToPreventIssuesInMap() {
		assertThat(ServerWebExchangeMatchers.anyExchange()).isNotEqualTo(ServerWebExchangeMatchers.anyExchange());
	}

}
