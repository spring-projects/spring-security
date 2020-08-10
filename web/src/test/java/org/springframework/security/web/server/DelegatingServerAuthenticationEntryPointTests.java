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

package org.springframework.security.web.server;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyZeroInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.security.web.server.DelegatingServerAuthenticationEntryPoint.*;

/**
 * @author Rob Winch
 * @since 5.0
 */
@RunWith(MockitoJUnitRunner.class)
public class DelegatingServerAuthenticationEntryPointTests {

	private ServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/").build());

	@Mock
	private ServerWebExchangeMatcher matcher1;

	@Mock
	private ServerWebExchangeMatcher matcher2;

	@Mock
	private ServerAuthenticationEntryPoint delegate1;

	@Mock
	private ServerAuthenticationEntryPoint delegate2;

	private AuthenticationException e = new AuthenticationCredentialsNotFoundException("Log In");

	private DelegatingServerAuthenticationEntryPoint entryPoint;

	@Test
	public void commenceWhenNotMatchThenMatchThenOnlySecondDelegateInvoked() {
		Mono<Void> expectedResult = Mono.empty();
		when(this.matcher1.matches(this.exchange)).thenReturn(ServerWebExchangeMatcher.MatchResult.notMatch());
		when(this.matcher2.matches(this.exchange)).thenReturn(ServerWebExchangeMatcher.MatchResult.match());
		when(this.delegate2.commence(this.exchange, this.e)).thenReturn(expectedResult);
		this.entryPoint = new DelegatingServerAuthenticationEntryPoint(new DelegateEntry(this.matcher1, this.delegate1),
				new DelegateEntry(this.matcher2, this.delegate2));

		Mono<Void> actualResult = this.entryPoint.commence(this.exchange, this.e);
		actualResult.block();

		verifyZeroInteractions(this.delegate1);
		verify(this.delegate2).commence(this.exchange, this.e);
	}

	@Test
	public void commenceWhenNotMatchThenDefault() {
		when(this.matcher1.matches(this.exchange)).thenReturn(ServerWebExchangeMatcher.MatchResult.notMatch());
		this.entryPoint = new DelegatingServerAuthenticationEntryPoint(
				new DelegateEntry(this.matcher1, this.delegate1));

		this.entryPoint.commence(this.exchange, this.e).block();

		assertThat(this.exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
		verifyZeroInteractions(this.delegate1);
	}

}
