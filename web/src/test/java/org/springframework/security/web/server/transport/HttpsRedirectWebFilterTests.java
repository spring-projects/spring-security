/*
 * Copyright 2002-2018 the original author or authors.
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

package org.springframework.security.web.server.transport;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;

import org.springframework.http.HttpHeaders;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.web.PortMapper;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilterChain;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatIllegalStateException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * Tests for {@link HttpsRedirectWebFilter}
 *
 * @author Josh Cummings
 */
@ExtendWith(MockitoExtension.class)
public class HttpsRedirectWebFilterTests {

	HttpsRedirectWebFilter filter;

	@Mock
	WebFilterChain chain;

	@BeforeEach
	public void configureFilter() {
		this.filter = new HttpsRedirectWebFilter();
	}

	@Test
	public void filterWhenExchangeIsInsecureThenRedirects() {
		given(this.chain.filter(any(ServerWebExchange.class))).willReturn(Mono.empty());
		ServerWebExchange exchange = get("http://localhost");
		this.filter.filter(exchange, this.chain).block();
		assertThat(statusCode(exchange)).isEqualTo(302);
		assertThat(redirectedUrl(exchange)).isEqualTo("https://localhost");
	}

	@Test
	public void filterWhenExchangeIsSecureThenNoRedirect() {
		given(this.chain.filter(any(ServerWebExchange.class))).willReturn(Mono.empty());
		ServerWebExchange exchange = get("https://localhost");
		this.filter.filter(exchange, this.chain).block();
		assertThat(exchange.getResponse().getStatusCode()).isNull();
	}

	@Test
	public void filterWhenExchangeMismatchesThenNoRedirect() {
		given(this.chain.filter(any(ServerWebExchange.class))).willReturn(Mono.empty());
		ServerWebExchangeMatcher matcher = mock(ServerWebExchangeMatcher.class);
		given(matcher.matches(any(ServerWebExchange.class)))
				.willReturn(ServerWebExchangeMatcher.MatchResult.notMatch());
		this.filter.setRequiresHttpsRedirectMatcher(matcher);
		ServerWebExchange exchange = get("http://localhost:8080");
		this.filter.filter(exchange, this.chain).block();
		assertThat(exchange.getResponse().getStatusCode()).isNull();
	}

	@Test
	public void filterWhenExchangeMatchesAndRequestIsInsecureThenRedirects() {
		given(this.chain.filter(any(ServerWebExchange.class))).willReturn(Mono.empty());
		ServerWebExchangeMatcher matcher = mock(ServerWebExchangeMatcher.class);
		given(matcher.matches(any(ServerWebExchange.class))).willReturn(ServerWebExchangeMatcher.MatchResult.match());
		this.filter.setRequiresHttpsRedirectMatcher(matcher);
		ServerWebExchange exchange = get("http://localhost:8080");
		this.filter.filter(exchange, this.chain).block();
		assertThat(statusCode(exchange)).isEqualTo(302);
		assertThat(redirectedUrl(exchange)).isEqualTo("https://localhost:8443");
		verify(matcher).matches(any(ServerWebExchange.class));
	}

	@Test
	public void filterWhenRequestIsInsecureThenPortMapperRemapsPort() {
		given(this.chain.filter(any(ServerWebExchange.class))).willReturn(Mono.empty());
		PortMapper portMapper = mock(PortMapper.class);
		given(portMapper.lookupHttpsPort(314)).willReturn(159);
		this.filter.setPortMapper(portMapper);
		ServerWebExchange exchange = get("http://localhost:314");
		this.filter.filter(exchange, this.chain).block();
		assertThat(statusCode(exchange)).isEqualTo(302);
		assertThat(redirectedUrl(exchange)).isEqualTo("https://localhost:159");
		verify(portMapper).lookupHttpsPort(314);
	}

	@Test
	public void filterWhenRequestIsInsecureAndNoPortMappingThenThrowsIllegalState() {
		given(this.chain.filter(any(ServerWebExchange.class))).willReturn(Mono.empty());
		ServerWebExchange exchange = get("http://localhost:1234");
		assertThatIllegalStateException().isThrownBy(() -> this.filter.filter(exchange, this.chain).block());
	}

	@Test
	public void filterWhenInsecureRequestHasAPathThenRedirects() {
		given(this.chain.filter(any(ServerWebExchange.class))).willReturn(Mono.empty());
		ServerWebExchange exchange = get("http://localhost:8080/path/page.html?query=string");
		this.filter.filter(exchange, this.chain).block();
		assertThat(statusCode(exchange)).isEqualTo(302);
		assertThat(redirectedUrl(exchange)).isEqualTo("https://localhost:8443/path/page.html?query=string");
	}

	@Test
	public void setRequiresTransportSecurityMatcherWhenSetWithNullValueThenThrowsIllegalArgument() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.filter.setRequiresHttpsRedirectMatcher(null));
	}

	@Test
	public void setPortMapperWhenSetWithNullValueThenThrowsIllegalArgument() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.filter.setPortMapper(null));
	}

	private String redirectedUrl(ServerWebExchange exchange) {
		return exchange.getResponse().getHeaders().get(HttpHeaders.LOCATION).iterator().next();
	}

	private int statusCode(ServerWebExchange exchange) {
		return exchange.getResponse().getStatusCode().value();
	}

	private ServerWebExchange get(String uri) {
		return MockServerWebExchange.from(MockServerHttpRequest.get(uri).build());
	}

}
