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

package org.springframework.security.web.server.savedrequest;

import java.net.URI;

import org.junit.jupiter.api.Test;

import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.web.server.ServerWebExchange;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

/**
 * @author Rob Winch
 * @since 5.0
 */
public class WebSessionServerRequestCacheTests {

	private WebSessionServerRequestCache cache = new WebSessionServerRequestCache();

	@Test
	public void saveRequestGetRequestWhenGetThenFound() {
		MockServerWebExchange exchange = MockServerWebExchange
				.from(MockServerHttpRequest.get("/secured/").accept(MediaType.TEXT_HTML));
		this.cache.saveRequest(exchange).block();
		URI saved = this.cache.getRedirectUri(exchange).block();
		assertThat(saved).isEqualTo(exchange.getRequest().getURI());
	}

	@Test
	public void saveRequestGetRequestWithQueryParamsWhenGetThenFound() {
		MockServerWebExchange exchange = MockServerWebExchange
				.from(MockServerHttpRequest.get("/secured/").queryParam("key", "value").accept(MediaType.TEXT_HTML));
		this.cache.saveRequest(exchange).block();
		URI saved = this.cache.getRedirectUri(exchange).block();
		assertThat(saved).isEqualTo(exchange.getRequest().getURI());
	}

	@Test
	public void saveRequestGetRequestWhenFaviconThenNotFound() {
		MockServerWebExchange exchange = MockServerWebExchange
				.from(MockServerHttpRequest.get("/favicon.png").accept(MediaType.TEXT_HTML));
		this.cache.saveRequest(exchange).block();
		URI saved = this.cache.getRedirectUri(exchange).block();
		assertThat(saved).isNull();
	}

	@Test
	public void saveRequestGetRequestWhenPostThenNotFound() {
		MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.post("/secured/"));
		this.cache.saveRequest(exchange).block();
		assertThat(this.cache.getRedirectUri(exchange).block()).isNull();
	}

	@Test
	public void saveRequestGetRequestWhenPostAndCustomMatcherThenFound() {
		this.cache.setSaveRequestMatcher((e) -> ServerWebExchangeMatcher.MatchResult.match());
		MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.post("/secured/"));
		this.cache.saveRequest(exchange).block();
		URI saved = this.cache.getRedirectUri(exchange).block();
		assertThat(saved).isEqualTo(exchange.getRequest().getURI());
	}

	@Test
	public void saveRequestRemoveRequestWhenThenFound() {
		MockServerWebExchange exchange = MockServerWebExchange
				.from(MockServerHttpRequest.get("/secured/").accept(MediaType.TEXT_HTML));
		this.cache.saveRequest(exchange).block();
		ServerHttpRequest saved = this.cache.removeMatchingRequest(exchange).block();
		assertThat(saved.getURI()).isEqualTo(exchange.getRequest().getURI());
	}

	@Test
	public void removeRequestGetRequestWhenDefaultThenNotFound() {
		MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/secured/"));
		this.cache.saveRequest(exchange).block();
		this.cache.removeMatchingRequest(exchange).block();
		assertThat(this.cache.getRedirectUri(exchange).block()).isNull();
	}

	@Test
	public void removeMatchingRequestWhenNoParameter() {
		this.cache.setMatchingRequestParameterName("success");
		MockServerHttpRequest request = MockServerHttpRequest.get("/secured/").build();
		ServerWebExchange exchange = mock(ServerWebExchange.class);
		given(exchange.getRequest()).willReturn(request);
		assertThat(this.cache.removeMatchingRequest(exchange).block()).isNull();
		verify(exchange, never()).getSession();
	}

	@Test
	public void removeMatchingRequestWhenParameter() {
		this.cache.setMatchingRequestParameterName("success");
		MockServerHttpRequest request = MockServerHttpRequest.get("/secured/").accept(MediaType.TEXT_HTML).build();
		ServerWebExchange exchange = MockServerWebExchange.from(request);
		this.cache.saveRequest(exchange).block();
		String redirectUri = "/secured/?success";
		assertThat(this.cache.getRedirectUri(exchange).block()).isEqualTo(URI.create(redirectUri));
		MockServerHttpRequest redirectRequest = MockServerHttpRequest.get(redirectUri).build();
		ServerWebExchange redirectExchange = exchange.mutate().request(redirectRequest).build();
		assertThat(this.cache.removeMatchingRequest(redirectExchange).block()).isNotNull();
	}

}
