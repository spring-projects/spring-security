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

package org.springframework.security.web.server.savedrequest;

import org.junit.Test;
import org.springframework.http.HttpCookie;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseCookie;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.util.MultiValueMap;

import java.net.URI;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link CookieServerRequestCache}
 *
 * @author Eleftheria Stein
 */
public class CookieServerRequestCacheTests {

	private CookieServerRequestCache cache = new CookieServerRequestCache();

	@Test
	public void saveRequestWhenGetRequestThenRequestUriInCookie() {
		MockServerWebExchange exchange = MockServerWebExchange
				.from(MockServerHttpRequest.get("/secured/").accept(MediaType.TEXT_HTML));
		this.cache.saveRequest(exchange).block();

		MultiValueMap<String, ResponseCookie> cookies = exchange.getResponse().getCookies();
		assertThat(cookies.size()).isEqualTo(1);
		ResponseCookie cookie = cookies.getFirst("REDIRECT_URI");
		assertThat(cookie).isNotNull();
		String encodedRedirectUrl = Base64.getEncoder().encodeToString("/secured/".getBytes());
		assertThat(cookie.toString())
				.isEqualTo("REDIRECT_URI=" + encodedRedirectUrl + "; Path=/; HttpOnly; SameSite=Lax");
	}

	@Test
	public void saveRequestWhenGetRequestWithQueryParamsThenRequestUriInCookie() {
		MockServerWebExchange exchange = MockServerWebExchange
				.from(MockServerHttpRequest.get("/secured/").queryParam("key", "value").accept(MediaType.TEXT_HTML));
		this.cache.saveRequest(exchange).block();

		MultiValueMap<String, ResponseCookie> cookies = exchange.getResponse().getCookies();
		assertThat(cookies.size()).isEqualTo(1);
		ResponseCookie cookie = cookies.getFirst("REDIRECT_URI");
		assertThat(cookie).isNotNull();
		String encodedRedirectUrl = Base64.getEncoder().encodeToString("/secured/?key=value".getBytes());
		assertThat(cookie.toString())
				.isEqualTo("REDIRECT_URI=" + encodedRedirectUrl + "; Path=/; HttpOnly; SameSite=Lax");
	}

	@Test
	public void saveRequestWhenGetRequestFaviconThenNoCookie() {
		MockServerWebExchange exchange = MockServerWebExchange
				.from(MockServerHttpRequest.get("/favicon.png").accept(MediaType.TEXT_HTML));
		this.cache.saveRequest(exchange).block();

		MultiValueMap<String, ResponseCookie> cookies = exchange.getResponse().getCookies();
		assertThat(cookies).isEmpty();
	}

	@Test
	public void saveRequestWhenPostRequestThenNoCookie() {
		MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.post("/secured/"));
		this.cache.saveRequest(exchange).block();

		MultiValueMap<String, ResponseCookie> cookies = exchange.getResponse().getCookies();
		assertThat(cookies).isEmpty();
	}

	@Test
	public void saveRequestWhenPostRequestAndCustomMatcherThenRequestUriInCookie() {
		this.cache.setSaveRequestMatcher(e -> ServerWebExchangeMatcher.MatchResult.match());
		MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.post("/secured/"));
		this.cache.saveRequest(exchange).block();

		MultiValueMap<String, ResponseCookie> cookies = exchange.getResponse().getCookies();
		ResponseCookie cookie = cookies.getFirst("REDIRECT_URI");
		assertThat(cookie).isNotNull();

		String encodedRedirectUrl = Base64.getEncoder().encodeToString("/secured/".getBytes());
		assertThat(cookie.toString())
				.isEqualTo("REDIRECT_URI=" + encodedRedirectUrl + "; Path=/; HttpOnly; SameSite=Lax");
	}

	@Test
	public void getRedirectUriWhenCookieThenReturnsRedirectUriFromCookie() {
		String encodedRedirectUrl = Base64.getEncoder().encodeToString("/secured/".getBytes());
		MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/secured/")
				.accept(MediaType.TEXT_HTML).cookie(new HttpCookie("REDIRECT_URI", encodedRedirectUrl)));

		URI redirectUri = this.cache.getRedirectUri(exchange).block();

		assertThat(redirectUri).isEqualTo(URI.create("/secured/"));
	}

	@Test
	public void getRedirectUriWhenCookieValueNotEncodedThenRedirectUriIsNull() {
		MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/secured/")
				.accept(MediaType.TEXT_HTML).cookie(new HttpCookie("REDIRECT_URI", "/secured/")));

		URI redirectUri = this.cache.getRedirectUri(exchange).block();

		assertThat(redirectUri).isNull();
	}

	@Test
	public void getRedirectUriWhenNoCookieThenRedirectUriIsNull() {
		MockServerWebExchange exchange = MockServerWebExchange
				.from(MockServerHttpRequest.get("/secured/").accept(MediaType.TEXT_HTML));

		URI redirectUri = this.cache.getRedirectUri(exchange).block();

		assertThat(redirectUri).isNull();
	}

	@Test
	public void removeMatchingRequestThenRedirectUriCookieExpired() {
		MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/secured/")
				.accept(MediaType.TEXT_HTML).cookie(new HttpCookie("REDIRECT_URI", "/secured/")));

		this.cache.removeMatchingRequest(exchange).block();

		MultiValueMap<String, ResponseCookie> cookies = exchange.getResponse().getCookies();
		ResponseCookie cookie = cookies.getFirst("REDIRECT_URI");
		assertThat(cookie).isNotNull();
		assertThat(cookie.toString()).isEqualTo(
				"REDIRECT_URI=; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=Lax");
	}

}
