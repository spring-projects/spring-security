/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.web.server.firewall;

import java.net.URI;
import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Test;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseCookie;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link StrictServerWebExchangeFirewall}.
 *
 * @author Rob Winch
 * @since 6.4
 */
class StrictServerWebExchangeFirewallTests {

	public String[] unnormalizedPaths = { "http://exploit.example/..", "http://exploit.example/./path/",
			"http://exploit.example/path/path/.", "http://exploit.example/path/path//.",
			"http://exploit.example/./path/../path//.", "http://exploit.example/./path",
			"http://exploit.example/.//path", "http://exploit.example/.", "http://exploit.example//path",
			"http://exploit.example//path/path", "http://exploit.example//path//path",
			"http://exploit.example/path//path" };

	private StrictServerWebExchangeFirewall firewall = new StrictServerWebExchangeFirewall();

	private MockServerHttpRequest.BaseBuilder<?> request = get("/");

	@Test
	void cookieWhenHasNewLineThenThrowsException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> ResponseCookie.from("test").value("Something\nhere").build());
	}

	@Test
	void cookieWhenHasLineFeedThenThrowsException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> ResponseCookie.from("test").value("Something\rhere").build());
	}

	@Test
	void responseHeadersWhenValueHasNewLineThenThrowsException() {
		this.request = MockServerHttpRequest.get("/");
		ServerWebExchange exchange = getFirewalledExchange();
		exchange.getResponse().getHeaders().set("FOO", "new\nline");
		assertThatIllegalArgumentException().isThrownBy(() -> exchange.getResponse().setComplete().block());
	}

	@Test
	void responseHeadersWhenValueHasLineFeedThenThrowsException() {
		this.request = MockServerHttpRequest.get("/");
		ServerWebExchange exchange = getFirewalledExchange();
		exchange.getResponse().getHeaders().set("FOO", "line\rfeed");
		assertThatIllegalArgumentException().isThrownBy(() -> exchange.getResponse().setComplete().block());
	}

	@Test
	void responseHeadersWhenNameHasNewLineThenThrowsException() {
		this.request = MockServerHttpRequest.get("/");
		ServerWebExchange exchange = getFirewalledExchange();
		exchange.getResponse().getHeaders().set("new\nline", "FOO");
		assertThatIllegalArgumentException().isThrownBy(() -> exchange.getResponse().setComplete().block());
	}

	@Test
	void responseHeadersWhenNameHasLineFeedThenThrowsException() {
		this.request = MockServerHttpRequest.get("/");
		ServerWebExchange exchange = getFirewalledExchange();
		exchange.getResponse().getHeaders().set("line\rfeed", "FOO");
		assertThatIllegalArgumentException().isThrownBy(() -> exchange.getResponse().setComplete().block());
	}

	@Test
	void getFirewalledExchangeWhenInvalidMethodThenThrowsServerExchangeRejectedException() {
		this.request = MockServerHttpRequest.method(HttpMethod.valueOf("INVALID"), "/");
		assertThatExceptionOfType(ServerExchangeRejectedException.class).isThrownBy(() -> getFirewalledExchange());
	}

	private ServerWebExchange getFirewalledExchange() {
		MockServerWebExchange exchange = MockServerWebExchange.from(this.request.build());
		return this.firewall.getFirewalledExchange(exchange).block();
	}

	private MockServerHttpRequest.BodyBuilder get(String uri) {
		URI url = URI.create(uri);
		return MockServerHttpRequest.method(HttpMethod.GET, url);
	}

	// blocks XST attacks
	@Test
	void getFirewalledExchangeWhenTraceMethodThenThrowsServerExchangeRejectedException() {
		this.request = MockServerHttpRequest.method(HttpMethod.TRACE, "/");
		assertThatExceptionOfType(ServerExchangeRejectedException.class).isThrownBy(() -> getFirewalledExchange());
	}

	@Test
	// blocks XST attack if request is forwarded to a Microsoft IIS web server
	void getFirewalledExchangeWhenTrackMethodThenThrowsServerExchangeRejectedException() {
		this.request = MockServerHttpRequest.method(HttpMethod.TRACE, "/");
		assertThatExceptionOfType(ServerExchangeRejectedException.class).isThrownBy(() -> getFirewalledExchange());
	}

	@Test
	// HTTP methods are case sensitive
	void getFirewalledExchangeWhenLowercaseGetThenThrowsServerExchangeRejectedException() {
		this.request = MockServerHttpRequest.method(HttpMethod.valueOf("get"), "/");
		assertThatExceptionOfType(ServerExchangeRejectedException.class).isThrownBy(() -> getFirewalledExchange());
	}

	@Test
	void getFirewalledExchangeWhenAllowedThenNoException() {
		List<String> allowedMethods = Arrays.asList("DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT");
		for (String allowedMethod : allowedMethods) {
			this.request = MockServerHttpRequest.method(HttpMethod.valueOf(allowedMethod), "/");
			getFirewalledExchange();
		}
	}

	@Test
	void getFirewalledExchangeWhenInvalidMethodAndAnyMethodThenNoException() {
		this.firewall.setUnsafeAllowAnyHttpMethod(true);
		this.request = MockServerHttpRequest.method(HttpMethod.valueOf("INVALID"), "/");
		getFirewalledExchange();
	}

	@Test
	void getFirewalledExchangeWhenURINotNormalizedThenThrowsServerExchangeRejectedException() {
		for (String path : this.unnormalizedPaths) {
			this.request = get(path);
			assertThatExceptionOfType(ServerExchangeRejectedException.class)
				.describedAs("The path '" + path + "' is not normalized")
				.isThrownBy(() -> getFirewalledExchange());
		}
	}

	@Test
	void getFirewalledExchangeWhenSemicolonInRequestUriThenThrowsServerExchangeRejectedException() {
		this.request = get("/path;/");
		assertThatExceptionOfType(ServerExchangeRejectedException.class).isThrownBy(() -> getFirewalledExchange());
	}

	@Test
	void getFirewalledExchangeWhenEncodedSemicolonInRequestUriThenThrowsServerExchangeRejectedException() {
		this.request = get("/path%3B/");
		assertThatExceptionOfType(ServerExchangeRejectedException.class).isThrownBy(() -> getFirewalledExchange());
	}

	@Test
	void getFirewalledExchangeWhenLowercaseEncodedSemicolonInRequestUriThenThrowsServerExchangeRejectedException() {
		this.request = MockServerHttpRequest.method(HttpMethod.GET, URI.create("/path%3b/"));
		assertThatExceptionOfType(ServerExchangeRejectedException.class).isThrownBy(() -> getFirewalledExchange());
	}

	@Test
	void getFirewalledExchangeWhenSemicolonInRequestUriAndAllowSemicolonThenNoException() {
		this.firewall.setAllowSemicolon(true);
		this.request = get("/path;/");
		getFirewalledExchange();
	}

	@Test
	void getFirewalledExchangeWhenEncodedSemicolonInRequestUriAndAllowSemicolonThenNoException() {
		this.firewall.setAllowSemicolon(true);
		this.request = get("/path%3B/");
		getFirewalledExchange();
	}

	@Test
	void getFirewalledExchangeWhenLowercaseEncodedSemicolonInRequestUriAndAllowSemicolonThenNoException() {
		this.firewall.setAllowSemicolon(true);
		this.request = get("/path%3b/");
		getFirewalledExchange();
	}

	@Test
	void getFirewalledExchangeWhenLowercaseEncodedPeriodInThenThrowsServerExchangeRejectedException() {
		this.request = get("/%2e/");
		assertThatExceptionOfType(ServerExchangeRejectedException.class).isThrownBy(() -> getFirewalledExchange());
	}

	@Test
	void getFirewalledExchangeWhenContainsLowerboundAsciiThenNoException() {
		this.request = get("/%20");
		getFirewalledExchange();
	}

	@Test
	void getFirewalledExchangeWhenContainsUpperboundAsciiThenNoException() {
		this.request = get("/~");
		getFirewalledExchange();
	}

	@Test
	void getFirewalledExchangeWhenJapaneseCharacterThenNoException() {
		// FIXME: .method(HttpMethod.GET to .get and similar methods
		this.request = get("/\u3042");
		getFirewalledExchange();
	}

	@Test
	void getFirewalledExchangeWhenContainsEncodedNullThenException() {
		this.request = get("/something%00/");
		assertThatExceptionOfType(ServerExchangeRejectedException.class).isThrownBy(() -> getFirewalledExchange());
	}

	@Test
	void getFirewalledExchangeWhenContainsLowercaseEncodedLineFeedThenException() {
		this.request = get("/something%0a/");
		assertThatExceptionOfType(ServerExchangeRejectedException.class).isThrownBy(() -> getFirewalledExchange());
	}

	@Test
	void getFirewalledExchangeWhenContainsUppercaseEncodedLineFeedThenException() {
		this.request = get("/something%0A/");
		assertThatExceptionOfType(ServerExchangeRejectedException.class).isThrownBy(() -> getFirewalledExchange());
	}

	@Test
	void getFirewalledExchangeWhenContainsLowercaseEncodedCarriageReturnThenException() {
		this.request = get("/something%0d/");
		assertThatExceptionOfType(ServerExchangeRejectedException.class).isThrownBy(() -> getFirewalledExchange());
	}

	@Test
	void getFirewalledExchangeWhenContainsUppercaseEncodedCarriageReturnThenException() {
		this.request = get("/something%0D/");
		assertThatExceptionOfType(ServerExchangeRejectedException.class).isThrownBy(() -> getFirewalledExchange());
	}

	@Test
	void getFirewalledExchangeWhenContainsLowercaseEncodedLineFeedAndAllowedThenNoException() {
		this.firewall.setAllowUrlEncodedLineFeed(true);
		this.request = get("/something%0a/");
		getFirewalledExchange();
	}

	@Test
	void getFirewalledExchangeWhenContainsUppercaseEncodedLineFeedAndAllowedThenNoException() {
		this.firewall.setAllowUrlEncodedLineFeed(true);
		this.request = get("/something%0A/");
		getFirewalledExchange();
	}

	@Test
	void getFirewalledExchangeWhenContainsLowercaseEncodedCarriageReturnAndAllowedThenNoException() {
		this.firewall.setAllowUrlEncodedCarriageReturn(true);
		this.request = get("/something%0d/");
		getFirewalledExchange();
	}

	@Test
	void getFirewalledExchangeWhenContainsUppercaseEncodedCarriageReturnAndAllowedThenNoException() {
		this.firewall.setAllowUrlEncodedCarriageReturn(true);
		this.request = get("/something%0D/");
		getFirewalledExchange();
	}

	/**
	 * On WebSphere 8.5 a URL like /context-root/a/b;%2f1/c can bypass a rule on /a/b/c
	 * because the pathInfo is /a/b;/1/c which ends up being /a/b/1/c while Spring MVC
	 * will strip the ; content from requestURI before the path is URL decoded.
	 */
	@Test
	void getFirewalledExchangeWhenLowercaseEncodedPathThenException() {
		this.request = get("/context-root/a/b;%2f1/c");
		assertThatExceptionOfType(ServerExchangeRejectedException.class).isThrownBy(() -> getFirewalledExchange());
	}

	@Test
	void getFirewalledExchangeWhenUppercaseEncodedPathThenException() {
		this.request = get("/context-root/a/b;%2F1/c");
		assertThatExceptionOfType(ServerExchangeRejectedException.class).isThrownBy(() -> getFirewalledExchange());
	}

	@Test
	void getFirewalledExchangeWhenAllowUrlEncodedSlashAndLowercaseEncodedPathThenNoException() {
		this.firewall.setAllowUrlEncodedSlash(true);
		this.firewall.setAllowSemicolon(true);
		this.request = get("/context-root/a/b;%2f1/c");
		getFirewalledExchange();
	}

	@Test
	void getFirewalledExchangeWhenAllowUrlEncodedSlashAndUppercaseEncodedPathThenNoException() {
		this.firewall.setAllowUrlEncodedSlash(true);
		this.firewall.setAllowSemicolon(true);
		this.request = get("/context-root/a/b;%2F1/c");
		getFirewalledExchange();
	}

	@Test
	void getFirewalledExchangeWhenAllowUrlLowerCaseEncodedDoubleSlashThenNoException() {
		this.firewall.setAllowUrlEncodedSlash(true);
		this.firewall.setAllowUrlEncodedDoubleSlash(true);
		this.request = get("/context-root/a/b%2f%2fc");
		getFirewalledExchange();
	}

	@Test
	void getFirewalledExchangeWhenAllowUrlUpperCaseEncodedDoubleSlashThenNoException() {
		this.firewall.setAllowUrlEncodedSlash(true);
		this.firewall.setAllowUrlEncodedDoubleSlash(true);
		this.request = get("/context-root/a/b%2F%2Fc");
		getFirewalledExchange();
	}

	@Test
	void getFirewalledExchangeWhenAllowUrlLowerCaseAndUpperCaseEncodedDoubleSlashThenNoException() {
		this.firewall.setAllowUrlEncodedSlash(true);
		this.firewall.setAllowUrlEncodedDoubleSlash(true);
		this.request = get("/context-root/a/b%2f%2Fc");
		getFirewalledExchange();
	}

	@Test
	void getFirewalledExchangeWhenAllowUrlUpperCaseAndLowerCaseEncodedDoubleSlashThenNoException() {
		this.firewall.setAllowUrlEncodedSlash(true);
		this.firewall.setAllowUrlEncodedDoubleSlash(true);
		this.request = get("/context-root/a/b%2F%2fc");
		getFirewalledExchange();
	}

	@Test
	void getFirewalledExchangeWhenRemoveFromUpperCaseEncodedUrlBlocklistThenNoException() {
		this.firewall.setAllowUrlEncodedSlash(true);
		this.request = get("/context-root/a/b%2Fc");
		this.firewall.getEncodedUrlBlocklist().removeAll(Arrays.asList("%2F%2F"));
		getFirewalledExchange();
	}

	@Test
	void getFirewalledExchangeWhenRemoveFromDecodedUrlBlocklistThenNoException() {
		this.request = get("/a/b%2F%2Fc");
		this.firewall.getDecodedUrlBlocklist().removeAll(Arrays.asList("//"));
		this.firewall.getEncodedUrlBlocklist().removeAll(Arrays.asList("%2F%2F"));
		this.firewall.getEncodedUrlBlocklist().removeAll(Arrays.asList("%2F"));
		getFirewalledExchange();
	}

	@Test
	void getFirewalledExchangeWhenTrustedDomainThenNoException() {
		this.request.header("Host", "example.org");
		this.firewall.setAllowedHostnames((hostname) -> hostname.equals("example.org"));
		getFirewalledExchange();
	}

	@Test
	void getFirewalledExchangeWhenUntrustedDomainThenException() {
		this.request = get("https://example.org");
		this.firewall.setAllowedHostnames((hostname) -> hostname.equals("myexample.org"));
		assertThatExceptionOfType(ServerExchangeRejectedException.class).isThrownBy(() -> getFirewalledExchange());
	}

	@Test
	void getFirewalledExchangeGetHeaderWhenNotAllowedHeaderNameThenException() {
		this.firewall.setAllowedHeaderNames((name) -> !name.equals("bad name"));
		ServerWebExchange exchange = getFirewalledExchange();
		HttpHeaders headers = exchange.getRequest().getHeaders();
		assertThatExceptionOfType(ServerExchangeRejectedException.class).isThrownBy(() -> headers.get("bad name"));
	}

	@Test
	void getFirewalledExchangeWhenHeaderNameNotAllowedWithAugmentedHeaderNamesThenException() {
		this.firewall.setAllowedHeaderNames(
				StrictServerWebExchangeFirewall.ALLOWED_HEADER_NAMES.and((name) -> !name.equals("bad name")));
		ServerWebExchange exchange = getFirewalledExchange();
		HttpHeaders headers = exchange.getRequest().getHeaders();
		assertThatExceptionOfType(ServerExchangeRejectedException.class).isThrownBy(() -> headers.getFirst("bad name"));
	}

	@Test
	void getFirewalledExchangeGetHeaderWhenNotAllowedHeaderValueThenException() {
		this.request.header("good name", "bad value");
		this.firewall.setAllowedHeaderValues((value) -> !value.equals("bad value"));
		ServerWebExchange exchange = getFirewalledExchange();
		HttpHeaders headers = exchange.getRequest().getHeaders();
		assertThatExceptionOfType(ServerExchangeRejectedException.class).isThrownBy(() -> headers.get("good name"));
	}

	@Test
	void getFirewalledExchangeWhenHeaderValueNotAllowedWithAugmentedHeaderValuesThenException() {
		this.request.header("good name", "bad value");
		this.firewall.setAllowedHeaderValues(
				StrictServerWebExchangeFirewall.ALLOWED_HEADER_VALUES.and((value) -> !value.equals("bad value")));
		ServerWebExchange exchange = getFirewalledExchange();
		HttpHeaders headers = exchange.getRequest().getHeaders();
		assertThatExceptionOfType(ServerExchangeRejectedException.class).isThrownBy(() -> headers.get("good name"));
	}

	@Test
	void getFirewalledExchangeGetDateHeaderWhenControlCharacterInHeaderNameThenException() {
		this.request.header("Bad\0Name", "some value");
		ServerWebExchange exchange = getFirewalledExchange();
		HttpHeaders headers = exchange.getRequest().getHeaders();
		assertThatExceptionOfType(ServerExchangeRejectedException.class).isThrownBy(() -> headers.get("Bad\0Name"));
	}

	@Test
	void getFirewalledExchangeGetHeaderWhenUndefinedCharacterInHeaderNameThenException() {
		this.request.header("Bad\uFFFEName", "some value");
		ServerWebExchange exchange = getFirewalledExchange();
		HttpHeaders headers = exchange.getRequest().getHeaders();
		assertThatExceptionOfType(ServerExchangeRejectedException.class).isThrownBy(() -> headers.get("Bad\uFFFEName"));
	}

	@Test
	void getFirewalledExchangeGetHeadersWhenControlCharacterInHeaderNameThenException() {
		this.request.header("Bad\0Name", "some value");
		ServerWebExchange exchange = getFirewalledExchange();
		HttpHeaders headers = exchange.getRequest().getHeaders();
		assertThatExceptionOfType(ServerExchangeRejectedException.class).isThrownBy(() -> headers.get("Bad\0Name"));
	}

	@Test
	void getFirewalledExchangeGetHeaderNamesWhenControlCharacterInHeaderNameThenException() {
		this.request.header("Bad\0Name", "some value");
		ServerWebExchange exchange = getFirewalledExchange();
		HttpHeaders headers = exchange.getRequest().getHeaders();
		assertThatExceptionOfType(ServerExchangeRejectedException.class)
			.isThrownBy(() -> headers.keySet().iterator().next());
	}

	@Test
	void getFirewalledExchangeGetHeaderWhenControlCharacterInHeaderValueThenException() {
		this.request.header("Something", "bad\0value");
		ServerWebExchange exchange = getFirewalledExchange();
		HttpHeaders headers = exchange.getRequest().getHeaders();
		assertThatExceptionOfType(ServerExchangeRejectedException.class).isThrownBy(() -> headers.get("Something"));
	}

	@Test
	void getFirewalledExchangeGetHeaderWhenHorizontalTabInHeaderValueThenNoException() {
		this.request.header("Something", "tab\tvalue");
		ServerWebExchange exchange = getFirewalledExchange();
		HttpHeaders headers = exchange.getRequest().getHeaders();
		assertThat(headers.getFirst("Something")).isEqualTo("tab\tvalue");
	}

	@Test
	void getFirewalledExchangeGetHeaderWhenUndefinedCharacterInHeaderValueThenException() {
		this.request.header("Something", "bad\uFFFEvalue");
		ServerWebExchange exchange = getFirewalledExchange();
		HttpHeaders headers = exchange.getRequest().getHeaders();
		assertThatExceptionOfType(ServerExchangeRejectedException.class)
			.isThrownBy(() -> headers.getFirst("Something"));
	}

	@Test
	void getFirewalledExchangeGetHeadersWhenControlCharacterInHeaderValueThenException() {
		this.request.header("Something", "bad\0value");
		ServerWebExchange exchange = getFirewalledExchange();
		HttpHeaders headers = exchange.getRequest().getHeaders();
		assertThatExceptionOfType(ServerExchangeRejectedException.class).isThrownBy(() -> headers.get("Something"));
	}

	@Test
	void getFirewalledExchangeGetParameterWhenControlCharacterInParameterNameThenException() {
		this.request.queryParam("Bad\0Name", "some value");
		ServerWebExchange exchange = getFirewalledExchange();
		ServerHttpRequest request = exchange.getRequest();
		assertThatExceptionOfType(ServerExchangeRejectedException.class).isThrownBy(request::getQueryParams);
	}

	@Test
	void getFirewalledExchangeGetParameterValuesWhenNotAllowedInParameterValueThenException() {
		this.firewall.setAllowedParameterValues((value) -> !value.equals("bad value"));
		this.request.queryParam("Something", "bad value");
		ServerWebExchange exchange = getFirewalledExchange();
		ServerHttpRequest request = exchange.getRequest();
		assertThatExceptionOfType(ServerExchangeRejectedException.class).isThrownBy(() -> request.getQueryParams());
	}

	@Test
	void getFirewalledExchangeGetParameterValuesWhenNotAllowedInParameterNameThenException() {
		this.firewall.setAllowedParameterNames((value) -> !value.equals("bad name"));
		this.request.queryParam("bad name", "good value");
		ServerWebExchange exchange = getFirewalledExchange();
		ServerHttpRequest request = exchange.getRequest();
		assertThatExceptionOfType(ServerExchangeRejectedException.class).isThrownBy(() -> request.getQueryParams());
	}

	// gh-9598
	@Test
	void getFirewalledExchangeGetHeaderWhenNameIsNullThenNull() {
		ServerWebExchange exchange = getFirewalledExchange();
		assertThat(exchange.getRequest().getHeaders().get(null)).isNull();
	}

	@Test
	void getFirewalledExchangeWhenMutateThenHeadersStillFirewalled() {
		String invalidHeaderName = "bad name";
		this.firewall.setAllowedHeaderNames((name) -> !name.equals(invalidHeaderName));
		ServerWebExchange exchange = getFirewalledExchange();
		ServerWebExchange mutatedExchange = exchange.mutate().request(exchange.getRequest().mutate().build()).build();
		HttpHeaders headers = mutatedExchange.getRequest().getHeaders();
		assertThatExceptionOfType(ServerExchangeRejectedException.class)
			.isThrownBy(() -> headers.get(invalidHeaderName));
	}

	@Test
	void getMutatedFirewalledExchangeGetHeaderWhenNotAllowedHeaderNameThenException() {
		String invalidHeaderName = "bad name";
		this.firewall.setAllowedHeaderNames((name) -> !name.equals(invalidHeaderName));
		ServerWebExchange exchange = getFirewalledExchange();
		HttpHeaders headers = exchange.getRequest().mutate().build().getHeaders();
		assertThatExceptionOfType(ServerExchangeRejectedException.class)
			.isThrownBy(() -> headers.get(invalidHeaderName));
	}

}
