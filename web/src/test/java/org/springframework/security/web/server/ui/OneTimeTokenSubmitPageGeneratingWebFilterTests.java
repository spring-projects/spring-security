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

package org.springframework.security.web.server.ui;

import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;

import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link OneTimeTokenSubmitPageGeneratingWebFilter}
 *
 * @author Max Batischev
 */
public class OneTimeTokenSubmitPageGeneratingWebFilterTests {

	private final OneTimeTokenSubmitPageGeneratingWebFilter filter = new OneTimeTokenSubmitPageGeneratingWebFilter();

	@Test
	void filterWhenTokenQueryParamThenShouldIncludeJavascriptToAutoSubmitFormAndInputHasTokenValue() {
		MockServerWebExchange exchange = MockServerWebExchange
			.from(MockServerHttpRequest.get("/login/ott").queryParam("token", "test"));

		this.filter.filter(exchange, (e) -> Mono.empty()).block();

		assertThat(exchange.getResponse().getBodyAsString().block()).contains(
				"<input type=\"text\" id=\"token\" name=\"token\" value=\"test\" placeholder=\"Token\" required=\"true\" autofocus=\"autofocus\"/>");
	}

	@Test
	void setRequestMatcherWhenNullThenException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.filter.setRequestMatcher(null));
	}

	@Test
	void setLoginProcessingUrlWhenNullOrEmptyThenException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.filter.setLoginProcessingUrl(null));
		assertThatIllegalArgumentException().isThrownBy(() -> this.filter.setLoginProcessingUrl(""));
	}

	@Test
	void setLoginProcessingUrlThenUseItForFormAction() {
		this.filter.setLoginProcessingUrl("/login/another");

		MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/login/ott"));

		this.filter.filter(exchange, (e) -> Mono.empty()).block();

		assertThat(exchange.getResponse().getBodyAsString().block())
			.contains("<form class=\"login-form\" action=\"/login/another\" method=\"post\">");
	}

	@Test
	void setContextThenGenerates() {
		MockServerWebExchange exchange = MockServerWebExchange
			.from(MockServerHttpRequest.get("/test/login/ott").contextPath("/test"));
		this.filter.setLoginProcessingUrl("/login/another");

		this.filter.filter(exchange, (e) -> Mono.empty()).block();

		assertThat(exchange.getResponse().getBodyAsString().block())
			.contains("<form class=\"login-form\" action=\"/test/login/another\" method=\"post\">");
	}

	@Test
	void filterWhenTokenQueryParamUsesSpecialCharactersThenValueIsEscaped() {
		MockServerWebExchange exchange = MockServerWebExchange
			.from(MockServerHttpRequest.get("/login/ott").queryParam("token", "this<>!@#\""));

		this.filter.filter(exchange, (e) -> Mono.empty()).block();

		assertThat(exchange.getResponse().getBodyAsString().block()).contains(
				"<input type=\"text\" id=\"token\" name=\"token\" value=\"this&lt;&gt;!@#&quot;\" placeholder=\"Token\" required=\"true\" autofocus=\"autofocus\"/>");
	}

	@Test
	void filterThenRenders() {
		MockServerWebExchange exchange = MockServerWebExchange
			.from(MockServerHttpRequest.get("/login/ott").queryParam("token", "this<>!@#\""));
		this.filter.setLoginProcessingUrl("/login/another");

		this.filter.filter(exchange, (e) -> Mono.empty()).block();

		assertThat(exchange.getResponse().getBodyAsString().block()).isEqualTo(
				"""
						<!DOCTYPE html>
						<html lang="en">
						  <head>
						    <title>One-Time Token Login</title>
						    <meta charset="utf-8"/>
						    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no"/>
						    <link href="/default-ui.css" rel="stylesheet" />
						  </head>
						  <body>
						    <div class="container">
						      <form class="login-form" action="/login/another" method="post">
						        <h2>Please input the token</h2>
						        <p>
						          <label for="token" class="screenreader">Token</label>
						          <input type="text" id="token" name="token" value="this&lt;&gt;!@#&quot;" placeholder="Token" required="true" autofocus="autofocus"/>
						        </p>

						        <button class="primary" type="submit">Sign in</button>
						      </form>
						    </div>
						  </body>
						</html>
						""");
	}

}
