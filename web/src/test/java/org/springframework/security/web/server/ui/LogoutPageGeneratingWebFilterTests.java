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

package org.springframework.security.web.server.ui;

import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;

import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;

import static org.assertj.core.api.Assertions.assertThat;

public class LogoutPageGeneratingWebFilterTests {

	@Test
	public void filterWhenLogoutWithContextPathThenActionContainsContextPath() throws Exception {
		LogoutPageGeneratingWebFilter filter = new LogoutPageGeneratingWebFilter();
		MockServerWebExchange exchange = MockServerWebExchange
			.from(MockServerHttpRequest.get("/test/logout").contextPath("/test"));
		filter.filter(exchange, (e) -> Mono.empty()).block();
		assertThat(exchange.getResponse().getBodyAsString().block()).contains("action=\"/test/logout\"");
	}

	@Test
	public void filterWhenLogoutWithNoContextPathThenActionDoesNotContainsContextPath() throws Exception {
		LogoutPageGeneratingWebFilter filter = new LogoutPageGeneratingWebFilter();
		MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/logout"));
		filter.filter(exchange, (e) -> Mono.empty()).block();
		assertThat(exchange.getResponse().getBodyAsString().block()).contains("action=\"/logout\"");
	}

	@Test
	void filterThenRendersPage() {
		LogoutPageGeneratingWebFilter filter = new LogoutPageGeneratingWebFilter();
		MockServerWebExchange exchange = MockServerWebExchange
			.from(MockServerHttpRequest.get("/test/logout").contextPath("/test"));
		filter.filter(exchange, (e) -> Mono.empty()).block();
		assertThat(exchange.getResponse().getBodyAsString().block()).isEqualTo("""
				<!DOCTYPE html>
				<html lang="en">
				  <head>
				    <meta charset="utf-8">
				    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
				    <meta name="description" content="">
				    <meta name="author" content="">
				    <title>Confirm Log Out?</title>
				    <link href="/test/default-ui.css" rel="stylesheet" />
				  </head>
				  <body>
				    <div class="content">
				      <form class="logout-form" method="post" action="/test/logout">
				        <h2>Are you sure you want to log out?</h2>

				        <button class="primary" type="submit">Log Out</button>
				      </form>
				    </div>
				  </body>
				</html>""");
	}

}
