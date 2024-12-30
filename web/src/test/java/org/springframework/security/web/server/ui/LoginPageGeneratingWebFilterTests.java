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

package org.springframework.security.web.server.ui;

import java.util.Collections;

import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;

import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;

import static org.assertj.core.api.Assertions.assertThat;

public class LoginPageGeneratingWebFilterTests {

	@Test
	public void filterWhenLoginWithContextPathThenActionContainsContextPath() throws Exception {
		LoginPageGeneratingWebFilter filter = new LoginPageGeneratingWebFilter();
		filter.setFormLoginEnabled(true);
		MockServerWebExchange exchange = MockServerWebExchange
			.from(MockServerHttpRequest.get("/test/login").contextPath("/test"));
		filter.filter(exchange, (e) -> Mono.empty()).block();
		assertThat(exchange.getResponse().getBodyAsString().block()).contains("action=\"/test/login\"");
	}

	@Test
	public void filterWhenLoginWithNoContextPathThenActionDoesNotContainsContextPath() throws Exception {
		LoginPageGeneratingWebFilter filter = new LoginPageGeneratingWebFilter();
		filter.setFormLoginEnabled(true);
		MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/login"));
		filter.filter(exchange, (e) -> Mono.empty()).block();
		assertThat(exchange.getResponse().getBodyAsString().block()).contains("action=\"/login\"");
	}

	@Test
	void filtersThenRendersPage() {
		String clientName = "Google < > \" \' &";
		LoginPageGeneratingWebFilter filter = new LoginPageGeneratingWebFilter();
		filter.setOauth2AuthenticationUrlToClientName(
				Collections.singletonMap("/oauth2/authorization/google", clientName));
		filter.setFormLoginEnabled(true);
		MockServerWebExchange exchange = MockServerWebExchange
			.from(MockServerHttpRequest.get("/test/login").contextPath("/test"));
		filter.filter(exchange, (e) -> Mono.empty()).block();
		assertThat(exchange.getResponse().getBodyAsString().block()).isEqualTo("""
				<!DOCTYPE html>
				<html lang="en">
				  <head>
				    <meta charset="utf-8">
				    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
				    <meta name="description" content="">
				    <meta name="author" content="">
				    <title>Please sign in</title>
				    <link href="/test/default-ui.css" rel="stylesheet" />
				  </head>
				  <body>
				    <div class="content">
				      <form class="login-form" method="post" action="/test/login">
				        <h2>Please sign in</h2>

				        <p>
				          <label for="username" class="screenreader">Username</label>
				          <input type="text" id="username" name="username" placeholder="Username" required autofocus>
				        </p>
				        <p>
				          <label for="password" class="screenreader">Password</label>
				          <input type="password" id="password" name="password" placeholder="Password" required>
				        </p>

				        <button type="submit" class="primary">Sign in</button>
				      </form>

				<h2>Login with OAuth 2.0</h2>

				<table class="table table-striped">
				  <tr><td><a href="/test/oauth2/authorization/google">Google &lt; &gt; &quot; &#39; &amp;</a></td></tr>
				</table>
				    </div>
				  </body>
				</html>""");
	}

	@Test
	public void filterWhenOneTimeTokenLoginThenOttForm() {
		LoginPageGeneratingWebFilter filter = new LoginPageGeneratingWebFilter();
		filter.setOneTimeTokenEnabled(true);
		filter.setGenerateOneTimeTokenUrl("/ott/authenticate");
		filter.setFormLoginEnabled(true);
		MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/login"));

		filter.filter(exchange, (e) -> Mono.empty()).block();

		assertThat(exchange.getResponse().getBodyAsString().block()).contains("Request a One-Time Token");
		assertThat(exchange.getResponse().getBodyAsString().block()).contains("""
				 <form id="ott-form" class="login-form" method="post" action="/ott/authenticate">
				""");
	}

}
