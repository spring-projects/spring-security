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

import org.junit.Test;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import reactor.core.publisher.Mono;

import static org.assertj.core.api.Assertions.assertThat;


public class LoginPageGeneratingWebFilterTests {

	@Test
	public void filterWhenLoginWithContextPathThenActionContainsContextPath() throws Exception {
		LoginPageGeneratingWebFilter filter = new LoginPageGeneratingWebFilter();
		filter.setFormLoginEnabled(true);

		MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/test/login").contextPath("/test"));

		filter.filter(exchange, e -> Mono.empty()).block();

		assertThat(exchange.getResponse().getBodyAsString().block()).contains("action=\"/test/login\"");
	}

	@Test
	public void filterWhenLoginWithNoContextPathThenActionDoesNotContainsContextPath() throws Exception {
		LoginPageGeneratingWebFilter filter = new LoginPageGeneratingWebFilter();
		filter.setFormLoginEnabled(true);

		MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/login"));

		filter.filter(exchange, e -> Mono.empty()).block();

		assertThat(exchange.getResponse().getBodyAsString().block()).contains("action=\"/login\"");
	}
}
