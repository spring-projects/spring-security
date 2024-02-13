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

package org.springframework.security.config.web.server;

import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;

import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.web.server.ServerWebExchange;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link OidcBackChannelServerLogoutHandler}
 */
public class OidcBackChannelServerLogoutHandlerTests {

	// gh-14553
	@Test
	public void computeLogoutEndpointWhenDifferentHostnameThenLocalhost() {
		OidcBackChannelServerLogoutHandler logoutHandler = new OidcBackChannelServerLogoutHandler();
		MockServerHttpRequest request = MockServerHttpRequest
			.get("https://host.docker.internal:8090/back-channel/logout")
			.build();
		ServerWebExchange exchange = new MockServerWebExchange.Builder(request).build();
		String endpoint = logoutHandler.computeLogoutEndpoint(new WebFilterExchange(exchange, (ex) -> Mono.empty()));
		assertThat(endpoint).isEqualTo("https://localhost:8090/logout");
	}

}
