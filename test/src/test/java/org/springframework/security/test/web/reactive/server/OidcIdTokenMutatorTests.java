/*
 * Copyright 2002-2019 the original author or authors.
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
package org.springframework.security.test.web.reactive.server;

import static org.springframework.security.test.web.reactive.server.OAuth2SecurityMockServerConfigurers.mockOidcId;

import java.util.Collections;

import org.junit.Test;

/**
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 * @since 5.2
 */
public class OidcIdTokenMutatorTests {
// @formatter:off
	@Test
	public void testDefaultOidcIdTokenConfigurer() {
		TestController.clientBuilder().apply(mockOidcId()).build()
				.get().uri("/greet").exchange()
				.expectStatus().isOk()
				.expectBody().toString().equals("Hello user!");

		TestController.clientBuilder()
				.apply(mockOidcId()).build()
				.get().uri("/authorities").exchange()
				.expectStatus().isOk()
				.expectBody().toString().equals("[\"ROLE_USER\"]");
	}

	@Test
	public void testCustomOidcIdTokenConfigurer() {
		TestController.clientBuilder()
				.apply(mockOidcId().name("ch4mpy").claim("scope", Collections.singleton("message:read"))).build()
				.get().uri("/greet").exchange()
				.expectStatus().isOk()
				.expectBody().toString().equals("Hello ch4mpy!");

		TestController.clientBuilder()
				.apply(mockOidcId().name("ch4mpy").claim("scope", Collections.singleton("message:read"))).build()
				.get().uri("/authorities").exchange()
				.expectStatus().isOk()
				.expectBody().toString().equals("[\"SCOPE_message:read\"]");

		TestController.clientBuilder()
				.apply(mockOidcId().name("ch4mpy").claim("scope", Collections.singleton("message:read"))).build()
				.get().uri("/open-id").exchange()
				.expectStatus().isOk()
				.expectBody().toString().equals(
						"Hello,ch4mpy! You are sucessfully authenticated and granted with [message:read] scopes using a JavaWebToken.");
	}

	@Test
	public void testCustomOidcIdTokenMutator() {
		TestController.client()
				.mutateWith((mockOidcId().name("ch4mpy").claim("scope", Collections.singleton("message:read"))))
				.get().uri("/greet").exchange()
				.expectStatus().isOk()
				.expectBody().toString().equals("Hello ch4mpy!");

		TestController.client()
				.mutateWith((mockOidcId().name("ch4mpy").claim("scope", Collections.singleton("message:read"))))
				.get().uri("/authorities").exchange()
				.expectStatus().isOk()
				.expectBody().toString().equals("[\"SCOPE_message:read\"]");

		TestController.client()
				.mutateWith(mockOidcId().name("ch4mpy").claim("scope", Collections.singleton("message:read")))
				.get().uri("/open-id").exchange()
				.expectStatus().isOk()
				.expectBody().toString().equals(
						"Hello, ch4mpy! You are sucessfully authenticated and granted with [message:read] scopes using an OAuth2OidcIdToken.");
	}
// @formatter:on
}
