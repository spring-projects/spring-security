/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.web.server.authentication.ott;

import java.time.Duration;

import org.junit.jupiter.api.Test;

import org.springframework.http.MediaType;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.authentication.ott.GenerateOneTimeTokenRequest;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link DefaultServerGenerateOneTimeTokenRequestResolver}
 *
 * @author Max Batischev
 */
public class DefaultServerGenerateOneTimeTokenRequestResolverTests {

	private final DefaultServerGenerateOneTimeTokenRequestResolver resolver = new DefaultServerGenerateOneTimeTokenRequestResolver();

	@Test
	void resolveWhenUsernameParameterIsPresentThenResolvesGenerateRequest() {
		MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.post("/ott/generate")
			.contentType(MediaType.APPLICATION_FORM_URLENCODED)
			.body("username=user"));

		GenerateOneTimeTokenRequest request = this.resolver.resolve(exchange).block();

		assertThat(request).isNotNull();
		assertThat(request.getUsername()).isEqualTo("user");
		assertThat(request.getExpiresIn()).isEqualTo(Duration.ofMinutes(5));
	}

	@Test
	void resolveWhenUsernameParameterIsNotPresentThenNull() {
		MockServerWebExchange exchange = MockServerWebExchange
			.from(MockServerHttpRequest.post("/ott/generate").contentType(MediaType.APPLICATION_FORM_URLENCODED));

		GenerateOneTimeTokenRequest request = this.resolver.resolve(exchange).block();

		assertThat(request).isNull();
	}

	@Test
	void resolveWhenExpiresInSetThenResolvesGenerateRequest() {
		MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.post("/ott/generate")
			.contentType(MediaType.APPLICATION_FORM_URLENCODED)
			.body("username=user"));
		this.resolver.setExpiresIn(Duration.ofSeconds(600));

		GenerateOneTimeTokenRequest generateRequest = this.resolver.resolve(exchange).block();

		assertThat(generateRequest.getExpiresIn()).isEqualTo(Duration.ofSeconds(600));
	}

	@Test
	void resolveWhenTokenValueFactorySetThenResolvesGenerateRequest() {
		MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.post("/ott/generate")
			.contentType(MediaType.APPLICATION_FORM_URLENCODED)
			.body("username=user"));
		this.resolver.setTokenValueFactory(() -> "tokenValue");

		GenerateOneTimeTokenRequest generateRequest = this.resolver.resolve(exchange).block();

		assertThat(generateRequest.getTokenValue()).isEqualTo("tokenValue");
	}

}
