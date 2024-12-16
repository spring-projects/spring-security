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

package org.springframework.security.web.server.authentication.ott;

import org.junit.jupiter.api.Test;

import org.springframework.http.MediaType;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.authentication.ott.OneTimeTokenAuthenticationToken;
import org.springframework.security.core.Authentication;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link ServerOneTimeTokenAuthenticationConverter}
 *
 * @author Max Batischev
 */
public class ServerOneTimeTokenAuthenticationConverterTests {

	private final ServerOneTimeTokenAuthenticationConverter converter = new ServerOneTimeTokenAuthenticationConverter();

	private static final String TOKEN = "token";

	private static final String USERNAME = "Max";

	@Test
	void convertWhenTokenParameterThenReturnOneTimeTokenAuthenticationToken() {
		MockServerHttpRequest.BaseBuilder<?> request = MockServerHttpRequest.get("/").queryParam("token", TOKEN);

		OneTimeTokenAuthenticationToken authentication = (OneTimeTokenAuthenticationToken) this.converter
			.convert(MockServerWebExchange.from(request))
			.block();

		assertThat(authentication).isNotNull();
		assertThat(authentication.getTokenValue()).isEqualTo(TOKEN);
		assertThat(authentication.getPrincipal()).isNull();
	}

	@Test
	void convertWhenOnlyUsernameParameterThenReturnNull() {
		MockServerHttpRequest.BaseBuilder<?> request = MockServerHttpRequest.get("/").queryParam("username", USERNAME);

		OneTimeTokenAuthenticationToken authentication = (OneTimeTokenAuthenticationToken) this.converter
			.convert(MockServerWebExchange.from(request))
			.block();

		assertThat(authentication).isNull();
	}

	@Test
	void convertWhenNoTokenParameterThenNull() {
		MockServerHttpRequest.BaseBuilder<?> request = MockServerHttpRequest.get("/");

		Authentication authentication = this.converter.convert(MockServerWebExchange.from(request)).block();

		assertThat(authentication).isNull();
	}

	@Test
	void convertWhenTokenEncodedFormParameterThenReturnOneTimeTokenAuthenticationToken() {
		// @formatter:off
		MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.post("/")
				.contentType(MediaType.APPLICATION_FORM_URLENCODED)
				.body("token=token"));

		// @formatter:on

		OneTimeTokenAuthenticationToken authentication = (OneTimeTokenAuthenticationToken) this.converter
			.convert(exchange)
			.block();

		assertThat(authentication).isNotNull();
		assertThat(authentication.getTokenValue()).isEqualTo(TOKEN);
		assertThat(authentication.getPrincipal()).isNull();
	}

}
