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

import java.time.Instant;

import org.junit.jupiter.api.Test;

import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.authentication.ott.DefaultOneTimeToken;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link ServerRedirectGeneratedOneTimeTokenHandler}
 *
 * @author Max Batischev
 */
public class ServerRedirectGeneratedOneTimeTokenHandlerTests {

	private static final String TOKEN = "token";

	private static final String USERNAME = "Max";

	private final MockServerHttpRequest request = MockServerHttpRequest.get("/").build();

	@Test
	void handleThenRedirectToDefaultLocation() {
		ServerGeneratedOneTimeTokenHandler handler = new ServerRedirectGeneratedOneTimeTokenHandler("/login/ott");
		MockServerWebExchange webExchange = MockServerWebExchange.from(this.request);

		handler.handle(webExchange, new DefaultOneTimeToken(TOKEN, USERNAME, Instant.now())).block();

		assertThat(webExchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.FOUND);
		assertThat(webExchange.getResponse().getHeaders().getLocation()).hasPath("/login/ott");
	}

	@Test
	void handleWhenUrlChangedThenRedirectToUrl() {
		ServerGeneratedOneTimeTokenHandler handler = new ServerRedirectGeneratedOneTimeTokenHandler("/redirected");
		MockServerWebExchange webExchange = MockServerWebExchange.from(this.request);

		handler.handle(webExchange, new DefaultOneTimeToken(TOKEN, USERNAME, Instant.now())).block();

		assertThat(webExchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.FOUND);
		assertThat(webExchange.getResponse().getHeaders().getLocation()).hasPath("/redirected");
	}

	@Test
	void setRedirectUrlWhenNullOrEmptyThenException() {
		assertThatIllegalArgumentException().isThrownBy(() -> new ServerRedirectGeneratedOneTimeTokenHandler(null))
			.withMessage("redirectUri cannot be empty or null");
		assertThatIllegalArgumentException().isThrownBy(() -> new ServerRedirectGeneratedOneTimeTokenHandler(""))
			.withMessage("redirectUri cannot be empty or null");
	}

}
