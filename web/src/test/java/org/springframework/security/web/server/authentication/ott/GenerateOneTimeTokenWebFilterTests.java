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

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatchers;
import reactor.core.publisher.Mono;

import org.springframework.http.MediaType;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.authentication.ott.DefaultOneTimeToken;
import org.springframework.security.authentication.ott.GenerateOneTimeTokenRequest;
import org.springframework.security.authentication.ott.reactive.ReactiveOneTimeTokenService;

import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

/**
 * Tests for {@link GenerateOneTimeTokenWebFilter}
 *
 * @author Max Batischev
 */
public class GenerateOneTimeTokenWebFilterTests {

	private final ReactiveOneTimeTokenService oneTimeTokenService = mock(ReactiveOneTimeTokenService.class);

	private final ServerRedirectOneTimeTokenGenerationSuccessHandler oneTimeTokenGenerationSuccessHandler = new ServerRedirectOneTimeTokenGenerationSuccessHandler(
			"/login/ott");

	private static final String TOKEN = "token";

	private static final String USERNAME = "user";

	@Test
	void filterWhenUsernameFormParamIsPresentThenSuccess() {
		given(this.oneTimeTokenService.generate(ArgumentMatchers.any(GenerateOneTimeTokenRequest.class)))
			.willReturn(Mono.just(new DefaultOneTimeToken(TOKEN, USERNAME, Instant.now())));
		MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.post("/ott/generate")
			.contentType(MediaType.APPLICATION_FORM_URLENCODED)
			.body("username=user"));
		GenerateOneTimeTokenWebFilter filter = new GenerateOneTimeTokenWebFilter(this.oneTimeTokenService,
				this.oneTimeTokenGenerationSuccessHandler);

		filter.filter(exchange, (e) -> Mono.empty()).block();

		verify(this.oneTimeTokenService).generate(ArgumentMatchers.any(GenerateOneTimeTokenRequest.class));
		Assertions.assertThat(exchange.getResponse().getHeaders().getLocation()).hasPath("/login/ott");
	}

	@Test
	void filterWhenUsernameFormParamIsEmptyThenNull() {
		given(this.oneTimeTokenService.generate(ArgumentMatchers.any(GenerateOneTimeTokenRequest.class)))
			.willReturn(Mono.just(new DefaultOneTimeToken(TOKEN, USERNAME, Instant.now())));
		MockServerHttpRequest.BaseBuilder<?> request = MockServerHttpRequest.post("/ott/generate");
		MockServerWebExchange exchange = MockServerWebExchange.from(request);
		GenerateOneTimeTokenWebFilter filter = new GenerateOneTimeTokenWebFilter(this.oneTimeTokenService,
				this.oneTimeTokenGenerationSuccessHandler);

		filter.filter(exchange, (e) -> Mono.empty()).block();

		verify(this.oneTimeTokenService, never()).generate(ArgumentMatchers.any(GenerateOneTimeTokenRequest.class));
	}

	@Test
	public void constructorWhenOneTimeTokenServiceNullThenIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new GenerateOneTimeTokenWebFilter(null, this.oneTimeTokenGenerationSuccessHandler));
		// @formatter:on
	}

	@Test
	public void setWhenRequestMatcherNullThenIllegalArgumentException() {
		GenerateOneTimeTokenWebFilter filter = new GenerateOneTimeTokenWebFilter(this.oneTimeTokenService,
				this.oneTimeTokenGenerationSuccessHandler);
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> filter.setRequestMatcher(null));
		// @formatter:on
	}

}
