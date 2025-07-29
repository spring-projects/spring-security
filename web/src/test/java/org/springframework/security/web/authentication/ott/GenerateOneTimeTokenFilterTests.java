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

package org.springframework.security.web.authentication.ott;

import java.io.IOException;
import java.time.Instant;

import jakarta.servlet.ServletException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatchers;

import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.ott.DefaultOneTimeToken;
import org.springframework.security.authentication.ott.GenerateOneTimeTokenRequest;
import org.springframework.security.authentication.ott.OneTimeTokenService;
import org.springframework.security.web.server.authentication.ott.GenerateOneTimeTokenWebFilter;

import static org.assertj.core.api.Assertions.assertThat;
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
public class GenerateOneTimeTokenFilterTests {

	private final OneTimeTokenService oneTimeTokenService = mock(OneTimeTokenService.class);

	private final RedirectOneTimeTokenGenerationSuccessHandler successHandler = new RedirectOneTimeTokenGenerationSuccessHandler(
			"/login/ott");

	private static final String TOKEN = "token";

	private static final String USERNAME = "user";

	private final MockHttpServletRequest request = new MockHttpServletRequest();

	private final MockHttpServletResponse response = new MockHttpServletResponse();

	private final MockFilterChain filterChain = new MockFilterChain();

	@BeforeEach
	void setup() {
		this.request.setMethod("POST");
		this.request.setServletPath("/ott/generate");
		this.request.setRequestURI("/ott/generate");
	}

	@Test
	void filterWhenUsernameFormParamIsPresentThenSuccess() throws ServletException, IOException {
		given(this.oneTimeTokenService.generate(ArgumentMatchers.any(GenerateOneTimeTokenRequest.class)))
			.willReturn(new DefaultOneTimeToken(TOKEN, USERNAME, Instant.now()));
		this.request.setParameter("username", USERNAME);

		GenerateOneTimeTokenFilter filter = new GenerateOneTimeTokenFilter(this.oneTimeTokenService,
				this.successHandler);

		filter.doFilter(this.request, this.response, this.filterChain);

		verify(this.oneTimeTokenService).generate(ArgumentMatchers.any(GenerateOneTimeTokenRequest.class));
		assertThat(this.response.getRedirectedUrl()).isEqualTo("/login/ott");
	}

	@Test
	void filterWhenUsernameFormParamIsEmptyThenNull() throws ServletException, IOException {
		given(this.oneTimeTokenService.generate(ArgumentMatchers.any(GenerateOneTimeTokenRequest.class)))
			.willReturn((new DefaultOneTimeToken(TOKEN, USERNAME, Instant.now())));
		GenerateOneTimeTokenFilter filter = new GenerateOneTimeTokenFilter(this.oneTimeTokenService,
				this.successHandler);

		filter.doFilter(this.request, this.response, this.filterChain);

		verify(this.oneTimeTokenService, never()).generate(ArgumentMatchers.any(GenerateOneTimeTokenRequest.class));
	}

	@Test
	public void constructorWhenOneTimeTokenServiceNullThenIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new GenerateOneTimeTokenFilter(null, this.successHandler));
		// @formatter:on
	}

	@Test
	public void setWhenRequestMatcherNullThenIllegalArgumentException() {
		GenerateOneTimeTokenFilter filter = new GenerateOneTimeTokenFilter(this.oneTimeTokenService,
				this.successHandler);
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> filter.setRequestMatcher(null));
		// @formatter:on
	}

}
