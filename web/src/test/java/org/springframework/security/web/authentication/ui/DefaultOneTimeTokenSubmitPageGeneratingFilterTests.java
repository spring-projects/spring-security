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

package org.springframework.security.web.authentication.ui;

import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link DefaultOneTimeTokenSubmitPageGeneratingFilter}
 *
 * @author Marcus da Coregio
 */
class DefaultOneTimeTokenSubmitPageGeneratingFilterTests {

	DefaultOneTimeTokenSubmitPageGeneratingFilter filter = new DefaultOneTimeTokenSubmitPageGeneratingFilter();

	MockHttpServletRequest request = new MockHttpServletRequest();

	MockHttpServletResponse response = new MockHttpServletResponse();

	MockFilterChain filterChain = new MockFilterChain();

	@BeforeEach
	void setup() {
		this.request.setMethod("GET");
		this.request.setServletPath("/login/ott");
	}

	@Test
	void filterWhenTokenQueryParamThenShouldIncludeJavascriptToAutoSubmitFormAndInputHasTokenValue() throws Exception {
		this.request.setParameter("token", "1234");
		this.filter.doFilterInternal(this.request, this.response, this.filterChain);
		String response = this.response.getContentAsString();
		assertThat(response).contains(
				"<input type=\"text\" id=\"token\" name=\"token\" value=\"1234\" placeholder=\"Token\" required=\"true\" autofocus=\"autofocus\"/>");
	}

	@Test
	void setRequestMatcherWhenNullThenException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.filter.setRequestMatcher(null));
	}

	@Test
	void setLoginProcessingUrlWhenNullOrEmptyThenException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.filter.setLoginProcessingUrl(null));
		assertThatIllegalArgumentException().isThrownBy(() -> this.filter.setLoginProcessingUrl(""));
	}

	@Test
	void setLoginProcessingUrlThenUseItForFormAction() throws Exception {
		this.filter.setLoginProcessingUrl("/login/another");
		this.filter.doFilterInternal(this.request, this.response, this.filterChain);
		String response = this.response.getContentAsString();
		assertThat(response).contains("<form class=\"login-form\" action=\"/login/another\" method=\"post\">");
	}

	@Test
	void setContextThenGenerates() throws Exception {
		this.request.setContextPath("/context");
		this.filter.setLoginProcessingUrl("/login/another");
		this.filter.doFilterInternal(this.request, this.response, this.filterChain);
		String response = this.response.getContentAsString();
		assertThat(response).contains("<form class=\"login-form\" action=\"/context/login/another\" method=\"post\">");
	}

	@Test
	void filterWhenTokenQueryParamUsesSpecialCharactersThenValueIsEscaped() throws Exception {
		this.request.setParameter("token", "this<>!@#\"");
		this.filter.doFilterInternal(this.request, this.response, this.filterChain);
		String response = this.response.getContentAsString();
		assertThat(response).contains(
				"<input type=\"text\" id=\"token\" name=\"token\" value=\"this&lt;&gt;!@#&quot;\" placeholder=\"Token\" required=\"true\" autofocus=\"autofocus\"/>");
	}

	@Test
	void filterThenRenders() throws Exception {
		this.request.setParameter("token", "this<>!@#\"");
		this.filter.setLoginProcessingUrl("/login/another");
		this.filter.setResolveHiddenInputs((request) -> Map.of("_csrf", "csrf-token-value"));
		this.filter.doFilterInternal(this.request, this.response, this.filterChain);
		String response = this.response.getContentAsString();
		assertThat(response).isEqualTo(
				"""
						<!DOCTYPE html>
						<html lang="en">
						  <head>
						    <title>One-Time Token Login</title>
						    <meta charset="utf-8"/>
						    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no"/>
						    <link href="/default-ui.css" rel="stylesheet" />
						  </head>
						  <body>
						    <div class="container">
						      <form class="login-form" action="/login/another" method="post">
						        <h2>Please input the token</h2>
						        <p>
						          <label for="token" class="screenreader">Token</label>
						          <input type="text" id="token" name="token" value="this&lt;&gt;!@#&quot;" placeholder="Token" required="true" autofocus="autofocus"/>
						        </p>
						        <button class="primary" type="submit">Sign in</button>
						<input name="_csrf" type="hidden" value="csrf-token-value" />
						      </form>
						    </div>
						  </body>
						</html>
						""");
	}

}
