/*
 * Copyright 2002-2023 the original author or authors.
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

import java.io.IOException;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockServletContext;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

import static org.assertj.core.api.Assertions.assertThat;

public class FormRedirectStrategyTests {

	private FormRedirectStrategy formRedirectStrategy;

	private MockHttpServletRequest request;

	private MockHttpServletResponse response;

	@BeforeEach
	public void beforeEach() {
		this.formRedirectStrategy = new FormRedirectStrategy();
		final MockServletContext mockServletContext = new MockServletContext();
		mockServletContext.setContextPath("/contextPath");
		// the request URL doesn't matter
		this.request = MockMvcRequestBuilders.get("https://localhost").buildRequest(mockServletContext);
		this.response = new MockHttpServletResponse();
	}

	@Test
	public void absoluteUrlNoParametersRedirect() throws IOException {
		this.formRedirectStrategy.sendRedirect(this.request, this.response, "https://example.com");
		assertThat(this.response.getStatus()).isEqualTo(HttpStatus.OK.value());
		assertThat(this.response.getContentType()).isEqualTo(MediaType.TEXT_HTML_VALUE);
		assertThat(this.response.getContentAsString()).contains("action=\"https://example.com\"");
	}

	@Test
	public void rootRelativeUrlNoParametersRedirect() throws IOException {
		this.formRedirectStrategy.sendRedirect(this.request, this.response, "/test");
		assertThat(this.response.getStatus()).isEqualTo(HttpStatus.OK.value());
		assertThat(this.response.getContentType()).isEqualTo(MediaType.TEXT_HTML_VALUE);
		assertThat(this.response.getContentAsString()).contains("action=\"/test\"");
	}

	@Test
	public void relativeUrlNoParametersRedirect() throws IOException {
		this.formRedirectStrategy.sendRedirect(this.request, this.response, "test");
		assertThat(this.response.getStatus()).isEqualTo(HttpStatus.OK.value());
		assertThat(this.response.getContentType()).isEqualTo(MediaType.TEXT_HTML_VALUE);
		assertThat(this.response.getContentAsString()).contains("action=\"test\"");
	}

	@Test
	public void absoluteUrlWithFragmentRedirect() throws IOException {
		this.formRedirectStrategy.sendRedirect(this.request, this.response, "https://example.com/path#fragment");
		assertThat(this.response.getStatus()).isEqualTo(HttpStatus.OK.value());
		assertThat(this.response.getContentType()).isEqualTo(MediaType.TEXT_HTML_VALUE);
		assertThat(this.response.getContentAsString()).contains("action=\"https://example.com/path#fragment\"");
	}

	@Test
	public void absoluteUrlWithQueryParamsRedirect() throws IOException {
		this.formRedirectStrategy.sendRedirect(this.request, this.response,
				"https://example.com/path?param1=one&param2=two#fragment");
		assertThat(this.response.getStatus()).isEqualTo(HttpStatus.OK.value());
		assertThat(this.response.getContentType()).isEqualTo(MediaType.TEXT_HTML_VALUE);
		assertThat(this.response.getContentAsString()).contains("action=\"https://example.com/path#fragment\"");
		assertThat(this.response.getContentAsString())
			.contains("<input name=\"param1\" type=\"hidden\" value=\"one\" />");
		assertThat(this.response.getContentAsString())
			.contains("<input name=\"param2\" type=\"hidden\" value=\"two\" />");
	}

}
