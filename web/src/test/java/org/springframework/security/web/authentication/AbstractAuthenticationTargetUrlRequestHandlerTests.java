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

package org.springframework.security.web.authentication;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Dayan Kodippily
 */
public class AbstractAuthenticationTargetUrlRequestHandlerTests {

	public static final String REQUEST_URI = "https://example.org";

	public static final String DEFAULT_TARGET_URL = "/defaultTarget";

	public static final String REFERER_URL = "https://www.springsource.com/";

	public static final String TARGET_URL = "https://example.org/target";

	private MockHttpServletRequest request;

	private MockHttpServletResponse response;

	private AbstractAuthenticationTargetUrlRequestHandler handler;

	@BeforeEach
	void setUp() {
		this.request = new MockHttpServletRequest();
		this.response = new MockHttpServletResponse();
		this.handler = new AbstractAuthenticationTargetUrlRequestHandler() {
			@Override
			protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response) {
				return super.determineTargetUrl(request, response);
			}
		};
		this.handler.setDefaultTargetUrl(DEFAULT_TARGET_URL);
		this.request.setRequestURI(REQUEST_URI);
	}

	@Test
	void returnDefaultTargetUrlIfUseDefaultTargetUrlTrue() {
		this.handler.setAlwaysUseDefaultTargetUrl(true);
		assertThat(this.handler.determineTargetUrl(this.request, this.response)).isEqualTo(DEFAULT_TARGET_URL);
	}

	@Test
	void returnTargetUrlParamValueIfParamHasValue() {
		this.handler.setTargetUrlParameter("param");
		this.request.setParameter("param", TARGET_URL);
		assertThat(this.handler.determineTargetUrl(this.request, this.response)).isEqualTo(TARGET_URL);
	}

	@Test
	void targetUrlParamValueTakePrecedenceOverRefererIfParamHasValue() {
		this.handler.setUseReferer(true);
		this.handler.setTargetUrlParameter("param");
		this.request.setParameter("param", TARGET_URL);
		assertThat(this.handler.determineTargetUrl(this.request, this.response)).isEqualTo(TARGET_URL);
	}

	@Test
	void returnDefaultTargetUrlIfTargetUrlParamHasNoValue() {
		this.handler.setTargetUrlParameter("param");
		this.request.setParameter("param", "");
		assertThat(this.handler.determineTargetUrl(this.request, this.response)).isEqualTo(DEFAULT_TARGET_URL);
	}

	@Test
	void returnDefaultTargetUrlIfTargetUrlParamHasNoValueContainsOnlyWhiteSpaces() {
		this.handler.setTargetUrlParameter("param");
		this.request.setParameter("param", "   ");
		assertThat(this.handler.determineTargetUrl(this.request, this.response)).isEqualTo(DEFAULT_TARGET_URL);
	}

	@Test
	void returnRefererUrlIfUseRefererIsTrue() {
		this.handler.setUseReferer(true);
		this.request.addHeader("Referer", REFERER_URL);
		assertThat(this.handler.determineTargetUrl(this.request, this.response)).isEqualTo(REFERER_URL);
	}

	@Test
	void returnDefaultTargetUrlIfUseRefererIsFalse() {
		this.handler.setUseReferer(false);
		this.request.addHeader("Referer", REFERER_URL);
		assertThat(this.handler.determineTargetUrl(this.request, this.response)).isEqualTo(DEFAULT_TARGET_URL);
	}

}
