/*
 * Copyright 2002-2018 the original author or authors.
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
package org.springframework.security.config.http;

import org.apache.http.HttpStatus;
import org.junit.Rule;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.test.web.servlet.MockMvc;

import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 *
 * @author Rob Winch
 * @author Josh Cummings
 */
public class HttpConfigTests {

	private static final String CONFIG_LOCATION_PREFIX =
			"classpath:org/springframework/security/config/http/HttpConfigTests";

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Autowired
	MockMvc mvc;

	@Test
	public void getWhenUsingMinimalConfigurationThenRedirectsToLogin()
		throws Exception {

		this.spring.configLocations(this.xml("Minimal")).autowire();

		this.mvc.perform(get("/"))
				.andExpect(status().isFound())
				.andExpect(redirectedUrl("http://localhost/login"));
	}

	@Test
	public void getWhenUsingMinimalConfigurationThenPreventsSessionAsUrlParameter()
		throws Exception {

		this.spring.configLocations(this.xml("Minimal")).autowire();

		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/");
		MockHttpServletResponse response = new MockHttpServletResponse();

		FilterChainProxy proxy = this.spring.getContext().getBean(FilterChainProxy.class);

		proxy.doFilter(
				request,
				new EncodeUrlDenyingHttpServletResponseWrapper(response),
				(req, resp) -> {});

		assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_MOVED_TEMPORARILY);
		assertThat(response.getRedirectedUrl()).isEqualTo("http://localhost/login");
	}

	private static class EncodeUrlDenyingHttpServletResponseWrapper
			extends HttpServletResponseWrapper {

		EncodeUrlDenyingHttpServletResponseWrapper(HttpServletResponse response) {
			super(response);
		}

		@Override
		public String encodeURL(String url) {
			throw new RuntimeException("Unexpected invocation of encodeURL");
		}

		@Override
		public String encodeRedirectURL(String url) {
			throw new RuntimeException("Unexpected invocation of encodeURL");
		}

		@Override
		public String encodeUrl(String url) {
			throw new RuntimeException("Unexpected invocation of encodeURL");
		}

		@Override
		public String encodeRedirectUrl(String url) {
			throw new RuntimeException("Unexpected invocation of encodeURL");
		}
	}

	private String xml(String configName) {
		return CONFIG_LOCATION_PREFIX + "-" + configName + ".xml";
	}
}
