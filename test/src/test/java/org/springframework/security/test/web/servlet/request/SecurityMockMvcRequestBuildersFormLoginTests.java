/*
 * Copyright 2002-2014 the original author or authors.
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
package org.springframework.security.test.web.servlet.request;

import org.junit.Before;
import org.junit.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.CsrfRequestPostProcessor;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.request.RequestPostProcessor;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;

public class SecurityMockMvcRequestBuildersFormLoginTests {

	private MockServletContext servletContext;

	@Before
	public void setup() {
		this.servletContext = new MockServletContext();
	}

	@Test
	public void defaults() {
		MockHttpServletRequest request = formLogin().buildRequest(this.servletContext);
		CsrfToken token = (CsrfToken) request
				.getAttribute(CsrfRequestPostProcessor.TestCsrfTokenRepository.TOKEN_ATTR_NAME);

		assertThat(request.getParameter("username")).isEqualTo("user");
		assertThat(request.getParameter("password")).isEqualTo("password");
		assertThat(request.getMethod()).isEqualTo("POST");
		assertThat(request.getParameter(token.getParameterName())).isEqualTo(token.getToken());
		assertThat(request.getRequestURI()).isEqualTo("/login");
		assertThat(request.getParameter("_csrf")).isNotNull();
	}

	@Test
	public void custom() {
		MockHttpServletRequest request = formLogin("/login").user("username", "admin").password("password", "secret")
				.buildRequest(this.servletContext);

		CsrfToken token = (CsrfToken) request
				.getAttribute(CsrfRequestPostProcessor.TestCsrfTokenRepository.TOKEN_ATTR_NAME);

		assertThat(request.getParameter("username")).isEqualTo("admin");
		assertThat(request.getParameter("password")).isEqualTo("secret");
		assertThat(request.getMethod()).isEqualTo("POST");
		assertThat(request.getParameter(token.getParameterName())).isEqualTo(token.getToken());
		assertThat(request.getRequestURI()).isEqualTo("/login");
	}

	@Test
	public void customWithUriVars() {
		MockHttpServletRequest request = formLogin().loginProcessingUrl("/uri-login/{var1}/{var2}", "val1", "val2")
				.user("username", "admin").password("password", "secret").buildRequest(this.servletContext);

		CsrfToken token = (CsrfToken) request
				.getAttribute(CsrfRequestPostProcessor.TestCsrfTokenRepository.TOKEN_ATTR_NAME);

		assertThat(request.getParameter("username")).isEqualTo("admin");
		assertThat(request.getParameter("password")).isEqualTo("secret");
		assertThat(request.getMethod()).isEqualTo("POST");
		assertThat(request.getParameter(token.getParameterName())).isEqualTo(token.getToken());
		assertThat(request.getRequestURI()).isEqualTo("/uri-login/val1/val2");
	}

	/**
	 * spring-restdocs uses postprocessors to do its trick. It will work only if these are
	 * merged together with our request builders. (gh-7572)
	 * @throws Exception
	 */
	@Test
	public void postProcessorsAreMergedDuringMockMvcPerform() throws Exception {
		RequestPostProcessor postProcessor = mock(RequestPostProcessor.class);
		when(postProcessor.postProcessRequest(any())).thenAnswer(i -> i.getArgument(0));
		MockMvc mockMvc = MockMvcBuilders.standaloneSetup(new Object())
				.defaultRequest(MockMvcRequestBuilders.get("/").with(postProcessor)).build();

		MvcResult mvcResult = mockMvc.perform(formLogin()).andReturn();
		assertThat(mvcResult.getRequest().getMethod()).isEqualTo(HttpMethod.POST.name());
		assertThat(mvcResult.getRequest().getHeader("Accept"))
				.isEqualTo(MediaType.toString(Arrays.asList(MediaType.APPLICATION_FORM_URLENCODED)));
		assertThat(mvcResult.getRequest().getParameter("username")).isEqualTo("user");
		assertThat(mvcResult.getRequest().getParameter("password")).isEqualTo("password");
		assertThat(mvcResult.getRequest().getRequestURI()).isEqualTo("/login");
		assertThat(mvcResult.getRequest().getParameter("_csrf")).isNotEmpty();
		verify(postProcessor).postProcessRequest(any());
	}

	// gh-3920
	@Test
	public void usesAcceptMediaForContentNegotiation() {
		MockHttpServletRequest request = formLogin("/login").user("username", "admin").password("password", "secret")
				.buildRequest(this.servletContext);

		assertThat(request.getHeader("Accept")).isEqualTo(MediaType.APPLICATION_FORM_URLENCODED_VALUE);
	}

}
