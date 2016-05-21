/*
 * Copyright 2002-2014 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.test.web.servlet.request;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultMatcher;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.filter.OncePerRequestFilter;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration
@WebAppConfiguration
public class SecurityMockMvcRequestPostProcessorsCsrfTests {
	@Autowired
	WebApplicationContext wac;

	MockMvc mockMvc;

	@Before
	public void setup() {
		mockMvc = MockMvcBuilders
				.webAppContextSetup(wac)
				.apply(springSecurity())
				.build();
	}

	@Test
	public void csrfWithParam() throws Exception {
		mockMvc.perform(post("/").with(csrf()))
			.andExpect(status().is2xxSuccessful())
			.andExpect(csrfAsParam());
	}

	@Test
	public void csrfWithHeader() throws Exception {
		mockMvc.perform(post("/").with(csrf().asHeader()))
			.andExpect(status().is2xxSuccessful())
			.andExpect(csrfAsHeader());
	}

	@Test
	public void csrfWithInvalidParam() throws Exception {
		mockMvc.perform(post("/").with(csrf().useInvalidToken()))
				.andExpect(status().isForbidden())
				.andExpect(csrfAsParam());
	}

	@Test
	public void csrfWithInvalidHeader() throws Exception {
		mockMvc.perform(post("/").with(csrf().asHeader().useInvalidToken()))
			.andExpect(status().isForbidden())
			.andExpect(csrfAsHeader());
	}

	// SEC-3097
	@Test
	public void csrfWithWrappedRequest() throws Exception {
		mockMvc = MockMvcBuilders
				.webAppContextSetup(wac)
				.addFilter(new SessionRepositoryFilter())
				.apply(springSecurity())
				.build();

		mockMvc.perform(post("/").with(csrf()))
				.andExpect(status().is2xxSuccessful())
				.andExpect(csrfAsParam());
	}

	public static ResultMatcher csrfAsParam() {
		return new CsrfParamResultMatcher();
	}

	static class CsrfParamResultMatcher implements ResultMatcher {

		public void match(MvcResult result) throws Exception {
			MockHttpServletRequest request = result.getRequest();
			assertThat(request.getParameter("_csrf")).isNotNull();
			assertThat(request.getHeader("X-CSRF-TOKEN")).isNull();
		}
	}

	public static ResultMatcher csrfAsHeader() {
		return new CsrfHeaderResultMatcher();
	}

	static class CsrfHeaderResultMatcher implements ResultMatcher {

		public void match(MvcResult result) throws Exception {
			MockHttpServletRequest request = result.getRequest();
			assertThat(request.getParameter("_csrf")).isNull();
			assertThat(request.getHeader("X-CSRF-TOKEN")).isNotNull();
		}
	}

	static class SessionRepositoryFilter extends OncePerRequestFilter {

		@Override
		protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
				throws ServletException, IOException {
			filterChain.doFilter(new SessionRequestWrapper(request) , response);
		}

		static class SessionRequestWrapper extends HttpServletRequestWrapper {
			HttpSession session = new MockHttpSession();

			public SessionRequestWrapper(HttpServletRequest request) {
				super(request);
			}

			@Override
			public HttpSession getSession(boolean create) {
				return session;
			}

			@Override
			public HttpSession getSession() {
				return session;
			}
		}
	}

	@EnableWebSecurity
	static class Config extends WebSecurityConfigurerAdapter {
		@Override
		protected void configure(HttpSecurity http) throws Exception {
		}

		@Bean
		public TheController controller() {
			return new TheController();
		}

		@RestController
		static class TheController {
			@RequestMapping("/")
			String index() {
				return "Hi";
			}
		}
	}
}
