/*
 * Copyright 2002-2016 the original author or authors.
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
package org.springframework.security.config.annotation.web.configuration;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.DefaultCsrfToken;
import org.springframework.stereotype.Controller;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultMatcher;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

/**
 * @author Rob Winch
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration
@WebAppConfiguration
public class WebMvcSecurityConfigurationTests {

	@Autowired
	WebApplicationContext context;

	MockMvc mockMvc;

	Authentication authentication;

	@Before
	public void setup() {
		mockMvc = MockMvcBuilders.webAppContextSetup(context).build();
		authentication = new TestingAuthenticationToken("user", "password",
				AuthorityUtils.createAuthorityList("ROLE_USER"));
		SecurityContextHolder.getContext().setAuthentication(authentication);
	}

	@After
	public void cleanup() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void authenticationPrincipalResolved() throws Exception {
		mockMvc.perform(get("/authentication-principal"))
				.andExpect(assertResult(authentication.getPrincipal()))
				.andExpect(view().name("authentication-principal-view"));
	}

	@Test
	public void deprecatedAuthenticationPrincipalResolved() throws Exception {
		mockMvc.perform(get("/deprecated-authentication-principal"))
				.andExpect(assertResult(authentication.getPrincipal()))
				.andExpect(view().name("deprecated-authentication-principal-view"));
	}

	@Test
	public void csrfToken() throws Exception {
		CsrfToken csrfToken = new DefaultCsrfToken("headerName", "paramName", "token");
		MockHttpServletRequestBuilder request = get("/csrf").requestAttr(
				CsrfToken.class.getName(), csrfToken);

		mockMvc.perform(request).andExpect(assertResult(csrfToken));
	}

	private ResultMatcher assertResult(Object expected) {
		return model().attribute("result", expected);
	}

	@Controller
	static class TestController {

		@RequestMapping("/authentication-principal")
		public ModelAndView authenticationPrincipal(
				@AuthenticationPrincipal String principal) {
			return new ModelAndView("authentication-principal-view", "result", principal);
		}

		@RequestMapping("/deprecated-authentication-principal")
		public ModelAndView deprecatedAuthenticationPrincipal(
				@org.springframework.security.web.bind.annotation.AuthenticationPrincipal String principal) {
			return new ModelAndView("deprecated-authentication-principal-view", "result",
					principal);
		}

		@RequestMapping("/csrf")
		public ModelAndView csrf(CsrfToken token) {
			return new ModelAndView("view", "result", token);
		}
	}

	@Configuration
	@EnableWebMvc
	@EnableWebSecurity
	static class Config {
		@Bean
		public TestController testController() {
			return new TestController();
		}
	}

}