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
package org.springframework.security.test.web.servlet.showcase.login;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.*;
import static org.springframework.security.test.web.servlet.response.RedirectMatcher.redirectUrl;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.*;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.*;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = AuthenticationTests.Config.class)
@WebAppConfiguration
public class AuthenticationTests {

	@Autowired
	private WebApplicationContext context;

	private MockMvc mvc;

	@Before
	public void setup() {
		mvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
	}

	@Test
	public void requiresAuthentication() throws Exception {
		mvc.perform(get("/")).andExpect(status().isFound());
	}

	@Test
	public void httpBasicAuthenticationSuccess() throws Exception {
		mvc.perform(get("/secured/butnotfound").with(httpBasic("user", "password")))
				.andExpect(status().isNotFound())
				.andExpect(authenticated().withUsername("user"));
	}

	@Test
	public void authenticationSuccess() throws Exception {
		mvc.perform(formLogin()).andExpect(status().isFound())
				.andExpect(redirectUrl("/"))
				.andExpect(authenticated().withUsername("user"));
	}

	@Test
	public void authenticationFailed() throws Exception {
		mvc.perform(formLogin().user("user").password("invalid"))
				.andExpect(status().isFound())
				.andExpect(redirectUrl("/login?error"))
				.andExpect(unauthenticated());
	}

	@EnableWebSecurity
	@EnableWebMvc
	static class Config extends WebSecurityConfigurerAdapter {
		// @formatter:off
		@Autowired
		public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
			auth
				.inMemoryAuthentication()
					.withUser("user").password("password").roles("USER");
		}
		// @formatter:on
	}
}