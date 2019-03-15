/*
 * Copyright 2002-2015 the original author or authors.
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

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

/**
 * @author Rob Winch
 */


@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration
@WebAppConfiguration
public class Sec2935Tests {

	@Autowired
	WebApplicationContext context;

	MockMvc mvc;

	@Before
	public void setup() {
		mvc = MockMvcBuilders.webAppContextSetup(context)
				.apply(springSecurity())
				.build();
	}

	// SEC-2935
	@Test
	public void postProcessorUserNoUser() throws Exception {
		mvc
			.perform(get("/admin/abc").with(user("user").roles("ADMIN","USER")))
			.andExpect(status().isNotFound())
			.andExpect(authenticated().withUsername("user"));

		mvc
			.perform(get("/admin/abc"))
			.andExpect(status().isUnauthorized())
			.andExpect(unauthenticated());
	}

	@Test
	public void postProcessorUserOtherUser() throws Exception {
		mvc
			.perform(get("/admin/abc").with(user("user1").roles("ADMIN","USER")))
			.andExpect(status().isNotFound())
			.andExpect(authenticated().withUsername("user1"));

		mvc
			.perform(get("/admin/abc").with(user("user2").roles("USER")))
			.andExpect(status().isForbidden())
			.andExpect(authenticated().withUsername("user2"));
	}

	@WithMockUser
	@Test
	public void postProcessorUserWithMockUser() throws Exception {
		mvc
			.perform(get("/admin/abc").with(user("user1").roles("ADMIN","USER")))
			.andExpect(status().isNotFound())
			.andExpect(authenticated().withUsername("user1"));

		mvc
			.perform(get("/admin/abc"))
			.andExpect(status().isForbidden())
			.andExpect(authenticated().withUsername("user"));
	}

	// SEC-2941
	@Test
	public void defaultRequest() throws Exception {
		mvc = MockMvcBuilders.webAppContextSetup(context)
				.apply(springSecurity())
				.defaultRequest(get("/").with(user("default")))
				.build();

		mvc
			.perform(get("/admin/abc").with(user("user1").roles("ADMIN","USER")))
			.andExpect(status().isNotFound())
			.andExpect(authenticated().withUsername("user1"));

		mvc
			.perform(get("/admin/abc"))
			.andExpect(status().isForbidden())
			.andExpect(authenticated().withUsername("default"));
	}

	@Ignore
	@WithMockUser
	@Test
	public void defaultRequestOverridesWithMockUser() throws Exception {
		mvc = MockMvcBuilders.webAppContextSetup(context)
				.apply(springSecurity())
				.defaultRequest(get("/").with(user("default")))
				.build();

		mvc
			.perform(get("/admin/abc").with(user("user1").roles("ADMIN","USER")))
			.andExpect(status().isNotFound())
			.andExpect(authenticated().withUsername("user1"));

		mvc
			.perform(get("/admin/abc"))
			.andExpect(status().isForbidden())
			.andExpect(authenticated().withUsername("default"));
	}

	@EnableWebSecurity
	@Configuration
	static class Config extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
				.authorizeRequests()
					.antMatchers("/admin/**").hasRole("ADMIN")
					.anyRequest().authenticated()
					.and()
				.httpBasic();
		}

		@Autowired
		public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
			auth.inMemoryAuthentication();
		}
	}
}
