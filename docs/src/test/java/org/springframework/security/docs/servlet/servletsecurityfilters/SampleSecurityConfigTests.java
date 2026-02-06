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

package org.springframework.security.docs.servlet.servletsecurityfilters;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.*;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.*;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@ExtendWith(SpringExtension.class)
@ContextConfiguration(classes = { SampleSecurityConfigTests.UserDetailsConfig.class, SecurityConfig.class })
@WebAppConfiguration
public class SampleSecurityConfigTests {

	@Autowired
	private WebApplicationContext context;

	private MockMvc mvc;

	@BeforeEach
	public void setup() {
		this.mvc = MockMvcBuilders.webAppContextSetup(this.context)
				.defaultRequest(get("/api").with(user("user")))
				.defaultRequest(post("/api").with(csrf()))
				.apply(springSecurity())
				.build();
	}

	@Test
	void testGet() throws Exception {
		this.mvc.perform(get("/api")
						.with(httpBasic("user", "password")))
				// Security check was successful
				.andExpect(status().isNotFound())
				.andExpect(authenticated().withUsername("user"));
	}

	@Test
	void testUnauthenticated() throws Exception {
		this.mvc.perform(get("/api"))
				// Security check was successful
				.andExpect(status().isUnauthorized());
	}

	@Test
	void testCsrf() throws Exception {
		this.mvc.perform(post("/api")
				.with(csrf())
				.with(httpBasic("user", "password"))
		).andExpect(status().isNotFound());
	}

	@Configuration
	static class UserDetailsConfig {
		@Bean
		UserDetailsService userDetailsService() {
			UserDetails user = User.withDefaultPasswordEncoder()
					.username("user")
					.password("password")
					.build();
			return new InMemoryUserDetailsManager(user);
		}
	}
}
