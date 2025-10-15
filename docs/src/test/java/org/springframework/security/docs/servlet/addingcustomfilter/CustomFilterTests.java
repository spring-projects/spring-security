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

package org.springframework.security.docs.servlet.addingcustomfilter;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
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
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@ExtendWith(SpringExtension.class)
@ContextConfiguration(classes = {
		CustomFilterTests.UserDetailsConfig.class,
		CustomFilterTests.ApiController.class,
		SecurityConfig.class })
@WebAppConfiguration
public class CustomFilterTests {

	@Autowired
	private WebApplicationContext context;

	private MockMvc mvc;

	@BeforeEach
	void setup() {
		this.mvc = MockMvcBuilders.webAppContextSetup(this.context)
				.defaultRequest(get("/api").with(user("user")))
				.apply(springSecurity())
				.build();
	}

	@Test
	void tenantFilterWhenHeaderMissingThenAccessDenied() {
		assertThatExceptionOfType(AccessDeniedException.class)
				.isThrownBy(() -> this.mvc.perform(get("/api")).andReturn());
	}

	@Test
	void tenantFilterWhenHeaderPresentThenContinuesFilterChain() throws Exception {
		this.mvc.perform(get("/api").header("X-Tenant-Id", "some-tenant-id"))
					.andExpect(status().isOk())
					.andExpect(authenticated().withUsername("user"));
	}

	@Configuration
	static class UserDetailsConfig {
		@Bean
		UserDetailsService userDetailsService() {
			UserDetails user = User.withDefaultPasswordEncoder()
					.username("user")
					.password("password")
					.roles("USER")
					.build();
			return new InMemoryUserDetailsManager(user);
		}
	}

	@RestController
	static class ApiController {

		@GetMapping("/api")
		String api() {
			return "ok";
		}

	}
}
