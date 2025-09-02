/*
 * Copyright 2004-present the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain clients copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.docs.servlet.authorization.customizingauthorizationmanagers;

import java.util.Collections;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.anonymous;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests for {@link CustomMethodInvocationAuthorizationManagerFactory}.
 *
 * @author Steve Riesenberg
 */
@ExtendWith(SpringTestContextExtension.class)
public class CustomMethodInvocationAuthorizationManagerFactoryTests {

	public final SpringTestContext spring = new SpringTestContext(this);

	@Autowired
	MockMvc mockMvc;

	@Test
	void getUserWhenAnonymousThenForbidden() throws Exception {
		this.spring.register(SecurityConfiguration.class, TestController.class).autowire();
		// @formatter:off
		this.mockMvc.perform(get("/user").with(anonymous()))
			.andExpect(status().isForbidden())
			.andExpect(unauthenticated());
		// @formatter:on
	}

	@Test
	void getUserWhenAuthenticatedWithNoRolesThenForbidden() throws Exception {
		this.spring.register(SecurityConfiguration.class, TestController.class).autowire();
		Authentication authentication = new TestingAuthenticationToken("user", "", Collections.emptyList());
		// @formatter:off
		this.mockMvc.perform(get("/user").with(authentication(authentication)))
			.andExpect(status().isForbidden())
			.andExpect(authenticated().withAuthentication(authentication));
		// @formatter:on
	}

	@Test
	void getUserWhenAuthenticatedWithUserRoleThenOk() throws Exception {
		this.spring.register(SecurityConfiguration.class, TestController.class).autowire();
		Authentication authentication = new TestingAuthenticationToken("user", "", "ROLE_USER");
		// @formatter:off
		this.mockMvc.perform(get("/user").with(authentication(authentication)))
			.andExpect(status().isOk())
			.andExpect(authenticated().withAuthentication(authentication));
		// @formatter:on
	}

	@Test
	void getUserWhenAuthenticatedWithAdminRoleThenOk() throws Exception {
		this.spring.register(SecurityConfiguration.class, TestController.class).autowire();
		Authentication authentication = new TestingAuthenticationToken("admin", "", "ROLE_ADMIN");
		// @formatter:off
		this.mockMvc.perform(get("/user").with(authentication(authentication)))
			.andExpect(status().isOk())
			.andExpect(authenticated().withAuthentication(authentication));
		// @formatter:on
	}

	@Test
	void getUserWhenAuthenticatedWithOtherRoleThenForbidden() throws Exception {
		this.spring.register(SecurityConfiguration.class, TestController.class).autowire();
		Authentication authentication = new TestingAuthenticationToken("user", "", "ROLE_OTHER");
		// @formatter:off
		this.mockMvc.perform(get("/user").with(authentication(authentication)))
			.andExpect(status().isForbidden())
			.andExpect(authenticated().withAuthentication(authentication));
		// @formatter:on
	}

	@Test
	void getRolesWhenAuthenticatedWithRole1RoleThenOk() throws Exception {
		this.spring.register(SecurityConfiguration.class, TestController.class).autowire();
		Authentication authentication = new TestingAuthenticationToken("user", "", "ROLE_ROLE1");
		// @formatter:off
		this.mockMvc.perform(get("/roles").with(authentication(authentication)))
			.andExpect(status().isOk())
			.andExpect(authenticated().withAuthentication(authentication));
		// @formatter:on
	}

	@Test
	void getRolesWhenAuthenticatedWithAdminRoleThenOk() throws Exception {
		this.spring.register(SecurityConfiguration.class, TestController.class).autowire();
		Authentication authentication = new TestingAuthenticationToken("admin", "", "ROLE_ADMIN");
		// @formatter:off
		this.mockMvc.perform(get("/roles").with(authentication(authentication)))
			.andExpect(status().isOk())
			.andExpect(authenticated().withAuthentication(authentication));
		// @formatter:on
	}

	@Test
	void getRolesWhenAuthenticatedWithOtherRoleThenForbidden() throws Exception {
		this.spring.register(SecurityConfiguration.class, TestController.class).autowire();
		Authentication authentication = new TestingAuthenticationToken("user", "", "ROLE_OTHER");
		// @formatter:off
		this.mockMvc.perform(get("/roles").with(authentication(authentication)))
			.andExpect(status().isForbidden())
			.andExpect(authenticated().withAuthentication(authentication));
		// @formatter:on
	}

	@EnableWebMvc
	@EnableWebSecurity
	@EnableMethodSecurity
	@Configuration
	static class SecurityConfiguration {

		@Bean
		SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeHttpRequests((authorize) -> authorize
					.anyRequest().authenticated()
				);
			// @formatter:on
			return http.build();
		}

		@Bean
		CustomMethodInvocationAuthorizationManagerFactory customMethodInvocationAuthorizationManagerFactory() {
			return new CustomMethodInvocationAuthorizationManagerFactory();
		}

	}

	@RestController
	static class TestController {

		@GetMapping("/user")
		@ResponseStatus(HttpStatus.OK)
		@PreAuthorize("hasRole('USER')")
		void user() {
		}

		@GetMapping("/roles")
		@ResponseStatus(HttpStatus.OK)
		@PreAuthorize("hasAnyRole('ROLE1', 'ROLE2')")
		void roles() {
		}

	}

}
