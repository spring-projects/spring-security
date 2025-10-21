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

package org.springframework.security.test.web.servlet.response;

import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;

@ExtendWith(SpringExtension.class)
@ContextConfiguration(classes = SecurityMockWithAuthoritiesMvcResultMatchersTests.Config.class)
@WebAppConfiguration
public class SecurityMockWithAuthoritiesMvcResultMatchersTests {

	private static final String ROLE_CUSTOM = "ROLE_CUSTOM";

	@Autowired
	private WebApplicationContext context;

	private MockMvc mockMvc;

	@BeforeEach
	public void setup() {
		this.mockMvc = MockMvcBuilders.webAppContextSetup(this.context).apply(springSecurity()).build();
	}

	@Test
	public void withAuthoritiesStringAllowsAnyOrderAndPermitsAnyImpl() throws Exception {
		this.mockMvc.perform(formLogin())
			.andExpect(authenticated().withAuthorities("ROLE_ADMIN", "ROLE_SELLER",
					FactorGrantedAuthority.PASSWORD_AUTHORITY));
	}

	@Test
	public void withAuthoritiesFailsIfNotAllRoles() throws Exception {
		List<SimpleGrantedAuthority> grantedAuthorities = new ArrayList<>();
		grantedAuthorities.add(new SimpleGrantedAuthority("ROLE_ADMIN"));
		assertThatExceptionOfType(AssertionError.class).isThrownBy(
				() -> this.mockMvc.perform(formLogin()).andExpect(authenticated().withAuthorities(grantedAuthorities)));
	}

	@Test
	public void withAuthoritiesStringSupportsCustomAuthority() throws Exception {
		this.mockMvc.perform(formLogin().user("custom"))
			.andExpect(authenticated().withAuthorities(ROLE_CUSTOM, FactorGrantedAuthority.PASSWORD_AUTHORITY));
	}

	@Configuration
	@EnableWebSecurity
	@EnableWebMvc
	static class Config {

		@Bean
		UserDetailsService userDetailsService() {
			// @formatter:off
			UserDetails user = User.withDefaultPasswordEncoder().username("user").password("password").roles("ADMIN", "SELLER").build();
			UserDetails customAuthorityUser = User.withDefaultPasswordEncoder().username("custom").password("password").authorities(new CustomAuthority(ROLE_CUSTOM)).build();
			return new InMemoryUserDetailsManager(user, customAuthorityUser);
			// @formatter:on
		}

		@RestController
		static class Controller {

			@RequestMapping("/")
			String ok() {
				return "ok";
			}

		}

	}

	/**
	 * A custom {@link GrantedAuthority} for testing.
	 *
	 * @author Rob Winch
	 * @since 7.0
	 */
	static class CustomAuthority implements GrantedAuthority {

		private final String authority;

		CustomAuthority(String authority) {
			this.authority = authority;
		}

		@Override
		public String getAuthority() {
			return this.authority;
		}

	}

}
