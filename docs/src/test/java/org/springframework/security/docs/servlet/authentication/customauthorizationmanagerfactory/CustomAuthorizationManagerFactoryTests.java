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

package org.springframework.security.docs.servlet.authentication.customauthorizationmanagerfactory;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.core.GrantedAuthorities;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.docs.servlet.authentication.servletx509config.CustomX509Configuration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests {@link CustomX509Configuration}.
 *
 * @author Rob Winch
 */
@ExtendWith(SpringTestContextExtension.class)
public class CustomAuthorizationManagerFactoryTests {

	public final SpringTestContext spring = new SpringTestContext(this);

	@Autowired
	MockMvc mockMvc;

	@Autowired
	UserDetailsService users;

	@Test
	void getWhenOptedInThenRedirectsToOtt() throws Exception {
		this.spring.register(CustomAuthorizationManagerFactory.class, Http200Controller.class).autowire();
		UserDetails user = this.users.loadUserByUsername("optedin");
		// @formatter:off
		this.mockMvc.perform(get("/").with(user(user)))
			.andExpect(status().is3xxRedirection())
			.andExpect(redirectedUrl("http://localhost/login?factor=ott"));
		// @formatter:on
	}

	@Test
	void getWhenNotOptedInThenAllows() throws Exception {
		this.spring.register(CustomAuthorizationManagerFactory.class, Http200Controller.class).autowire();
		UserDetails user = this.users.loadUserByUsername("user");
		// @formatter:off
		this.mockMvc.perform(get("/").with(user(user)))
			.andExpect(status().isOk())
			.andExpect(authenticated().withUsername("user"));
		// @formatter:on
	}

	@Test
	void getWhenOptedAndHasFactorThenAllows() throws Exception {
		this.spring.register(CustomAuthorizationManagerFactory.class, Http200Controller.class).autowire();
		UserDetails user = this.users.loadUserByUsername("optedin");
		TestingAuthenticationToken token = new TestingAuthenticationToken(user, "", GrantedAuthorities.FACTOR_OTT_AUTHORITY);
		// @formatter:off
		this.mockMvc.perform(get("/").with(authentication(token)))
			.andExpect(status().isOk())
			.andExpect(authenticated().withUsername("optedin"));
		// @formatter:on
	}

	@RestController
	static class Http200Controller {
		@GetMapping("/**")
		String ok() {
			return "ok";
		}
	}
}
