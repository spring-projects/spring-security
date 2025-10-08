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

package org.springframework.security.docs.servlet.authentication.obtainingmoreauthorization;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.docs.servlet.authentication.servletx509config.CustomX509Configuration;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.test.context.support.WithSecurityContextTestExecutionListener;
import org.springframework.test.context.TestExecutionListeners;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests {@link CustomX509Configuration}.
 *
 * @author Rob Winch
 */
@ExtendWith({ SpringExtension.class, SpringTestContextExtension.class })
@TestExecutionListeners(WithSecurityContextTestExecutionListener.class)
public class ObtainingMoreAuthorizationTests {

	public final SpringTestContext spring = new SpringTestContext(this);

	@Autowired
	MockMvc mockMvc;

	@Test
	@WithMockUser
	void profileWhenScopeConfigurationThenDenies() throws Exception {
		this.spring.register(ScopeConfiguration.class, Http200Controller.class).autowire();
		// @formatter:off
		this.mockMvc.perform(get("/profile"))
			.andExpect(status().isForbidden());
		// @formatter:on
	}

	@Test
	@WithMockUser(authorities = { FactorGrantedAuthority.X509_AUTHORITY, FactorGrantedAuthority.AUTHORIZATION_CODE_AUTHORITY })
	void profileWhenMissingAuthorityConfigurationThenRedirectsToAuthorizationServer() throws Exception {
		this.spring.register(MissingAuthorityConfiguration.class, Http200Controller.class).autowire();
		// @formatter:off
		this.mockMvc.perform(get("/profile"))
			.andExpect(status().is3xxRedirection())
			.andExpect(redirectedUrl("https://authz.example.org/authorize?scope=profile:read"));
		// @formatter:on
	}

	@Test
	@WithMockUser(authorities = { "SCOPE_profile:read" })
	void profileWhenMissingX509WithOttThenForbidden() throws Exception {
		this.spring.register(MissingAuthorityConfiguration.class, Http200Controller.class).autowire();
		// @formatter:off
		this.mockMvc.perform(get("/profile"))
			.andExpect(status().isForbidden());
		// @formatter:on
	}

	@Test
	@WithMockUser(authorities = { FactorGrantedAuthority.X509_AUTHORITY, FactorGrantedAuthority.AUTHORIZATION_CODE_AUTHORITY, "SCOPE_profile:read" })
	void profileWhenAuthenticatedAndHasScopeThenPermits() throws Exception {
		this.spring.register(MissingAuthorityConfiguration.class, Http200Controller.class).autowire();
		// @formatter:off
		this.mockMvc.perform(get("/profile"))
			.andExpect(status().isOk())
			.andExpect(authenticated().withUsername("user"));
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
