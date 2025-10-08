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

package org.springframework.security.config.annotation.authorization;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.WebApplicationContext;

import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests for {@link EnableGlobalMultiFactorAuthentication}.
 *
 * @author Rob Winch
 */
@ExtendWith(SpringExtension.class)
@WebAppConfiguration
public class EnableGlobalMultiFactorAuthenticationTests {

	@Autowired
	MockMvc mvc;

	@Autowired
	Service service;

	@Test
	@WithMockUser(authorities = { FactorGrantedAuthority.PASSWORD_AUTHORITY, FactorGrantedAuthority.OTT_AUTHORITY })
	void webWhenAuthorized() throws Exception {
		this.mvc.perform(get("/")).andExpect(status().isOk());
	}

	@Test
	@WithMockUser
	void webWhenNotAuthorized() throws Exception {
		this.mvc.perform(get("/")).andExpect(status().isUnauthorized());
	}

	@Test
	@WithMockUser(authorities = { FactorGrantedAuthority.PASSWORD_AUTHORITY, FactorGrantedAuthority.OTT_AUTHORITY })
	void methodWhenAuthorized() throws Exception {
		Assertions.assertThatNoException().isThrownBy(() -> this.service.authenticated());
	}

	@Test
	@WithMockUser
	void methodWhenNotAuthorized() throws Exception {
		Assertions.assertThatExceptionOfType(AccessDeniedException.class)
			.isThrownBy(() -> this.service.authenticated());
	}

	@EnableWebSecurity
	@EnableMethodSecurity
	@Configuration
	@EnableGlobalMultiFactorAuthentication(
			authorities = { FactorGrantedAuthority.OTT_AUTHORITY, FactorGrantedAuthority.PASSWORD_AUTHORITY })
	static class Config {

		@Bean
		Service service() {
			return new Service();
		}

		@Bean
		MockMvc mvc(WebApplicationContext context) {
			return MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
		}

		@RestController
		static class OkController {

			@GetMapping("/")
			String ok() {
				return "ok";
			}

		}

	}

	static class Service {

		@PreAuthorize("isAuthenticated()")
		void authenticated() {
		}

	}

}
