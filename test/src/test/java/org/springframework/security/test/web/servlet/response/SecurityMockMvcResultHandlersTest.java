/*
 * Copyright 2002-2022 the original author or authors.
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

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultHandlers.exportTestSecurityContext;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

@ExtendWith(SpringExtension.class)
@ContextConfiguration(classes = SecurityMockMvcResultHandlersTest.Config.class)
@WebAppConfiguration
public class SecurityMockMvcResultHandlersTest {

	@Autowired
	private WebApplicationContext context;

	private MockMvc mockMvc;

	@BeforeEach
	public void setup() {
		// @formatter:off
		this.mockMvc = MockMvcBuilders
				.webAppContextSetup(this.context)
				.apply(springSecurity())
				.build();
		// @formatter:on
	}

	@AfterEach
	public void tearDown() {
		SecurityContextHolder.clearContext();
	}

	@Test
	@WithMockUser
	public void withTestSecurityContextCopiedToSecurityContextHolder() throws Exception {
		this.mockMvc.perform(get("/")).andDo(exportTestSecurityContext());

		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

		assertThat(authentication.getName()).isEqualTo("user");
		assertThat(authentication.getAuthorities()).hasSize(1).first().hasToString("ROLE_USER");
	}

	@Test
	@WithMockUser
	public void withTestSecurityContextNotCopiedToSecurityContextHolder() throws Exception {
		this.mockMvc.perform(get("/"));

		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

		assertThat(authentication).isNull();
	}

	@Configuration
	@EnableWebSecurity
	@EnableWebMvc
	static class Config {

		@RestController
		static class Controller {

			@RequestMapping("/")
			String ok() {
				return "ok";
			}

		}

	}

}
