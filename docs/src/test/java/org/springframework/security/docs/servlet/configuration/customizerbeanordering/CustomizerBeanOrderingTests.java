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

package org.springframework.security.docs.servlet.configuration.customizerbeanordering;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 *
 */
@ExtendWith(SpringTestContextExtension.class)
public class CustomizerBeanOrderingTests {
	public final SpringTestContext spring = new SpringTestContext(this).mockMvcAfterSpringSecurityOk();

	@Autowired
	private MockMvc mockMvc;

	@Test
	void authorizationOrdered() throws Exception {
		this.spring.register(
				CustomizerBeanOrderingConfiguration.class).autowire();
		// @formatter:off
		this.mockMvc
			.perform(get("https://localhost/admins/1").with(user("admin").roles("ADMIN")))
			.andExpect(status().isOk());
		this.mockMvc
				.perform(get("https://localhost/admins/1").with(user("user").roles("USER")))
				.andExpect(status().isForbidden());
		this.mockMvc
				.perform(get("https://localhost/users/1").with(user("user").roles("USER")))
				.andExpect(status().isOk());
		this.mockMvc
				.perform(get("https://localhost/users/1").with(user("user").roles("OTHER")))
				.andExpect(status().isForbidden());
		this.mockMvc
				.perform(get("https://localhost/other").with(user("authenticated").roles("OTHER")))
				.andExpect(status().isOk());
		// @formatter:on
	}

}
