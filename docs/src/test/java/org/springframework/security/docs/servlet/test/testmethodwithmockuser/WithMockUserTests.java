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

package org.springframework.security.docs.servlet.test.testmethodwithmockuser;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.core.MessageService;
import org.springframework.security.docs.servlet.test.testmethod.HelloMessageService;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import static org.assertj.core.api.Assertions.assertThat;


@ExtendWith(SpringExtension.class)
@ContextConfiguration
class WithMockUserTests {

	@Autowired
	MessageService messageService;

	// tag::mock-user[]
	@Test
	@WithMockUser
	void getMessageWithMockUser() {
		String message = messageService.getMessage();
		assertThat(message).contains("user");
	}
	// end::mock-user[]

	// tag::custom-user[]
	@Test
	@WithMockUser("customUser")
	void getMessageWithMockUserCustomUsername() {
		String message = messageService.getMessage();
		assertThat(message).contains("customUser");
	}
	// end::custom-user[]

	// tag::custom-roles[]
	@Test
	@WithMockUser(username = "admin", roles = {"USER", "ADMIN"})
	void getMessageWithMockUserCustomRoles() {
		String message = messageService.getMessage();
		assertThat(message)
				.contains("admin")
				.contains("ROLE_ADMIN")
				.contains("ROLE_USER");
	}
	// end::custom-roles[]

	// tag::custom-authorities[]
	@Test
	@WithMockUser(username = "admin", authorities = {"ADMIN", "USER"})
	public void getMessageWithMockUserCustomAuthorities() {
		String message = messageService.getMessage();
		assertThat(message)
				.contains("admin")
				.contains("ADMIN")
				.contains("USER")
				.doesNotContain("ROLE_");
	}
	// end::custom-authorities[]

	@EnableMethodSecurity
	@Configuration
	static class Config {

		@Bean
		MessageService messageService() {
			return new HelloMessageService();
		}
	}
}
