/*
 * Copyright 2002-2025 the original author or authors.
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

package org.springframework.security.docs.servlet.test.testmethodmetaannotations;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.core.MessageService;
import org.springframework.security.docs.servlet.test.testmethod.HelloMessageService;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(SpringExtension.class)
@ContextConfiguration
public class WithMockAdminTests {

	@Autowired
	MessageService messageService;

	@Test
	@WithMockAdmin
	void getMessageWithMockUserAdminRoles() {
		String message = messageService.getMessage();
		assertThat(message)
				.contains("rob")
				.contains("ROLE_ADMIN")
				.contains("ROLE_USER");
	}

	@EnableMethodSecurity
	@Configuration
	static class Config {

		@Bean
		MessageService messageService() {
			return new HelloMessageService();
		}
	}
}
