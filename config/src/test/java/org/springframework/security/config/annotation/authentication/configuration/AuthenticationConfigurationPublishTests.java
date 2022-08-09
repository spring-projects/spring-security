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

package org.springframework.security.config.annotation.authentication.configuration;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.config.MockEventListener;
import org.springframework.security.config.users.AuthenticationTestConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Rob Winch
 */
@ExtendWith(SpringExtension.class)
public class AuthenticationConfigurationPublishTests {

	@Autowired
	MockEventListener<AuthenticationSuccessEvent> listener;

	AuthenticationManager authenticationManager;

	// gh-4940
	@Test
	public void authenticationEventPublisherBeanUsedByDefault() {
		this.authenticationManager
				.authenticate(UsernamePasswordAuthenticationToken.unauthenticated("user", "password"));
		assertThat(this.listener.getEvents()).hasSize(1);
	}

	@Autowired
	public void setAuthenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
		this.authenticationManager = authenticationConfiguration.getAuthenticationManager();
	}

	@Configuration
	@EnableGlobalAuthentication
	@Import(AuthenticationTestConfiguration.class)
	static class Config {

		@Bean
		AuthenticationEventPublisher publisher() {
			return new DefaultAuthenticationEventPublisher();
		}

		@Bean
		MockEventListener<AuthenticationSuccessEvent> eventListener() {
			return new MockEventListener<AuthenticationSuccessEvent>() {
			};
		}

	}

}
