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

package org.springframework.security.docs.reactive.oauth2.webclient;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mockito;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.web.reactive.function.client.WebClient;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests {@link ApplicationScopedAccessTokenConfiguration}.
 */
@ExtendWith(SpringTestContextExtension.class)
public class ApplicationScopedAccessTokenTests {

	public final SpringTestContext spring = new SpringTestContext(this);

	@Autowired
	WebClient webClient;

	@Test
	void webClientWhenClientCredentialsThenConfigured() {
		this.spring.register(TestConfig.class, ApplicationScopedAccessTokenConfiguration.class).autowire();
		assertThat(this.webClient).isNotNull();
	}

	@Configuration
	static class TestConfig {

		@Bean
		ReactiveClientRegistrationRepository clientRegistrationRepository() {
			return Mockito.mock(ReactiveClientRegistrationRepository.class);
		}

		@Bean
		ReactiveOAuth2AuthorizedClientService authorizedClientService() {
			return Mockito.mock(ReactiveOAuth2AuthorizedClientService.class);
		}

	}

}
