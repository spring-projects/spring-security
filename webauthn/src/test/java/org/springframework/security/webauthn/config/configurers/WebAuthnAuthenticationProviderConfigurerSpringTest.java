/*
 * Copyright 2002-2019 the original author or authors.
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

package org.springframework.security.webauthn.config.configurers;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.webauthn.WebAuthn4JWebAuthnManager;
import org.springframework.security.webauthn.WebAuthnAuthenticationProvider;
import org.springframework.security.webauthn.WebAuthnManager;
import org.springframework.security.webauthn.authenticator.WebAuthnAuthenticatorService;
import org.springframework.security.webauthn.challenge.HttpSessionWebAuthnChallengeRepository;
import org.springframework.security.webauthn.challenge.WebAuthnChallengeRepository;
import org.springframework.security.webauthn.server.EffectiveRpIdProvider;
import org.springframework.security.webauthn.server.WebAuthnServerPropertyProvider;
import org.springframework.security.webauthn.server.WebAuthnServerPropertyProviderImpl;
import org.springframework.security.webauthn.userdetails.WebAuthnUserDetailsService;
import org.springframework.test.context.junit4.SpringRunner;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.springframework.security.webauthn.config.configurers.WebAuthnLoginConfigurer.webAuthnLogin;

@RunWith(SpringRunner.class)
public class WebAuthnAuthenticationProviderConfigurerSpringTest {

	@Autowired
	ProviderManager providerManager;

	@Test
	public void test() {
		assertThat(providerManager.getProviders()).extracting("class").contains(WebAuthnAuthenticationProvider.class);
	}


	@EnableWebSecurity
	static class Config extends WebSecurityConfigurerAdapter {

		@Autowired
		private WebAuthnUserDetailsService webAuthnUserDetailsService;

		@Autowired
		private WebAuthnAuthenticatorService webAuthnAuthenticatorService;

		@Autowired
		private WebAuthnManager webAuthnManager;

		@Bean
		@Override
		public AuthenticationManager authenticationManagerBean() throws Exception {
			return super.authenticationManager();
		}

		@Override
		protected void configure(HttpSecurity http) throws Exception {

			// Authentication
			http.apply(webAuthnLogin());

			// Authorization
			http.authorizeRequests()
					.antMatchers("/login").permitAll()
					.anyRequest().authenticated();
		}

		@Override
		public void configure(AuthenticationManagerBuilder builder) throws Exception {
			builder.apply(new WebAuthnAuthenticationProviderConfigurer<>(webAuthnUserDetailsService, webAuthnAuthenticatorService, webAuthnManager));
		}

		@Configuration
		static class BeanConfig {

			@Bean
			public WebAuthn4JWebAuthnManager webAuthn4JWebAuthnAuthenticationManager() {
				return mock(WebAuthn4JWebAuthnManager.class);
			}

			@Bean
			public WebAuthnUserDetailsService webAuthnUserDetailsService() {
				return mock(WebAuthnUserDetailsService.class);
			}

			@Bean
			public WebAuthnAuthenticatorService webAuthnAuthenticatorService() {
				return mock(WebAuthnAuthenticatorService.class);
			}

			@Bean
			public WebAuthnChallengeRepository challengeRepository() {
				return new HttpSessionWebAuthnChallengeRepository();
			}

			@Bean
			public WebAuthnServerPropertyProvider serverPropertyProvider(EffectiveRpIdProvider effectiveRpIdProvider, WebAuthnChallengeRepository webAuthnChallengeRepository) {
				return new WebAuthnServerPropertyProviderImpl(effectiveRpIdProvider, webAuthnChallengeRepository);
			}


		}

	}


}
