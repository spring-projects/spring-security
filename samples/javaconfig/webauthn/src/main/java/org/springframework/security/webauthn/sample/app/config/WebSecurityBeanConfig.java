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

package org.springframework.security.webauthn.sample.app.config;

import com.webauthn4j.validator.WebAuthnAuthenticationContextValidator;
import com.webauthn4j.validator.WebAuthnRegistrationContextValidator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.webauthn.WebAuthnRegistrationRequestValidator;
import org.springframework.security.webauthn.challenge.ChallengeRepository;
import org.springframework.security.webauthn.challenge.HttpSessionChallengeRepository;
import org.springframework.security.webauthn.options.OptionsProvider;
import org.springframework.security.webauthn.options.OptionsProviderImpl;
import org.springframework.security.webauthn.server.ServerPropertyProvider;
import org.springframework.security.webauthn.server.ServerPropertyProviderImpl;
import org.springframework.security.webauthn.userdetails.WebAuthnUserDetailsService;

@Configuration
public class WebSecurityBeanConfig {

	@Bean
	public WebAuthnRegistrationRequestValidator webAuthnRegistrationRequestValidator(ServerPropertyProvider serverPropertyProvider) {
		WebAuthnRegistrationContextValidator webAuthnRegistrationContextValidator = WebAuthnRegistrationContextValidator.createNonStrictRegistrationContextValidator();
		return new WebAuthnRegistrationRequestValidator(webAuthnRegistrationContextValidator, serverPropertyProvider);
	}

	@Bean
	public ServerPropertyProvider serverPropertyProvider(WebAuthnUserDetailsService webAuthnUserDetailsService) {
		ChallengeRepository challengeRepository = new HttpSessionChallengeRepository();
		OptionsProvider optionsProvider = new OptionsProviderImpl(webAuthnUserDetailsService, challengeRepository);
		return new ServerPropertyProviderImpl(optionsProvider, challengeRepository);
	}

	@Bean
	public WebAuthnAuthenticationContextValidator webAuthnAuthenticationContextValidator() {
		return new WebAuthnAuthenticationContextValidator();
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	// Not to register DaoAuthenticationProvider to ProviderManager,
	// initialize DaoAuthenticationProvider manually instead of using DaoAuthenticationConfigurer.
	@Bean
	public DaoAuthenticationProvider daoAuthenticationProvider(PasswordEncoder passwordEncoder, UserDetailsService userDetailsService) {
		DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
		daoAuthenticationProvider.setPasswordEncoder(passwordEncoder);
		daoAuthenticationProvider.setUserDetailsService(userDetailsService);
		return daoAuthenticationProvider;
	}

}
