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

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.webauthn.*;
import org.springframework.security.webauthn.challenge.HttpSessionWebAuthnChallengeRepository;
import org.springframework.security.webauthn.challenge.WebAuthnChallengeRepository;
import org.springframework.security.webauthn.server.EffectiveRpIdProvider;
import org.springframework.security.webauthn.server.WebAuthnServerPropertyProvider;
import org.springframework.security.webauthn.server.WebAuthnServerPropertyProviderImpl;
import org.springframework.security.webauthn.userdetails.InMemoryWebAuthnAndPasswordUserDetailsManager;
import org.springframework.security.webauthn.userdetails.WebAuthnUserDetailsService;

@Configuration
public class WebSecurityBeanConfig {

	@Bean
	public WebAuthnServerPropertyProvider webAuthnServerPropertyProvider(EffectiveRpIdProvider effectiveRpIdProvider, WebAuthnChallengeRepository challengeRepository){
		return new WebAuthnServerPropertyProviderImpl(effectiveRpIdProvider, challengeRepository);
	}

	@Bean
	public WebAuthnChallengeRepository webAuthnChallengeRepository(){
		return new HttpSessionWebAuthnChallengeRepository();
	}

	@Bean
	public InMemoryWebAuthnAndPasswordUserDetailsManager webAuthnUserDetailsService(){
		return new InMemoryWebAuthnAndPasswordUserDetailsManager();
	}

	@Bean
	public WebAuthnOptionWebHelper webAuthnOptionWebHelper(WebAuthnChallengeRepository challengeRepository, WebAuthnUserDetailsService userDetailsService){
		return new WebAuthnOptionWebHelper(challengeRepository, userDetailsService);
	}

	@Bean
	public WebAuthnManager webAuthnAuthenticationManager(){
		return new WebAuthn4JWebAuthnManager();
	}

	@Bean
	public WebAuthnDataConverter webAuthnDataConverter(){
		return new WebAuthnDataConverter();
	}

	@Bean
	public WebAuthnRegistrationRequestValidator webAuthnRegistrationRequestValidator(WebAuthnManager webAuthnManager, WebAuthnServerPropertyProvider webAuthnServerPropertyProvider){
		return new WebAuthnRegistrationRequestValidator(webAuthnManager, webAuthnServerPropertyProvider);
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
