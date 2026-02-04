/*
 * Copyright 2026-present the original author or authors.
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

package org.springframework.security.docs.servlet.authentication.tokenbasedremembermeservices;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.rememberme.TokenBasedRememberMeServices;
import org.springframework.security.web.authentication.rememberme.TokenBasedRememberMeServices.RememberMeTokenAlgorithm;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

/**
 * Demonstrates custom algorithm for remember me configuration.
 *
 * @author Ngoc Nhan
 */
@EnableWebMvc
@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
public class CustomAlgorithmRememberMeServicesConfiguration {

	// tag::snippet[]
	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http, RememberMeServices rememberMeServices) throws Exception {
		// @formatter:off
		http
				.authorizeHttpRequests((authorize) -> authorize
						.anyRequest().authenticated()
				)
				.rememberMe((remember) -> remember
						.rememberMeServices(rememberMeServices)
				);
		// @formatter:on
		return http.build();
	}

	@Bean
	RememberMeServices rememberMeServices(UserDetailsService userDetailsService) {
		RememberMeTokenAlgorithm encodingAlgorithm = RememberMeTokenAlgorithm.SHA256;
		TokenBasedRememberMeServices rememberMe = new TokenBasedRememberMeServices("myKey", userDetailsService,
				encodingAlgorithm);
		rememberMe.setMatchingAlgorithm(RememberMeTokenAlgorithm.MD5);
		return rememberMe;
	}
	// end::snippet[]

}
