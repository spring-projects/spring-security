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

package org.springframework.security.docs.reactive.authentication.reactivex509;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.userdetails.MapReactiveUserDetailsService;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.preauth.x509.SubjectX500PrincipalExtractor;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.ReactivePreAuthenticatedAuthenticationManager;
import org.springframework.web.reactive.config.EnableWebFlux;

/**
 * Demonstrates custom configuration for x509 reactive configuration.
 *
 * @author Rob Winch
 */
@Configuration(proxyBeanMethods = false)
@EnableWebFluxSecurity
@EnableWebFlux
public class CustomX509Configuration {

	// tag::springSecurity[]
	@Bean
	SecurityWebFilterChain springSecurity(ServerHttpSecurity http) {
		SubjectX500PrincipalExtractor principalExtractor = new SubjectX500PrincipalExtractor();
		principalExtractor.setExtractPrincipalNameFromEmail(true);

		// @formatter:off
		UserDetails user = User
			.withUsername("luke@monkeymachine")
			.password("password")
			.roles("USER")
			.build();
		// @formatter:on

		ReactiveUserDetailsService users = new MapReactiveUserDetailsService(user);
		ReactiveAuthenticationManager authenticationManager = new ReactivePreAuthenticatedAuthenticationManager(users);

		// @formatter:off
		http
			.x509((x509) -> x509
				.principalExtractor(principalExtractor)
				.authenticationManager(authenticationManager)
			)
			.authorizeExchange((authorize) -> authorize
				.anyExchange().authenticated()
			);
		// @formatter:on
		return http.build();
	}
	// end::springSecurity[]

}
