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

package org.springframework.security.docs.servlet.authentication.servletx509config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

/**
 * Demonstrates custom configuration for x509 reactive configuration.
 *
 * @author Rob Winch
 */
@EnableWebMvc
@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
public class DefaultX509Configuration {

	// tag::springSecurity[]
	@Bean
	DefaultSecurityFilterChain springSecurity(HttpSecurity http) throws Exception {
		// @formatter:off
		http
			.x509(Customizer.withDefaults())
			.authorizeHttpRequests(exchanges -> exchanges
				.anyRequest().authenticated()
			);
		// @formatter:on
		return http.build();
	}
	// end::springSecurity[]

	@Bean
	UserDetailsService userDetailsService() {
		// @formatter:off
		UserDetails user = User
			.withUsername("rod")
			.password("password")
			.roles("USER")
			.build();
		// @formatter:on

		return new InMemoryUserDetailsManager(user);
	}
}
