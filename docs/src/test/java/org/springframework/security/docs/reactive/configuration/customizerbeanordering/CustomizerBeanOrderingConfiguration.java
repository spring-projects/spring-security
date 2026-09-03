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

package org.springframework.security.docs.reactive.configuration.customizerbeanordering;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.reactive.config.EnableWebFlux;

/**
 *
 */
@EnableWebFlux
@EnableWebFluxSecurity
@Configuration(proxyBeanMethods = false)
class CustomizerBeanOrderingConfiguration {

	// tag::sample[]
	@Bean // <4>
	SecurityWebFilterChain springSecurity(ServerHttpSecurity http) {
		// @formatter:off
		http
			.authorizeExchange((exchange) -> exchange
				.anyExchange().authenticated()
			);
		return http.build();
		// @formatter:on
	}

	@Bean
	@Order(Ordered.LOWEST_PRECEDENCE) // <2>
	Customizer<ServerHttpSecurity> userAuthorization() {
		// @formatter:off
		return (http) -> http
			.authorizeExchange((exchange) -> exchange
				.pathMatchers("/users/**").hasRole("USER")
			);
		// @formatter:on
	}

	@Bean
	@Order(Ordered.HIGHEST_PRECEDENCE) // <1>
	Customizer<ServerHttpSecurity> adminAuthorization() {
		// @formatter:off
		return (http) -> http
			.authorizeExchange((exchange) -> exchange
				.pathMatchers("/admins/**").hasRole("ADMIN")
			);
		// @formatter:on
	}

	// <3>

	@Bean
	Customizer<ServerHttpSecurity.HeaderSpec> contentSecurityPolicy() {
		// @formatter:off
		return (headers) -> headers
			.contentSecurityPolicy((csp) -> csp
				.policyDirectives("object-src 'none'")
			);
		// @formatter:on
	}

	@Bean
	Customizer<ServerHttpSecurity.HeaderSpec> contentTypeOptions() {
		// @formatter:off
		return (headers) -> headers
			.contentTypeOptions(Customizer.withDefaults());
		// @formatter:on
	}

	@Bean
	Customizer<ServerHttpSecurity.HttpsRedirectSpec> httpsRedirect() {
		// @formatter:off
		return Customizer.withDefaults();
		// @formatter:on
	}
	// end::sample[]

}
