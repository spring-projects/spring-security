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

package org.springframework.security.docs.reactive.configuration.toplevelcustomizerbean;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

/**
 *
 */
@EnableWebFluxSecurity
@Configuration(proxyBeanMethods = false)
public class TopLevelCustomizerBeanConfiguration {

	@Bean
	SecurityWebFilterChain springSecurity(ServerHttpSecurity http) {
		// @formatter:off
		http
			.authorizeExchange((exchange) -> exchange
				.anyExchange().authenticated()
			);
		return http.build();
		// @formatter:on
	}

	// tag::headersCustomizer[]
	@Bean
	Customizer<ServerHttpSecurity.HeaderSpec> headersSecurity() {
		// @formatter:off
		return (headers) -> headers
			.contentSecurityPolicy((csp) -> csp
				// <1>
				.policyDirectives("object-src 'none'")
			);
		// @formatter:on
	}
	// end::headersCustomizer[]

}
