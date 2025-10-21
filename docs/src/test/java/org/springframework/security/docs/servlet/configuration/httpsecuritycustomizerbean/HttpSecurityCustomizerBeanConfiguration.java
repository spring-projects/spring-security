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

package org.springframework.security.docs.servlet.configuration.httpsecuritycustomizerbean;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.ThrowingCustomizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

/**
 *
 */
@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
class HttpSecurityCustomizerBeanConfiguration {

	@Bean
	SecurityFilterChain springSecurity(HttpSecurity http) throws Exception {
		// @formatter:off
		http
			.authorizeHttpRequests((requests) -> requests
				.anyRequest().authenticated()
			);
		return http.build();
		// @formatter:on
	}

	// tag::httpSecurityCustomizer[]
	@Bean
	ThrowingCustomizer<HttpSecurity> httpSecurityCustomizer() {
		// @formatter:off
		return (http) -> http
			.headers((headers) -> headers
				.contentSecurityPolicy((csp) -> csp
					// <1>
					.policyDirectives("object-src 'none'")
				)
			)
			// <2>
			.redirectToHttps(Customizer.withDefaults());
		// @formatter:on
	}
	// end::httpSecurityCustomizer[]

}
