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

package org.springframework.security.docs.reactive.authentication.onetimetokenaccountstatus;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.authentication.ott.reactive.OneTimeTokenReactiveAuthenticationManager;
import org.springframework.security.authentication.ott.reactive.ReactiveOneTimeTokenService;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.web.server.SecurityWebFilterChain;

@EnableWebFluxSecurity
@Configuration(proxyBeanMethods = false)
class OneTimeTokenAccountStatusExample {

	@Bean
	SecurityWebFilterChain filterChain(ServerHttpSecurity http,
			OneTimeTokenReactiveAuthenticationManager oneTimeTokenAuthenticationManager) {
		// @formatter:off
		http
			// ...
			.formLogin(Customizer.withDefaults())
			.oneTimeTokenLogin((ott) -> ott
				.authenticationManager(oneTimeTokenAuthenticationManager)
			);
		// @formatter:on
		return http.build();
	}

	// tag::userDetailsChecker[]
	@Bean
	OneTimeTokenReactiveAuthenticationManager oneTimeTokenAuthenticationManager(
			ReactiveOneTimeTokenService oneTimeTokenService, ReactiveUserDetailsService userDetailsService) {
		OneTimeTokenReactiveAuthenticationManager authenticationManager = new OneTimeTokenReactiveAuthenticationManager(
				oneTimeTokenService, userDetailsService);
		authenticationManager.setUserDetailsChecker(new AccountStatusUserDetailsChecker());
		return authenticationManager;
	}
	// end::userDetailsChecker[]

}
