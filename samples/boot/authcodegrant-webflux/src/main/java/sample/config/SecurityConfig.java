/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package sample.config;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.userdetails.MapReactiveUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.web.server.AuthenticatedPrincipalServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.web.server.SecurityWebFilterChain;

/**
 * @author Rob Winch
 */
@EnableWebFluxSecurity
public class SecurityConfig {

	@Bean
	SecurityWebFilterChain configure(ServerHttpSecurity http) throws Exception {
		http
			.authorizeExchange()
				.anyExchange().authenticated()
				.and()
			.formLogin()
				.and()
			.oauth2()
				.client();
		return http.build();
	}

	@Bean
	ServerOAuth2AuthorizedClientRepository authorizedClientRepository(ReactiveOAuth2AuthorizedClientService authorizedClientService) {
		return new AuthenticatedPrincipalServerOAuth2AuthorizedClientRepository(authorizedClientService);
	}

	@Bean
	MapReactiveUserDetailsService userDetailsService() {
		UserDetails userDetails = User.withDefaultPasswordEncoder()
			.username("user")
			.password("password")
			.roles("USER")
			.build();
		return new MapReactiveUserDetailsService(userDetails);
	}
}
