/*
 *
 *  * Copyright 2002-2017 the original author or authors.
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *      http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */

package sample;

import org.springframework.context.annotation.Bean;
import org.springframework.security.core.userdetails.MapUserDetailsRepository;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.server.WebFilterChainFilter;
import org.springframework.security.web.server.authorization.AuthorizationContext;
import reactor.core.publisher.Mono;

/**
 * @author Rob Winch
 * @since 5.0
 */
@EnableWebFluxSecurity
public class SecurityConfig {

	@Bean
	WebFilterChainFilter springSecurityFilterChain(HttpSecurity http) throws Exception {
		http.authorizeExchange()
			.antMatchers("/admin/**").hasRole("ADMIN")
			.antMatchers("/users/{user}/**").access(this::currentUserMatchesPath)
			.anyExchange().authenticated();

		return http.build();
	}

	private Mono<AuthorizationDecision> currentUserMatchesPath(Mono<Authentication> authentication, AuthorizationContext context) {
		return authentication
			.map( a -> context.getVariables().get("user").equals(a.getName()))
			.map( granted -> new AuthorizationDecision(granted));
	}

	@Bean
	public MapUserDetailsRepository userDetailsRepository() {
		UserDetails rob = User.withUsername("rob").password("rob").roles("USER").build();
		UserDetails admin = User.withUsername("admin").password("admin").roles("USER","ADMIN").build();
		return new MapUserDetailsRepository(rob, admin);
	}

}
