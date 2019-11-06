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

package sample;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.userdetails.MapReactiveUserDetailsService;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.server.SecurityWebFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

/**
 * @author Alexey Nesterov
 * @since 5.2
 */
@SpringBootApplication
public class WebfluxX509Application {

	@Bean
	public ReactiveUserDetailsService reactiveUserDetailsService() {
		return new MapReactiveUserDetailsService(
			User.withUsername("client").password("").authorities("ROLE_USER").build()
		);
	}

	@Bean
	public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
		// @formatter:off
		http
			.x509(withDefaults())
			.authorizeExchange(exchanges ->
				exchanges
					.anyExchange().authenticated()
			);
		// @formatter:on

		return http.build();
	}

	public static void main(String[] args) {
		SpringApplication.run(WebfluxX509Application.class);
	}
}
