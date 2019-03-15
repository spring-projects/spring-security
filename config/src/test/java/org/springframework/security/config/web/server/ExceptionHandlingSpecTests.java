/*
 * Copyright 2002-2018 the original author or authors.
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
package org.springframework.security.config.web.server;

import org.junit.Test;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.reactive.ServerHttpSecurityConfigurationBuilder;
import org.springframework.security.test.web.reactive.server.WebTestClientBuilder;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationEntryPoint;
import org.springframework.security.web.server.authorization.HttpStatusServerAccessDeniedHandler;
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler;
import org.springframework.test.web.reactive.server.WebTestClient;
import static org.springframework.web.reactive.function.client.ExchangeFilterFunctions.Credentials.basicAuthenticationCredentials;
import static org.springframework.web.reactive.function.client.ExchangeFilterFunctions.basicAuthentication;

/**
 * @author Denys Ivano
 * @since 5.0.5
 */
public class ExceptionHandlingSpecTests {
	private ServerHttpSecurity http = ServerHttpSecurityConfigurationBuilder.httpWithDefaultAuthentication();

	@Test
	public void defaultAuthenticationEntryPoint() {
		SecurityWebFilterChain securityWebFilter = this.http
			.csrf().disable()
			.authorizeExchange()
				.anyExchange().authenticated()
				.and()
			.exceptionHandling()
				.and()
			.build();

		WebTestClient client = WebTestClientBuilder
			.bindToWebFilters(securityWebFilter)
			.build();

		client
			.get()
			.uri("/test")
			.exchange()
			.expectStatus().isUnauthorized()
			.expectHeader().valueMatches("WWW-Authenticate", "Basic.*");
	}

	@Test
	public void customAuthenticationEntryPoint() {
		SecurityWebFilterChain securityWebFilter = this.http
			.csrf().disable()
			.authorizeExchange()
				.anyExchange().authenticated()
				.and()
			.exceptionHandling()
				.authenticationEntryPoint(redirectServerAuthenticationEntryPoint("/auth"))
				.and()
			.build();

		WebTestClient client = WebTestClientBuilder
			.bindToWebFilters(securityWebFilter)
			.build();

		client
			.get()
			.uri("/test")
			.exchange()
			.expectStatus().isFound()
			.expectHeader().valueMatches("Location", ".*");
	}

	@Test
	public void defaultAccessDeniedHandler() {
		SecurityWebFilterChain securityWebFilter = this.http
			.csrf().disable()
			.httpBasic().and()
			.authorizeExchange()
				.anyExchange().hasRole("ADMIN")
				.and()
			.exceptionHandling()
				.and()
			.build();

		WebTestClient client = WebTestClientBuilder
			.bindToWebFilters(securityWebFilter)
			.filter(basicAuthentication())
			.build();

		client
			.get()
			.uri("/admin")
			.attributes(basicAuthenticationCredentials("user", "password"))
			.exchange()
			.expectStatus().isForbidden();
	}

	@Test
	public void customAccessDeniedHandler() {
		SecurityWebFilterChain securityWebFilter = this.http
			.csrf().disable()
			.httpBasic().and()
			.authorizeExchange()
				.anyExchange().hasRole("ADMIN")
				.and()
			.exceptionHandling()
				.accessDeniedHandler(httpStatusServerAccessDeniedHandler(HttpStatus.BAD_REQUEST))
				.and()
			.build();

		WebTestClient client = WebTestClientBuilder
			.bindToWebFilters(securityWebFilter)
			.filter(basicAuthentication())
			.build();

		client
			.get()
			.uri("/admin")
			.attributes(basicAuthenticationCredentials("user", "password"))
			.exchange()
			.expectStatus().isBadRequest();
	}

	private ServerAuthenticationEntryPoint redirectServerAuthenticationEntryPoint(String location) {
		return new RedirectServerAuthenticationEntryPoint(location);
	}

	private ServerAccessDeniedHandler httpStatusServerAccessDeniedHandler(HttpStatus httpStatus) {
		return new HttpStatusServerAccessDeniedHandler(httpStatus);
	}
}
