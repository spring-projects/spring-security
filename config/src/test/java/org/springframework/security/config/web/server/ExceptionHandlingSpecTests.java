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

package org.springframework.security.config.web.server;

import org.junit.jupiter.api.Test;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.ServerHttpSecurityConfigurationBuilder;
import org.springframework.security.test.web.reactive.server.WebTestClientBuilder;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.security.web.server.authentication.HttpStatusServerEntryPoint;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationEntryPoint;
import org.springframework.security.web.server.authorization.HttpStatusServerAccessDeniedHandler;
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;
import org.springframework.test.web.reactive.server.WebTestClient;

import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.springframework.security.config.Customizer.withDefaults;

/**
 * @author Denys Ivano
 * @since 5.0.5
 */
public class ExceptionHandlingSpecTests {

	private ServerHttpSecurity http = ServerHttpSecurityConfigurationBuilder.httpWithDefaultAuthentication();

	@Test
	public void defaultAuthenticationEntryPoint() {
		// @formatter:off
		SecurityWebFilterChain securityWebFilter = this.http
			.csrf((csrf) -> csrf.disable())
			.authorizeExchange((authorize) -> authorize
				.anyExchange().authenticated())
			.exceptionHandling(withDefaults())
			.build();
		WebTestClient client = WebTestClientBuilder
				.bindToWebFilters(securityWebFilter)
				.build();
		client.get()
				.uri("/test")
				.exchange()
				.expectStatus().isUnauthorized()
				.expectHeader().valueMatches("WWW-Authenticate", "Basic.*");
		// @formatter:on
	}

	@Test
	public void requestWhenExceptionHandlingWithDefaultsInLambdaThenDefaultAuthenticationEntryPointUsed() {
		// @formatter:off
		SecurityWebFilterChain securityWebFilter = this.http
				.authorizeExchange((authorize) -> authorize
						.anyExchange().authenticated()
				)
				.exceptionHandling(withDefaults())
				.build();
		WebTestClient client = WebTestClientBuilder
				.bindToWebFilters(securityWebFilter)
				.build();
		client.get()
				.uri("/test")
				.exchange()
				.expectStatus().isUnauthorized()
				.expectHeader().valueMatches("WWW-Authenticate", "Basic.*");
		// @formatter:on
	}

	@Test
	public void customAuthenticationEntryPoint() {
		// @formatter:off
		SecurityWebFilterChain securityWebFilter = this.http
			.csrf((csrf) -> csrf.disable())
			.authorizeExchange((authorize) -> authorize
				.anyExchange().authenticated())
			.exceptionHandling((handling) -> handling
				.authenticationEntryPoint(redirectServerAuthenticationEntryPoint("/auth")))
			.build();
		WebTestClient client = WebTestClientBuilder
				.bindToWebFilters(securityWebFilter)
				.build();
		client.get()
				.uri("/test")
				.exchange()
				.expectStatus().isFound()
				.expectHeader().valueMatches("Location", ".*");
		// @formatter:on
	}

	@Test
	public void requestWhenCustomAuthenticationEntryPointInLambdaThenCustomAuthenticationEntryPointUsed() {
		// @formatter:off
		SecurityWebFilterChain securityWebFilter = this.http
				.authorizeExchange((authorize) -> authorize
						.anyExchange().authenticated()
				)
				.exceptionHandling((exceptionHandling) -> exceptionHandling
						.authenticationEntryPoint(redirectServerAuthenticationEntryPoint("/auth"))
				)
				.build();
		WebTestClient client = WebTestClientBuilder
				.bindToWebFilters(securityWebFilter)
				.build();
		client.get()
				.uri("/test")
				.exchange()
				.expectStatus().isFound()
				.expectHeader().valueMatches("Location", ".*");
		// @formatter:on
	}

	@Test
	public void requestWhenDefaultAuthenticationEntryPointForMatchesThenPreferredEntryPointUsed() {
		// @formatter:off
		SecurityWebFilterChain securityWebFilter = this.http
				.authorizeExchange((authorize) -> authorize
						.anyExchange().authenticated()
				)
				.httpBasic(withDefaults())
				.exceptionHandling((exceptionHandling) -> exceptionHandling
						.defaultAuthenticationEntryPointFor(httpStatusServerEntryPoint(HttpStatus.I_AM_A_TEAPOT),
								ServerWebExchangeMatchers.pathMatchers("/api/**"))
				)
				.build();
		WebTestClient client = WebTestClientBuilder
				.bindToWebFilters(securityWebFilter)
				.build();
		client.get()
				.uri("/api/test")
				.exchange()
				.expectStatus().isEqualTo(HttpStatus.I_AM_A_TEAPOT);
		client.get()
				.uri("/test")
				.exchange()
				.expectStatus().isUnauthorized()
				.expectHeader().valueMatches("WWW-Authenticate", "Basic.*");
		// @formatter:on
	}

	@Test
	public void requestWhenDefaultAuthenticationEntryPointForAndFormLoginThenPreferredEntryPointTakesPrecedence() {
		// @formatter:off
		SecurityWebFilterChain securityWebFilter = this.http
				.authorizeExchange((authorize) -> authorize
						.anyExchange().authenticated()
				)
				.formLogin(withDefaults())
				.exceptionHandling((exceptionHandling) -> exceptionHandling
						.defaultAuthenticationEntryPointFor(httpStatusServerEntryPoint(HttpStatus.I_AM_A_TEAPOT),
								ServerWebExchangeMatchers.pathMatchers("/api/**"))
				)
				.build();
		WebTestClient client = WebTestClientBuilder
				.bindToWebFilters(securityWebFilter)
				.build();
		client.get()
				.uri("/api/test")
				.accept(MediaType.TEXT_HTML)
				.exchange()
				.expectStatus().isEqualTo(HttpStatus.I_AM_A_TEAPOT);
		client.get()
				.uri("/test")
				.accept(MediaType.TEXT_HTML)
				.exchange()
				.expectStatus().isFound()
				.expectHeader().location("/login");
		// @formatter:on
	}

	@Test
	public void requestWhenAuthenticationEntryPointAndDefaultAuthenticationEntryPointForThenAuthenticationEntryPointUsed() {
		// @formatter:off
		SecurityWebFilterChain securityWebFilter = this.http
				.authorizeExchange((authorize) -> authorize
						.anyExchange().authenticated()
				)
				.exceptionHandling((exceptionHandling) -> exceptionHandling
						.authenticationEntryPoint(redirectServerAuthenticationEntryPoint("/auth"))
						.defaultAuthenticationEntryPointFor(httpStatusServerEntryPoint(HttpStatus.I_AM_A_TEAPOT),
								ServerWebExchangeMatchers.pathMatchers("/api/**"))
				)
				.build();
		WebTestClient client = WebTestClientBuilder
				.bindToWebFilters(securityWebFilter)
				.build();
		client.get()
				.uri("/api/test")
				.exchange()
				.expectStatus().isFound()
				.expectHeader().location("/auth");
		// @formatter:on
	}

	@Test
	public void defaultAuthenticationEntryPointForWhenEntryPointNullThenIllegalArgumentException() {
		ServerWebExchangeMatcher matcher = ServerWebExchangeMatchers.pathMatchers("/api/**");
		assertThatIllegalArgumentException().isThrownBy(() -> this.http.exceptionHandling(
				(exceptionHandling) -> exceptionHandling.defaultAuthenticationEntryPointFor(null, matcher)));
	}

	@Test
	public void defaultAuthenticationEntryPointForWhenPreferredMatcherNullThenIllegalArgumentException() {
		ServerAuthenticationEntryPoint entryPoint = httpStatusServerEntryPoint(HttpStatus.I_AM_A_TEAPOT);
		assertThatIllegalArgumentException().isThrownBy(() -> this.http.exceptionHandling(
				(exceptionHandling) -> exceptionHandling.defaultAuthenticationEntryPointFor(entryPoint, null)));
	}

	@Test
	public void defaultAccessDeniedHandler() {
		// @formatter:off
		SecurityWebFilterChain securityWebFilter = this.http
			.csrf((csrf) -> csrf.disable())
			.httpBasic(Customizer.withDefaults())
			.authorizeExchange((authorize) -> authorize
				.anyExchange().hasRole("ADMIN"))
			.exceptionHandling(withDefaults())
			.build();
		WebTestClient client = WebTestClientBuilder
				.bindToWebFilters(securityWebFilter)
				.build();
		client.get()
				.uri("/admin")
				.headers((headers) -> headers.setBasicAuth("user", "password"))
				.exchange()
				.expectStatus().isForbidden();
		// @formatter:on
	}

	@Test
	public void requestWhenExceptionHandlingWithDefaultsInLambdaThenDefaultAccessDeniedHandlerUsed() {
		// @formatter:off
		SecurityWebFilterChain securityWebFilter = this.http
				.httpBasic(withDefaults())
				.authorizeExchange((authorize) -> authorize
						.anyExchange().hasRole("ADMIN")
				)
				.exceptionHandling(withDefaults())
				.build();
		WebTestClient client = WebTestClientBuilder
				.bindToWebFilters(securityWebFilter)
				.build();
		client.get()
				.uri("/admin")
				.headers((headers) -> headers.setBasicAuth("user", "password"))
				.exchange()
				.expectStatus().isForbidden();
		// @formatter:on
	}

	@Test
	public void customAccessDeniedHandler() {
		// @formatter:off
		SecurityWebFilterChain securityWebFilter = this.http
			.csrf((csrf) -> csrf.disable())
			.httpBasic(Customizer.withDefaults())
			.authorizeExchange((authorize) -> authorize
				.anyExchange().hasRole("ADMIN"))
			.exceptionHandling((handling) -> handling
				.accessDeniedHandler(httpStatusServerAccessDeniedHandler(HttpStatus.BAD_REQUEST)))
			.build();
		WebTestClient client = WebTestClientBuilder
				.bindToWebFilters(securityWebFilter)
				.build();
		client.get()
				.uri("/admin")
				.headers((headers) -> headers.setBasicAuth("user", "password"))
				.exchange()
				.expectStatus().isBadRequest();
		// @formatter:on
	}

	@Test
	public void requestWhenCustomAccessDeniedHandlerInLambdaThenCustomAccessDeniedHandlerUsed() {
		// @formatter:off
		SecurityWebFilterChain securityWebFilter = this.http
				.httpBasic(withDefaults())
				.authorizeExchange((authorize) -> authorize
						.anyExchange().hasRole("ADMIN")
				)
				.exceptionHandling((exceptionHandling) -> exceptionHandling
						.accessDeniedHandler(httpStatusServerAccessDeniedHandler(HttpStatus.BAD_REQUEST))
				)
				.build();
		WebTestClient client = WebTestClientBuilder
				.bindToWebFilters(securityWebFilter)
				.build();
		client.get()
				.uri("/admin")
				.headers((headers) -> headers.setBasicAuth("user", "password"))
				.exchange()
				.expectStatus().isBadRequest();
		// @formatter:on
	}

	private ServerAuthenticationEntryPoint redirectServerAuthenticationEntryPoint(String location) {
		return new RedirectServerAuthenticationEntryPoint(location);
	}

	private ServerAuthenticationEntryPoint httpStatusServerEntryPoint(HttpStatus httpStatus) {
		return new HttpStatusServerEntryPoint(httpStatus);
	}

	private ServerAccessDeniedHandler httpStatusServerAccessDeniedHandler(HttpStatus httpStatus) {
		return new HttpStatusServerAccessDeniedHandler(httpStatus);
	}

}
