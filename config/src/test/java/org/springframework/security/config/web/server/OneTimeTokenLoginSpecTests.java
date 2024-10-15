/*
 * Copyright 2002-2024 the original author or authors.
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

import java.util.Collections;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import reactor.core.publisher.Mono;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.ott.OneTimeToken;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.core.userdetails.MapReactiveUserDetailsService;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.authentication.ott.ServerOneTimeTokenGenerationSuccessHandler;
import org.springframework.security.web.server.authentication.ott.ServerRedirectOneTimeTokenGenerationSuccessHandler;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.reactive.config.EnableWebFlux;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.server.ServerWebExchange;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatException;

/**
 * Tests for {@link ServerHttpSecurity.OneTimeTokenLoginSpec}
 *
 * @author Max Batischev
 */
@ExtendWith(SpringTestContextExtension.class)
public class OneTimeTokenLoginSpecTests {

	public final SpringTestContext spring = new SpringTestContext(this);

	private WebTestClient client;

	private static final String EXPECTED_HTML_HEAD = """
			<!DOCTYPE html>
			<html lang="en">
			  <head>
			    <meta charset="utf-8">
			    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
			    <meta name="description" content="">
			    <meta name="author" content="">
			    <title>Please sign in</title>
			    <link href="/default-ui.css" rel="stylesheet" />
			  </head>
			""";

	private static final String LOGIN_PART = """
			<form class="login-form" method="post" action="/login">
			""";

	private static final String GENERATE_OTT_PART = """
			<form id="ott-form" class="login-form" method="post" action="/ott/generate">
			""";

	@Autowired
	public void setApplicationContext(ApplicationContext context) {
		this.client = WebTestClient.bindToApplicationContext(context).build();
	}

	@Test
	void oneTimeTokenWhenCorrectTokenThenCanAuthenticate() {
		this.spring.register(OneTimeTokenDefaultConfig.class).autowire();

		// @formatter:off
		this.client.mutateWith(SecurityMockServerConfigurers.csrf())
				.post()
				.uri((uriBuilder) -> uriBuilder
						.path("/ott/generate")
						.build()
				)
				.contentType(MediaType.APPLICATION_FORM_URLENCODED)
				.body(BodyInserters.fromFormData("username", "user"))
				.exchange()
				.expectStatus()
				.is3xxRedirection()
				.expectHeader().valueEquals("Location", "/login/ott");
		// @formatter:on

		String token = TestServerOneTimeTokenGenerationSuccessHandler.lastToken.getTokenValue();

		// @formatter:off
		this.client.mutateWith(SecurityMockServerConfigurers.csrf())
				.post()
				.uri((uriBuilder) -> uriBuilder
						.path("/login/ott")
						.queryParam("token", token)
						.build()
				)
				.exchange()
				.expectStatus()
				.is3xxRedirection()
				.expectHeader().valueEquals("Location", "/");
		// @formatter:on
	}

	@Test
	void oneTimeTokenWhenDifferentAuthenticationUrlsThenCanAuthenticate() {
		this.spring.register(OneTimeTokenDifferentUrlsConfig.class).autowire();

		// @formatter:off
		this.client.mutateWith(SecurityMockServerConfigurers.csrf())
				.post()
				.uri((uriBuilder) -> uriBuilder
						.path("/generateurl")
						.build()
				)
				.contentType(MediaType.APPLICATION_FORM_URLENCODED)
				.body(BodyInserters.fromValue("username=user"))
				.exchange()
				.expectStatus()
				.is3xxRedirection()
				.expectHeader().valueEquals("Location", "/redirected");
		// @formatter:on

		String token = TestServerOneTimeTokenGenerationSuccessHandler.lastToken.getTokenValue();

		// @formatter:off
		this.client.mutateWith(SecurityMockServerConfigurers.csrf())
				.post()
				.uri((uriBuilder) -> uriBuilder
						.path("/loginprocessingurl")
						.queryParam("token", token)
						.build()
				)
				.exchange()
				.expectStatus()
				.is3xxRedirection()
				.expectHeader().valueEquals("Location", "/authenticated");
		// @formatter:on
	}

	@Test
	void oneTimeTokenWhenCorrectTokenUsedTwiceThenSecondTimeFails() {
		this.spring.register(OneTimeTokenDefaultConfig.class).autowire();

		// @formatter:off
		this.client.mutateWith(SecurityMockServerConfigurers.csrf())
				.post()
				.uri((uriBuilder) -> uriBuilder
						.path("/ott/generate")
						.build()
				)
				.contentType(MediaType.APPLICATION_FORM_URLENCODED)
				.body(BodyInserters.fromValue("username=user"))
				.exchange()
				.expectStatus()
				.is3xxRedirection()
				.expectHeader().valueEquals("Location", "/login/ott");
		// @formatter:on

		String token = TestServerOneTimeTokenGenerationSuccessHandler.lastToken.getTokenValue();

		// @formatter:off
		this.client.mutateWith(SecurityMockServerConfigurers.csrf())
				.post()
				.uri((uriBuilder) -> uriBuilder
						.path("/login/ott")
						.queryParam("token", token)
						.build()
				)
				.exchange()
				.expectStatus()
				.is3xxRedirection()
				.expectHeader().valueEquals("Location", "/");

		this.client.mutateWith(SecurityMockServerConfigurers.csrf())
				.post()
				.uri((uriBuilder) -> uriBuilder
						.path("/login/ott")
						.queryParam("token", token)
						.build()
				)
				.exchange()
				.expectStatus()
				.is3xxRedirection()
				.expectHeader().valueEquals("Location", "/login?error");
		// @formatter:on
	}

	@Test
	void oneTimeTokenWhenWrongTokenThenAuthenticationFail() {
		this.spring.register(OneTimeTokenDefaultConfig.class).autowire();

		// @formatter:off
		this.client.mutateWith(SecurityMockServerConfigurers.csrf())
				.post()
				.uri((uriBuilder) -> uriBuilder
						.path("/ott/generate")
						.build()
				)
				.contentType(MediaType.APPLICATION_FORM_URLENCODED)
				.body(BodyInserters.fromValue("username=user"))
				.exchange()
				.expectStatus()
				.is3xxRedirection()
				.expectHeader().valueEquals("Location", "/login/ott");
		// @formatter:on

		String token = "wrong";

		// @formatter:off
		this.client.mutateWith(SecurityMockServerConfigurers.csrf())
				.post()
				.uri((uriBuilder) -> uriBuilder
						.path("/login/ott")
						.queryParam("token", token)
						.build()
				)
				.exchange()
				.expectStatus()
				.is3xxRedirection()
				.expectHeader().valueEquals("Location", "/login?error");
		// @formatter:on
	}

	@Test
	void oneTimeTokenWhenFormLoginConfiguredThenRendersRequestTokenForm() {
		this.spring.register(OneTimeTokenFormLoginConfig.class).autowire();

		//@formatter:off
		byte[] responseByteArray = this.client.mutateWith(SecurityMockServerConfigurers.csrf())
				.get()
				.uri((uriBuilder) -> uriBuilder
						.path("/login")
						.build()
				)
				.exchange()
				.expectBody()
				.returnResult()
				.getResponseBody();
		// @formatter:on

		String response = new String(responseByteArray);

		assertThat(response.contains(EXPECTED_HTML_HEAD)).isTrue();
		assertThat(response.contains(LOGIN_PART)).isTrue();
		assertThat(response.contains(GENERATE_OTT_PART)).isTrue();
	}

	@Test
	void oneTimeTokenWhenNoOneTimeTokenGenerationSuccessHandlerThenException() {
		assertThatException()
			.isThrownBy(() -> this.spring.register(OneTimeTokenNotGeneratedOttHandlerConfig.class).autowire())
			.havingRootCause()
			.isInstanceOf(IllegalStateException.class)
			.withMessage("""
					A ServerOneTimeTokenGenerationSuccessHandler is required to enable oneTimeTokenLogin().
					Please provide it as a bean or pass it to the oneTimeTokenLogin() DSL.
					""");
	}

	@Configuration(proxyBeanMethods = false)
	@EnableWebFlux
	@EnableWebFluxSecurity
	@Import(UserDetailsServiceConfig.class)
	static class OneTimeTokenDefaultConfig {

		@Bean
		SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
			// @formatter:off
			http
					.authorizeExchange((authorize) -> authorize
							.anyExchange()
							.authenticated()
					)
					.oneTimeTokenLogin((ott) -> ott
							.tokenGenerationSuccessHandler(new TestServerOneTimeTokenGenerationSuccessHandler())
					);
			// @formatter:on
			return http.build();
		}

	}

	@Configuration(proxyBeanMethods = false)
	@EnableWebFlux
	@EnableWebFluxSecurity
	@Import(UserDetailsServiceConfig.class)
	static class OneTimeTokenDifferentUrlsConfig {

		@Bean
		SecurityWebFilterChain securityFilterChain(ServerHttpSecurity http) {
			// @formatter:off
			http
					.authorizeExchange((authorize) -> authorize
							.anyExchange()
							.authenticated()
					)
					.oneTimeTokenLogin((ott) -> ott
							.tokenGeneratingUrl("/generateurl")
							.tokenGenerationSuccessHandler(new TestServerOneTimeTokenGenerationSuccessHandler("/redirected"))
							.loginProcessingUrl("/loginprocessingurl")
							.authenticationSuccessHandler(new RedirectServerAuthenticationSuccessHandler("/authenticated"))
					);
			// @formatter:on
			return http.build();
		}

	}

	@Configuration(proxyBeanMethods = false)
	@EnableWebFlux
	@EnableWebFluxSecurity
	@Import(UserDetailsServiceConfig.class)
	static class OneTimeTokenFormLoginConfig {

		@Bean
		SecurityWebFilterChain securityFilterChain(ServerHttpSecurity http) {
			// @formatter:off
			http
					.authorizeExchange((authorize) -> authorize
							.anyExchange()
							.authenticated()
					)
					.formLogin(Customizer.withDefaults())
					.oneTimeTokenLogin((ott) -> ott
							.tokenGenerationSuccessHandler(new TestServerOneTimeTokenGenerationSuccessHandler())
					);
			// @formatter:on
			return http.build();
		}

	}

	@Configuration(proxyBeanMethods = false)
	@EnableWebFlux
	@EnableWebFluxSecurity
	@Import(UserDetailsServiceConfig.class)
	static class OneTimeTokenNotGeneratedOttHandlerConfig {

		@Bean
		SecurityWebFilterChain securityFilterChain(ServerHttpSecurity http) {
			// @formatter:off
			http
					.authorizeExchange((authorize) -> authorize
							.anyExchange()
							.authenticated()
					)
					.oneTimeTokenLogin(Customizer.withDefaults());
			// @formatter:on
			return http.build();
		}

	}

	@Configuration(proxyBeanMethods = false)
	static class UserDetailsServiceConfig {

		@Bean
		ReactiveUserDetailsService userDetailsService() {
			return new MapReactiveUserDetailsService(
					Map.of("user", new User("user", "password", Collections.emptyList())));
		}

	}

	private static class TestServerOneTimeTokenGenerationSuccessHandler
			implements ServerOneTimeTokenGenerationSuccessHandler {

		private static OneTimeToken lastToken;

		private final ServerOneTimeTokenGenerationSuccessHandler delegate;

		TestServerOneTimeTokenGenerationSuccessHandler() {
			this.delegate = new ServerRedirectOneTimeTokenGenerationSuccessHandler("/login/ott");
		}

		TestServerOneTimeTokenGenerationSuccessHandler(String redirectUrl) {
			this.delegate = new ServerRedirectOneTimeTokenGenerationSuccessHandler(redirectUrl);
		}

		@Override
		public Mono<Void> handle(ServerWebExchange exchange, OneTimeToken oneTimeToken) {
			lastToken = oneTimeToken;
			return this.delegate.handle(exchange, oneTimeToken);
		}

	}

}
