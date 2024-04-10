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

package org.springframework.security.config.annotation.web.reactive;

import java.net.URI;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import reactor.core.publisher.Mono;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.password.CompromisedPasswordCheckResult;
import org.springframework.security.authentication.password.CompromisedPasswordException;
import org.springframework.security.authentication.password.ReactiveCompromisedPasswordChecker;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.config.users.ReactiveAuthenticationTestConfiguration;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.userdetails.MapReactiveUserDetailsService;
import org.springframework.security.core.userdetails.PasswordEncodedUser;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.server.DefaultServerRedirectStrategy;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.config.EnableWebFlux;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.server.adapter.WebHttpHandlerBuilder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.csrf;

/**
 * Tests for {@link ServerHttpSecurityConfiguration}.
 *
 * @author Eleftheria Stein
 */
@ExtendWith(SpringTestContextExtension.class)
public class ServerHttpSecurityConfigurationTests {

	public final SpringTestContext spring = new SpringTestContext(this);

	WebTestClient webClient;

	@Autowired
	void setup(ApplicationContext context) {
		if (!context.containsBean(WebHttpHandlerBuilder.WEB_HANDLER_BEAN_NAME)) {
			return;
		}
		this.webClient = WebTestClient.bindToApplicationContext(context).configureClient().build();
	}

	@Test
	public void loadConfigWhenReactiveUserDetailsServiceConfiguredThenServerHttpSecurityExists() {
		this.spring
			.register(ServerHttpSecurityConfiguration.class, ReactiveAuthenticationTestConfiguration.class,
					WebFluxSecurityConfiguration.class)
			.autowire();
		ServerHttpSecurity serverHttpSecurity = this.spring.getContext().getBean(ServerHttpSecurity.class);
		assertThat(serverHttpSecurity).isNotNull();
	}

	@Test
	public void loadConfigWhenProxyingEnabledAndSubclassThenServerHttpSecurityExists() {
		this.spring
			.register(SubclassConfig.class, ReactiveAuthenticationTestConfiguration.class,
					WebFluxSecurityConfiguration.class)
			.autowire();
		ServerHttpSecurity serverHttpSecurity = this.spring.getContext().getBean(ServerHttpSecurity.class);
		assertThat(serverHttpSecurity).isNotNull();
	}

	@Test
	void loginWhenCompromisePasswordCheckerConfiguredAndPasswordCompromisedThenUnauthorized() {
		this.spring.register(FormLoginConfig.class, UserDetailsConfig.class, CompromisedPasswordCheckerConfig.class)
			.autowire();
		MultiValueMap<String, String> data = new LinkedMultiValueMap<>();
		data.add("username", "user");
		data.add("password", "password");
		// @formatter:off
		this.webClient.mutateWith(csrf())
				.post()
				.uri("/login")
				.body(BodyInserters.fromFormData(data))
				.exchange()
				.expectStatus().is3xxRedirection()
				.expectHeader().location("/login?error");
		// @formatter:on
	}

	@Test
	void loginWhenCompromisePasswordCheckerConfiguredAndPasswordNotCompromisedThenUnauthorized() {
		this.spring.register(FormLoginConfig.class, UserDetailsConfig.class, CompromisedPasswordCheckerConfig.class)
			.autowire();
		MultiValueMap<String, String> data = new LinkedMultiValueMap<>();
		data.add("username", "admin");
		data.add("password", "password2");
		// @formatter:off
		this.webClient.mutateWith(csrf())
				.post()
				.uri("/login")
				.body(BodyInserters.fromFormData(data))
				.exchange()
				.expectStatus().is3xxRedirection()
				.expectHeader().location("/");
		// @formatter:on
	}

	@Test
	void loginWhenCompromisedPasswordAndRedirectIfPasswordExceptionThenRedirectedToResetPassword() {
		this.spring
			.register(FormLoginRedirectToResetPasswordConfig.class, UserDetailsConfig.class,
					CompromisedPasswordCheckerConfig.class)
			.autowire();
		MultiValueMap<String, String> data = new LinkedMultiValueMap<>();
		data.add("username", "user");
		data.add("password", "password");
		// @formatter:off
		this.webClient.mutateWith(csrf())
				.post()
				.uri("/login")
				.body(BodyInserters.fromFormData(data))
				.exchange()
				.expectStatus().is3xxRedirection()
				.expectHeader().location("/reset-password");
		// @formatter:on
	}

	@Configuration
	static class SubclassConfig extends ServerHttpSecurityConfiguration {

	}

	@Configuration(proxyBeanMethods = false)
	@EnableWebFlux
	@EnableWebFluxSecurity
	static class FormLoginConfig {

		@Bean
		SecurityWebFilterChain filterChain(ServerHttpSecurity http) {
			// @formatter:off
			http
					.authorizeExchange((exchange) -> exchange
						.anyExchange().authenticated()
					)
					.formLogin(Customizer.withDefaults());
			// @formatter:on
			return http.build();
		}

	}

	@Configuration(proxyBeanMethods = false)
	@EnableWebFlux
	@EnableWebFluxSecurity
	static class FormLoginRedirectToResetPasswordConfig {

		@Bean
		SecurityWebFilterChain filterChain(ServerHttpSecurity http) {
			// @formatter:off
			http
					.authorizeExchange((exchange) -> exchange
						.anyExchange().authenticated()
					)
					.formLogin((form) -> form
							.authenticationFailureHandler((webFilterExchange, exception) -> {
								String redirectUrl = "/login?error";
								if (exception instanceof CompromisedPasswordException) {
									redirectUrl = "/reset-password";
								}
								return new DefaultServerRedirectStrategy().sendRedirect(webFilterExchange.getExchange(), URI.create(redirectUrl));
							})
					);
			// @formatter:on
			return http.build();
		}

	}

	@Configuration(proxyBeanMethods = false)
	static class UserDetailsConfig {

		@Bean
		MapReactiveUserDetailsService userDetailsService() {
			// @formatter:off
			UserDetails user = PasswordEncodedUser.user();
			UserDetails admin = User.withDefaultPasswordEncoder()
					.username("admin")
					.password("password2")
					.roles("USER", "ADMIN")
					.build();
			// @formatter:on
			return new MapReactiveUserDetailsService(user, admin);
		}

	}

	@Configuration(proxyBeanMethods = false)
	static class CompromisedPasswordCheckerConfig {

		@Bean
		TestReactivePasswordChecker compromisedPasswordChecker() {
			return new TestReactivePasswordChecker();
		}

	}

	static class TestReactivePasswordChecker implements ReactiveCompromisedPasswordChecker {

		@Override
		public Mono<CompromisedPasswordCheckResult> check(String password) {
			if ("password".equals(password)) {
				return Mono.just(new CompromisedPasswordCheckResult(true));
			}
			return Mono.just(new CompromisedPasswordCheckResult(false));
		}

	}

}
