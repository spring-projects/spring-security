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

package org.springframework.security.config.annotation.web.reactive;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.net.URI;
import java.util.Iterator;

import io.micrometer.observation.Observation;
import io.micrometer.observation.ObservationHandler;
import io.micrometer.observation.ObservationRegistry;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import reactor.core.publisher.Mono;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.messaging.rsocket.annotation.support.RSocketMessageHandler;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authentication.password.CompromisedPasswordDecision;
import org.springframework.security.authentication.password.CompromisedPasswordException;
import org.springframework.security.authentication.password.ReactiveCompromisedPasswordChecker;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.rsocket.EnableRSocketSecurity;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.config.users.ReactiveAuthenticationTestConfiguration;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AnnotationTemplateExpressionDefaults;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.annotation.CurrentSecurityContext;
import org.springframework.security.core.userdetails.MapReactiveUserDetailsService;
import org.springframework.security.core.userdetails.PasswordEncodedUser;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.server.DefaultServerRedirectStrategy;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.config.EnableWebFlux;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.server.adapter.WebHttpHandlerBuilder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.springframework.security.config.Customizer.withDefaults;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.csrf;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockAuthentication;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

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
		this.webClient = WebTestClient.bindToApplicationContext(context)
			.apply(springSecurity())
			.configureClient()
			.build();
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

	@Test
	public void metaAnnotationWhenTemplateDefaultsBeanThenResolvesExpression() throws Exception {
		this.spring.register(MetaAnnotationPlaceholderConfig.class).autowire();
		Authentication user = new TestingAuthenticationToken("user", "password", "ROLE_USER");
		this.webClient.mutateWith(mockAuthentication(user))
			.get()
			.uri("/hi")
			.exchange()
			.expectStatus()
			.isOk()
			.expectBody(String.class)
			.isEqualTo("Hi, Stranger!");
		Authentication harold = new TestingAuthenticationToken("harold", "password", "ROLE_USER");
		this.webClient.mutateWith(mockAuthentication(harold))
			.get()
			.uri("/hi")
			.exchange()
			.expectBody(String.class)
			.isEqualTo("Hi, Harold!");
	}

	@Test
	public void resoleMetaAnnotationWhenTemplateDefaultsBeanThenResolvesExpression() throws Exception {
		this.spring.register(MetaAnnotationPlaceholderConfig.class).autowire();
		Authentication user = new TestingAuthenticationToken("user", "password", "ROLE_USER");
		this.webClient.mutateWith(mockAuthentication(user))
			.get()
			.uri("/hello")
			.exchange()
			.expectStatus()
			.isOk()
			.expectBody(String.class)
			.isEqualTo("user");
		Authentication harold = new TestingAuthenticationToken("harold", "password", "ROLE_USER");
		this.webClient.mutateWith(mockAuthentication(harold))
			.get()
			.uri("/hello")
			.exchange()
			.expectBody(String.class)
			.isEqualTo("harold");
	}

	@Test
	public void getWhenUsingObservationRegistryThenObservesRequest() {
		this.spring.register(ObservationRegistryConfig.class).autowire();
		// @formatter:off
		this.webClient
				.get()
				.uri("/hello")
				.headers((headers) -> headers.setBasicAuth("user", "password"))
				.exchange()
				.expectStatus()
				.isNotFound();
		// @formatter:on
		ObservationHandler<Observation.Context> handler = this.spring.getContext().getBean(ObservationHandler.class);
		ArgumentCaptor<Observation.Context> captor = ArgumentCaptor.forClass(Observation.Context.class);
		verify(handler, times(6)).onStart(captor.capture());
		Iterator<Observation.Context> contexts = captor.getAllValues().iterator();
		assertThat(contexts.next().getContextualName()).isEqualTo("http get");
		assertThat(contexts.next().getContextualName()).isEqualTo("security filterchain before");
		assertThat(contexts.next().getName()).isEqualTo("spring.security.authentications");
		assertThat(contexts.next().getName()).isEqualTo("spring.security.authorizations");
		assertThat(contexts.next().getName()).isEqualTo("spring.security.http.secured.requests");
		assertThat(contexts.next().getContextualName()).isEqualTo("security filterchain after");
	}

	// gh-16161
	@Test
	public void getWhenUsingRSocketThenObservesRequest() {
		this.spring.register(ObservationRegistryConfig.class, RSocketSecurityConfig.class).autowire();
		// @formatter:off
		this.webClient
				.get()
				.uri("/hello")
				.headers((headers) -> headers.setBasicAuth("user", "password"))
				.exchange()
				.expectStatus()
				.isNotFound();
		// @formatter:on
		ObservationHandler<Observation.Context> handler = this.spring.getContext().getBean(ObservationHandler.class);
		ArgumentCaptor<Observation.Context> captor = ArgumentCaptor.forClass(Observation.Context.class);
		verify(handler, times(6)).onStart(captor.capture());
		Iterator<Observation.Context> contexts = captor.getAllValues().iterator();
		assertThat(contexts.next().getContextualName()).isEqualTo("http get");
		assertThat(contexts.next().getContextualName()).isEqualTo("security filterchain before");
		assertThat(contexts.next().getName()).isEqualTo("spring.security.authentications");
		assertThat(contexts.next().getName()).isEqualTo("spring.security.authorizations");
		assertThat(contexts.next().getName()).isEqualTo("spring.security.http.secured.requests");
		assertThat(contexts.next().getContextualName()).isEqualTo("security filterchain after");
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
		public Mono<CompromisedPasswordDecision> check(String password) {
			if ("password".equals(password)) {
				return Mono.just(new CompromisedPasswordDecision(true));
			}
			return Mono.just(new CompromisedPasswordDecision(false));
		}

	}

	@Retention(RetentionPolicy.RUNTIME)
	@Target(ElementType.PARAMETER)
	@AuthenticationPrincipal(expression = "#this.equals('{value}')")
	@interface IsUser {

		String value() default "user";

	}

	@Target({ ElementType.PARAMETER })
	@Retention(RetentionPolicy.RUNTIME)
	@CurrentSecurityContext(expression = "authentication.{property}")
	@interface CurrentAuthenticationProperty {

		String property();

	}

	@RestController
	static class TestController {

		@GetMapping("/hi")
		String ifUser(@IsUser("harold") boolean isHarold) {
			if (isHarold) {
				return "Hi, Harold!";
			}
			else {
				return "Hi, Stranger!";
			}
		}

		@GetMapping("/hello")
		String getCurrentAuthenticationProperty(
				@CurrentAuthenticationProperty(property = "principal") String principal) {
			return principal;
		}

	}

	@Configuration
	@EnableWebFlux
	@EnableWebFluxSecurity
	static class MetaAnnotationPlaceholderConfig {

		@Bean
		SecurityWebFilterChain filterChain(ServerHttpSecurity http) {
			// @formatter:off
			http
				.authorizeExchange((authorize) -> authorize.anyExchange().authenticated())
				.httpBasic(Customizer.withDefaults());
			// @formatter:on
			return http.build();
		}

		@Bean
		ReactiveUserDetailsService userDetailsService() {
			return new MapReactiveUserDetailsService(
					User.withUsername("user").password("password").authorities("app").build());
		}

		@Bean
		TestController testController() {
			return new TestController();
		}

		@Bean
		AnnotationTemplateExpressionDefaults templateExpressionDefaults() {
			return new AnnotationTemplateExpressionDefaults();
		}

	}

	@Configuration
	@EnableWebFlux
	@EnableWebFluxSecurity
	static class ObservationRegistryConfig {

		private ObservationHandler<Observation.Context> handler = mock(ObservationHandler.class);

		@Bean
		SecurityWebFilterChain app(ServerHttpSecurity http) throws Exception {
			http.httpBasic(withDefaults()).authorizeExchange((authorize) -> authorize.anyExchange().authenticated());
			return http.build();
		}

		@Bean
		ReactiveUserDetailsService userDetailsService() {
			return new MapReactiveUserDetailsService(
					User.withDefaultPasswordEncoder().username("user").password("password").authorities("app").build());
		}

		@Bean
		ObservationHandler<Observation.Context> observationHandler() {
			return this.handler;
		}

		@Bean
		ObservationRegistry observationRegistry() {
			given(this.handler.supportsContext(any())).willReturn(true);
			ObservationRegistry registry = ObservationRegistry.create();
			registry.observationConfig().observationHandler(this.handler);
			return registry;
		}

	}

	@EnableRSocketSecurity
	static class RSocketSecurityConfig {

		@Bean
		RSocketMessageHandler messageHandler() {
			return new RSocketMessageHandler();
		}

	}

}
