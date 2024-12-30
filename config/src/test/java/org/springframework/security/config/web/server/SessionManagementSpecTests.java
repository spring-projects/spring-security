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

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import reactor.core.publisher.Mono;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseCookie;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.config.users.ReactiveAuthenticationTestConfiguration;
import org.springframework.security.core.session.InMemoryReactiveSessionRegistry;
import org.springframework.security.core.session.ReactiveSessionRegistry;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import org.springframework.security.oauth2.client.registration.InMemoryReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.TestOAuth2AccessTokens;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationExchange;
import org.springframework.security.oauth2.core.endpoint.TestOAuth2AuthorizationExchanges;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.core.user.TestOAuth2Users;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.InvalidateLeastUsedServerMaximumSessionsExceededHandler;
import org.springframework.security.web.server.authentication.PreventLoginServerMaximumSessionsExceededHandler;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.security.web.server.authentication.SessionLimit;
import org.springframework.security.web.server.context.WebSessionServerSecurityContextRepository;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.config.EnableWebFlux;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.server.adapter.WebHttpHandlerBuilder;
import org.springframework.web.server.session.DefaultWebSessionManager;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.csrf;

@ExtendWith({ SpringExtension.class, SpringTestContextExtension.class })
public class SessionManagementSpecTests {

	public final SpringTestContext spring = new SpringTestContext(this);

	WebTestClient client;

	@Autowired
	public void setApplicationContext(ApplicationContext context) {
		this.client = WebTestClient.bindToApplicationContext(context).build();
	}

	@Test
	void loginWhenMaxSessionPreventsLoginThenSecondLoginFails() {
		this.spring.register(ConcurrentSessionsMaxSessionPreventsLoginConfig.class).autowire();

		MultiValueMap<String, String> data = new LinkedMultiValueMap<>();
		data.add("username", "user");
		data.add("password", "password");

		ResponseCookie firstLoginSessionCookie = loginReturningCookie(data);

		// second login should fail
		ResponseCookie secondLoginSessionCookie = this.client.mutateWith(csrf())
			.post()
			.uri("/login")
			.contentType(MediaType.MULTIPART_FORM_DATA)
			.body(BodyInserters.fromFormData(data))
			.exchange()
			.expectHeader()
			.location("/login?error")
			.returnResult(Void.class)
			.getResponseCookies()
			.getFirst("SESSION");

		assertThat(secondLoginSessionCookie).isNull();

		// first login should still be valid
		this.client.mutateWith(csrf())
			.get()
			.uri("/")
			.cookie(firstLoginSessionCookie.getName(), firstLoginSessionCookie.getValue())
			.exchange()
			.expectStatus()
			.isOk();
	}

	@Test
	void httpBasicWhenUsingSavingAuthenticationInWebSessionAndPreventLoginThenSecondRequestFails() {
		this.spring.register(ConcurrentSessionsHttpBasicWithWebSessionMaxSessionPreventsLoginConfig.class).autowire();

		MultiValueMap<String, String> data = new LinkedMultiValueMap<>();
		data.add("username", "user");
		data.add("password", "password");

		// first request be successful
		ResponseCookie sessionCookie = this.client.get()
			.uri("/")
			.headers((headers) -> headers.setBasicAuth("user", "password"))
			.exchange()
			.expectStatus()
			.isOk()
			.expectCookie()
			.exists("SESSION")
			.returnResult(Void.class)
			.getResponseCookies()
			.getFirst("SESSION");

		// request with no session should fail
		this.client.get()
			.uri("/")
			.headers((headers) -> headers.setBasicAuth("user", "password"))
			.exchange()
			.expectStatus()
			.isUnauthorized();

		// request with session obtained from first request should be successful
		this.client.get()
			.uri("/")
			.headers((headers) -> headers.setBasicAuth("user", "password"))
			.cookie(sessionCookie.getName(), sessionCookie.getValue())
			.exchange()
			.expectStatus()
			.isOk();
	}

	@Test
	void loginWhenMaxSessionPerAuthenticationThenUserLoginFailsAndAdminLoginSucceeds() {
		ConcurrentSessionsMaxSessionPreventsLoginConfig.sessionLimit = (authentication) -> {
			if (authentication.getName().equals("admin")) {
				return Mono.empty();
			}
			return Mono.just(1);
		};
		this.spring.register(ConcurrentSessionsMaxSessionPreventsLoginConfig.class).autowire();

		MultiValueMap<String, String> data = new LinkedMultiValueMap<>();
		data.add("username", "user");
		data.add("password", "password");
		MultiValueMap<String, String> adminCreds = new LinkedMultiValueMap<>();
		adminCreds.add("username", "admin");
		adminCreds.add("password", "password");

		ResponseCookie userFirstLoginSessionCookie = loginReturningCookie(data);
		ResponseCookie adminFirstLoginSessionCookie = loginReturningCookie(adminCreds);
		// second user login should fail
		this.client.mutateWith(csrf())
			.post()
			.uri("/login")
			.contentType(MediaType.MULTIPART_FORM_DATA)
			.body(BodyInserters.fromFormData(data))
			.exchange()
			.expectHeader()
			.location("/login?error");
		// first login should still be valid
		this.client.mutateWith(csrf())
			.get()
			.uri("/")
			.cookie(userFirstLoginSessionCookie.getName(), userFirstLoginSessionCookie.getValue())
			.exchange()
			.expectStatus()
			.isOk();
		ResponseCookie adminSecondLoginSessionCookie = loginReturningCookie(adminCreds);
		this.client.mutateWith(csrf())
			.get()
			.uri("/")
			.cookie(adminFirstLoginSessionCookie.getName(), adminFirstLoginSessionCookie.getValue())
			.exchange()
			.expectStatus()
			.isOk();
		this.client.mutateWith(csrf())
			.get()
			.uri("/")
			.cookie(adminSecondLoginSessionCookie.getName(), adminSecondLoginSessionCookie.getValue())
			.exchange()
			.expectStatus()
			.isOk();
	}

	@Test
	void loginWhenMaxSessionDoesNotPreventLoginThenSecondLoginSucceedsAndFirstSessionIsInvalidated() {
		ConcurrentSessionsMaxSessionPreventsLoginFalseConfig.sessionLimit = SessionLimit.of(1);
		this.spring.register(ConcurrentSessionsMaxSessionPreventsLoginFalseConfig.class).autowire();

		MultiValueMap<String, String> data = new LinkedMultiValueMap<>();
		data.add("username", "user");
		data.add("password", "password");

		ResponseCookie firstLoginSessionCookie = loginReturningCookie(data);
		ResponseCookie secondLoginSessionCookie = loginReturningCookie(data);

		// first login should not be valid
		this.client.get()
			.uri("/")
			.cookie(firstLoginSessionCookie.getName(), firstLoginSessionCookie.getValue())
			.exchange()
			.expectStatus()
			.isFound()
			.expectHeader()
			.location("/login");

		// second login should be valid
		this.client.get()
			.uri("/")
			.cookie(secondLoginSessionCookie.getName(), secondLoginSessionCookie.getValue())
			.exchange()
			.expectStatus()
			.isOk();
	}

	@Test
	void loginWhenMaxSessionDoesNotPreventLoginThenLeastRecentlyUsedSessionIsInvalidated() {
		ConcurrentSessionsMaxSessionPreventsLoginFalseConfig.sessionLimit = SessionLimit.of(2);
		this.spring.register(ConcurrentSessionsMaxSessionPreventsLoginFalseConfig.class).autowire();

		MultiValueMap<String, String> data = new LinkedMultiValueMap<>();
		data.add("username", "user");
		data.add("password", "password");

		ResponseCookie firstLoginSessionCookie = loginReturningCookie(data);
		ResponseCookie secondLoginSessionCookie = loginReturningCookie(data);

		// update last access time for first request
		this.client.get()
			.uri("/")
			.cookie(firstLoginSessionCookie.getName(), firstLoginSessionCookie.getValue())
			.exchange()
			.expectStatus()
			.isOk();

		ResponseCookie thirdLoginSessionCookie = loginReturningCookie(data);

		// second login should be invalid, it is the least recently used session
		this.client.get()
			.uri("/")
			.cookie(secondLoginSessionCookie.getName(), secondLoginSessionCookie.getValue())
			.exchange()
			.expectStatus()
			.isFound()
			.expectHeader()
			.location("/login");

		// first login should be valid
		this.client.get()
			.uri("/")
			.cookie(firstLoginSessionCookie.getName(), firstLoginSessionCookie.getValue())
			.exchange()
			.expectStatus()
			.isOk();

		// third login should be valid
		this.client.get()
			.uri("/")
			.cookie(thirdLoginSessionCookie.getName(), thirdLoginSessionCookie.getValue())
			.exchange()
			.expectStatus()
			.isOk();
	}

	@Test
	void oauth2LoginWhenMaxSessionsThenPreventLogin() {
		OAuth2LoginConcurrentSessionsConfig.maxSessions = 1;
		OAuth2LoginConcurrentSessionsConfig.preventLogin = true;
		this.spring.register(OAuth2LoginConcurrentSessionsConfig.class).autowire();
		prepareOAuth2Config();
		// @formatter:off
		ResponseCookie sessionCookie = this.client.get()
				.uri("/login/oauth2/code/client-credentials")
				.exchange()
				.expectStatus().is3xxRedirection()
				.expectHeader().valueEquals("Location", "/")
				.expectCookie().exists("SESSION")
				.returnResult(Void.class)
				.getResponseCookies()
				.getFirst("SESSION");

		this.client.get()
				.uri("/login/oauth2/code/client-credentials")
				.exchange()
				.expectHeader().location("/login?error");

		this.client.get().uri("/")
				.cookie(sessionCookie.getName(), sessionCookie.getValue())
				.exchange()
				.expectStatus().isOk()
				.expectBody(String.class).isEqualTo("ok");
		// @formatter:on
	}

	@Test
	void oauth2LoginWhenMaxSessionDoesNotPreventLoginThenSecondLoginSucceedsAndFirstSessionIsInvalidated() {
		OAuth2LoginConcurrentSessionsConfig.maxSessions = 1;
		OAuth2LoginConcurrentSessionsConfig.preventLogin = false;
		this.spring.register(OAuth2LoginConcurrentSessionsConfig.class).autowire();
		prepareOAuth2Config();
		// @formatter:off
		ResponseCookie firstLoginCookie = this.client.get()
				.uri("/login/oauth2/code/client-credentials")
				.exchange()
				.expectStatus().is3xxRedirection()
				.expectHeader().valueEquals("Location", "/")
				.expectCookie().exists("SESSION")
				.returnResult(Void.class)
				.getResponseCookies()
				.getFirst("SESSION");
		ResponseCookie secondLoginCookie = this.client.get()
				.uri("/login/oauth2/code/client-credentials")
				.exchange()
				.expectStatus().is3xxRedirection()
				.expectHeader().valueEquals("Location", "/")
				.expectCookie().exists("SESSION")
				.returnResult(Void.class)
				.getResponseCookies()
				.getFirst("SESSION");

		this.client.get().uri("/")
				.cookie(firstLoginCookie.getName(), firstLoginCookie.getValue())
				.exchange()
				.expectStatus().isFound()
				.expectHeader().location("/login");

		this.client.get().uri("/")
				.cookie(secondLoginCookie.getName(), secondLoginCookie.getValue())
				.exchange()
				.expectStatus().isOk()
				.expectBody(String.class).isEqualTo("ok");
		// @formatter:on
	}

	@Test
	void loginWhenAuthenticationSuccessHandlerOverriddenThenConcurrentSessionHandlersBackOff() {
		this.spring.register(ConcurrentSessionsFormLoginOverrideAuthenticationSuccessHandlerConfig.class).autowire();
		MultiValueMap<String, String> data = new LinkedMultiValueMap<>();
		data.add("username", "user");
		data.add("password", "password");
		// first login should be successful
		login(data).expectStatus().isFound().expectHeader().location("/");
		// second login should be successful, there should be no concurrent session
		// control
		login(data).expectStatus().isFound().expectHeader().location("/");
	}

	private void prepareOAuth2Config() {
		OAuth2LoginConcurrentSessionsConfig config = this.spring.getContext()
			.getBean(OAuth2LoginConcurrentSessionsConfig.class);
		ServerAuthenticationConverter converter = config.authenticationConverter;
		ReactiveAuthenticationManager manager = config.manager;
		ServerOAuth2AuthorizationRequestResolver resolver = config.resolver;
		OAuth2AuthorizationExchange exchange = TestOAuth2AuthorizationExchanges.success();
		OAuth2User user = TestOAuth2Users.create();
		OAuth2AccessToken accessToken = TestOAuth2AccessTokens.noScopes();
		OAuth2LoginAuthenticationToken result = new OAuth2LoginAuthenticationToken(
				TestClientRegistrations.clientRegistration().build(), exchange, user, user.getAuthorities(),
				accessToken);
		given(converter.convert(any())).willReturn(Mono.just(new TestingAuthenticationToken("a", "b", "c")));
		given(manager.authenticate(any())).willReturn(Mono.just(result));
		given(resolver.resolve(any())).willReturn(Mono.empty());
	}

	private ResponseCookie loginReturningCookie(MultiValueMap<String, String> data) {
		return login(data).expectCookie()
			.exists("SESSION")
			.returnResult(Void.class)
			.getResponseCookies()
			.getFirst("SESSION");
	}

	private WebTestClient.ResponseSpec login(MultiValueMap<String, String> data) {
		return this.client.mutateWith(csrf())
			.post()
			.uri("/login")
			.contentType(MediaType.MULTIPART_FORM_DATA)
			.body(BodyInserters.fromFormData(data))
			.exchange();
	}

	@Configuration
	@EnableWebFlux
	@EnableWebFluxSecurity
	@Import(Config.class)
	static class ConcurrentSessionsMaxSessionPreventsLoginConfig {

		static SessionLimit sessionLimit = SessionLimit.of(1);

		@Bean
		SecurityWebFilterChain springSecurity(ServerHttpSecurity http) {
			// @formatter:off
			http
				.authorizeExchange((exchanges) -> exchanges.anyExchange().authenticated())
				.formLogin(Customizer.withDefaults())
				.sessionManagement((sessionManagement) -> sessionManagement
					.concurrentSessions((concurrentSessions) -> concurrentSessions
						.maximumSessions(sessionLimit)
						.maximumSessionsExceededHandler(new PreventLoginServerMaximumSessionsExceededHandler())
					)
				);
			// @formatter:on
			return http.build();
		}

	}

	@Configuration
	@EnableWebFlux
	@EnableWebFluxSecurity
	@Import(Config.class)
	static class OAuth2LoginConcurrentSessionsConfig {

		static int maxSessions = 1;

		static boolean preventLogin = true;

		ReactiveAuthenticationManager manager = mock(ReactiveAuthenticationManager.class);

		ServerAuthenticationConverter authenticationConverter = mock(ServerAuthenticationConverter.class);

		ServerOAuth2AuthorizationRequestResolver resolver = mock(ServerOAuth2AuthorizationRequestResolver.class);

		@Bean
		SecurityWebFilterChain springSecurityFilter(ServerHttpSecurity http,
				DefaultWebSessionManager webSessionManager) {
			// @formatter:off
			http
					.authorizeExchange((exchanges) -> exchanges
						.anyExchange().authenticated()
					)
					.oauth2Login((oauth2Login) -> oauth2Login
						.authenticationConverter(this.authenticationConverter)
						.authenticationManager(this.manager)
						.authorizationRequestResolver(this.resolver)
					)
					.sessionManagement((sessionManagement) -> sessionManagement
						.concurrentSessions((concurrentSessions) -> concurrentSessions
								.maximumSessions(SessionLimit.of(maxSessions))
								.maximumSessionsExceededHandler(preventLogin
										? new PreventLoginServerMaximumSessionsExceededHandler()
										: new InvalidateLeastUsedServerMaximumSessionsExceededHandler(webSessionManager.getSessionStore()))
						)
					);
			// @formatter:on
			return http.build();
		}

		@Bean
		InMemoryReactiveClientRegistrationRepository clientRegistrationRepository() {
			return new InMemoryReactiveClientRegistrationRepository(
					TestClientRegistrations.clientCredentials().build());
		}

	}

	@Configuration
	@EnableWebFlux
	@EnableWebFluxSecurity
	@Import(Config.class)
	static class ConcurrentSessionsMaxSessionPreventsLoginFalseConfig {

		static SessionLimit sessionLimit = SessionLimit.of(1);

		@Bean
		SecurityWebFilterChain springSecurity(ServerHttpSecurity http) {
			// @formatter:off
			http
				.authorizeExchange((exchanges) -> exchanges.anyExchange().authenticated())
				.formLogin(Customizer.withDefaults())
				.sessionManagement((sessionManagement) -> sessionManagement
					.concurrentSessions((concurrentSessions) -> concurrentSessions
						.maximumSessions(sessionLimit)
					)
				);
			// @formatter:on
			return http.build();
		}

	}

	@Configuration
	@EnableWebFlux
	@EnableWebFluxSecurity
	@Import(Config.class)
	static class ConcurrentSessionsFormLoginOverrideAuthenticationSuccessHandlerConfig {

		@Bean
		SecurityWebFilterChain springSecurity(ServerHttpSecurity http) {
			// @formatter:off
			http
				.authorizeExchange((exchanges) -> exchanges.anyExchange().authenticated())
				.formLogin((login) -> login
						.authenticationSuccessHandler(new RedirectServerAuthenticationSuccessHandler("/"))
				)
				.sessionManagement((sessionManagement) -> sessionManagement
					.concurrentSessions((concurrentSessions) -> concurrentSessions
						.maximumSessions(SessionLimit.of(1))
						.maximumSessionsExceededHandler(new PreventLoginServerMaximumSessionsExceededHandler())
					)
				);
			// @formatter:on
			return http.build();
		}

	}

	@Configuration
	@EnableWebFlux
	@EnableWebFluxSecurity
	@Import(Config.class)
	static class ConcurrentSessionsHttpBasicWithWebSessionMaxSessionPreventsLoginConfig {

		@Bean
		SecurityWebFilterChain springSecurity(ServerHttpSecurity http) {
			// @formatter:off
			http
					.authorizeExchange((exchanges) -> exchanges.anyExchange().authenticated())
					.httpBasic((basic) -> basic
							.securityContextRepository(new WebSessionServerSecurityContextRepository())
					)
					.sessionManagement((sessionManagement) -> sessionManagement
							.concurrentSessions((concurrentSessions) -> concurrentSessions
									.maximumSessions(SessionLimit.of(1))
									.maximumSessionsExceededHandler(new PreventLoginServerMaximumSessionsExceededHandler())
							)
					);
			// @formatter:on
			return http.build();
		}

	}

	@Configuration
	@Import({ ReactiveAuthenticationTestConfiguration.class, DefaultController.class })
	static class Config {

		@Bean(WebHttpHandlerBuilder.WEB_SESSION_MANAGER_BEAN_NAME)
		DefaultWebSessionManager webSessionManager() {
			return new DefaultWebSessionManager();
		}

		@Bean
		ReactiveSessionRegistry reactiveSessionRegistry() {
			return new InMemoryReactiveSessionRegistry();
		}

	}

	@RestController
	static class DefaultController {

		@GetMapping("/")
		String index() {
			return "ok";
		}

	}

}
