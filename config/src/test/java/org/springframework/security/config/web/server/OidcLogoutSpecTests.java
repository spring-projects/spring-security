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

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import jakarta.annotation.PreDestroy;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.htmlunit.util.UrlUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import reactor.core.publisher.Mono;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.core.annotation.Order;
import org.springframework.http.ResponseCookie;
import org.springframework.http.client.reactive.ClientHttpConnector;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.MapReactiveUserDetailsService;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.client.oidc.authentication.logout.LogoutTokenClaimNames;
import org.springframework.security.oauth2.client.oidc.authentication.logout.OidcLogoutToken;
import org.springframework.security.oauth2.client.oidc.authentication.logout.TestOidcLogoutTokens;
import org.springframework.security.oauth2.client.oidc.server.session.InMemoryReactiveOidcSessionRegistry;
import org.springframework.security.oauth2.client.oidc.server.session.ReactiveOidcSessionRegistry;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.TestOidcIdTokens;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.logout.ServerLogoutHandler;
import org.springframework.security.web.server.util.matcher.OrServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.PathPatternParserServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.test.web.reactive.server.FluxExchangeResult;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.test.web.reactive.server.WebTestClientConfigurer;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.ConfigurableWebApplicationContext;
import org.springframework.web.reactive.config.EnableWebFlux;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.server.WebSession;
import org.springframework.web.server.adapter.WebHttpHandlerBuilder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasValue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.csrf;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockAuthentication;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * Tests for {@link ServerHttpSecurity.OAuth2ResourceServerSpec}
 */
@ExtendWith({ SpringTestContextExtension.class })
public class OidcLogoutSpecTests {

	private static final String SESSION_COOKIE_NAME = "SESSION";

	private WebTestClient test;

	@Autowired(required = false)
	private MockWebServer web;

	@Autowired
	private ClientRegistration clientRegistration;

	public final SpringTestContext spring = new SpringTestContext(this);

	@Autowired
	public void setApplicationContext(ApplicationContext context) {
		this.test = WebTestClient.bindToApplicationContext(context)
			.apply(springSecurity())
			.configureClient()
			.responseTimeout(Duration.ofDays(1))
			.build();
		if (context instanceof ConfigurableWebApplicationContext configurable) {
			configurable.getBeanFactory().registerResolvableDependency(WebTestClient.class, this.test);
		}
	}

	@Test
	void logoutWhenDefaultsThenRemotelyInvalidatesSessions() {
		this.spring.register(WebServerConfig.class, OidcProviderConfig.class, DefaultConfig.class).autowire();
		String registrationId = this.clientRegistration.getRegistrationId();
		String session = login();
		String logoutToken = this.test.mutateWith(session(session))
			.get()
			.uri("/token/logout")
			.exchange()
			.expectStatus()
			.isOk()
			.returnResult(String.class)
			.getResponseBody()
			.blockFirst();
		this.test.post()
			.uri(this.web.url("/logout/connect/back-channel/" + registrationId).toString())
			.body(BodyInserters.fromFormData("logout_token", logoutToken))
			.exchange()
			.expectStatus()
			.isOk();
		this.test.mutateWith(session(session)).get().uri("/token/logout").exchange().expectStatus().isUnauthorized();
	}

	@Test
	@SuppressWarnings("removal")
	void logoutWhenInvalidLogoutTokenThenBadRequest() {
		this.spring.register(WebServerConfig.class, OidcProviderConfig.class, DefaultConfig.class).autowire();
		this.test.get().uri("/token/logout").exchange().expectStatus().isUnauthorized();
		String registrationId = this.clientRegistration.getRegistrationId();
		FluxExchangeResult<String> result = this.test.get()
			.uri("/oauth2/authorization/" + registrationId)
			.exchange()
			.expectStatus()
			.isFound()
			.returnResult(String.class);
		String session = sessionId(result);
		String redirectUrl = UrlUtils.decode(result.getResponseHeaders().getLocation().toString());
		String state = this.test
			.mutateWith(mockAuthentication(new TestingAuthenticationToken(this.clientRegistration.getClientId(),
					this.clientRegistration.getClientSecret(), "APP")))
			.get()
			.uri(redirectUrl)
			.exchange()
			.returnResult(String.class)
			.getResponseBody()
			.blockFirst();
		result = this.test.get()
			.uri("/login/oauth2/code/" + registrationId + "?code=code&state=" + state)
			.cookie("SESSION", session)
			.exchange()
			.expectStatus()
			.isFound()
			.returnResult(String.class);
		session = sessionId(result);
		this.test.post()
			.uri(this.web.url("/logout/connect/back-channel/" + registrationId).toString())
			.body(BodyInserters.fromFormData("logout_token", "invalid"))
			.exchange()
			.expectStatus()
			.isBadRequest()
			.expectBody(new ParameterizedTypeReference<Map<String, String>>() {
			})
			.value(hasValue("invalid_request"));
		this.test.get().uri("/token/logout").cookie("SESSION", session).exchange().expectStatus().isOk();
	}

	@Test
	@SuppressWarnings("removal")
	void logoutWhenLogoutTokenSpecifiesOneSessionThenRemotelyInvalidatesOnlyThatSession() throws Exception {
		this.spring.register(WebServerConfig.class, OidcProviderConfig.class, DefaultConfig.class).autowire();
		String registrationId = this.clientRegistration.getRegistrationId();
		String one = login();
		String two = login();
		String three = login();
		String logoutToken = this.test.get()
			.uri("/token/logout")
			.cookie("SESSION", one)
			.exchange()
			.expectStatus()
			.isOk()
			.returnResult(String.class)
			.getResponseBody()
			.blockFirst();
		this.test.post()
			.uri(this.web.url("/logout/connect/back-channel/" + registrationId).toString())
			.body(BodyInserters.fromFormData("logout_token", logoutToken))
			.exchange()
			.expectStatus()
			.isOk();
		this.test.get().uri("/token/logout").cookie("SESSION", one).exchange().expectStatus().isUnauthorized();
		this.test.get().uri("/token/logout").cookie("SESSION", two).exchange().expectStatus().isOk();
		logoutToken = this.test.get()
			.uri("/token/logout/all")
			.cookie("SESSION", three)
			.exchange()
			.expectStatus()
			.isOk()
			.returnResult(String.class)
			.getResponseBody()
			.blockFirst();
		this.test.post()
			.uri(this.web.url("/logout/connect/back-channel/" + registrationId).toString())
			.body(BodyInserters.fromFormData("logout_token", logoutToken))
			.exchange()
			.expectStatus()
			.isOk();
		this.test.get().uri("/token/logout").cookie("SESSION", two).exchange().expectStatus().isUnauthorized();
		this.test.get().uri("/token/logout").cookie("SESSION", three).exchange().expectStatus().isUnauthorized();
	}

	@Test
	@SuppressWarnings("removal")
	void logoutWhenRemoteLogoutUriThenUses() {
		this.spring.register(WebServerConfig.class, OidcProviderConfig.class, LogoutUriConfig.class).autowire();
		String registrationId = this.clientRegistration.getRegistrationId();
		String one = login();
		String logoutToken = this.test.get()
			.uri("/token/logout/all")
			.cookie("SESSION", one)
			.exchange()
			.expectStatus()
			.isOk()
			.returnResult(String.class)
			.getResponseBody()
			.blockFirst();
		this.test.post()
			.uri(this.web.url("/logout/connect/back-channel/" + registrationId).toString())
			.body(BodyInserters.fromFormData("logout_token", logoutToken))
			.exchange()
			.expectStatus()
			.isBadRequest()
			.expectBody(new ParameterizedTypeReference<Map<String, String>>() {
			})
			.value(hasValue("partial_logout"))
			.value(hasValue(containsString("not all sessions were terminated")));
		this.test.get().uri("/token/logout").cookie("SESSION", one).exchange().expectStatus().isOk();
	}

	@Test
	void logoutWhenSelfRemoteLogoutUriThenUses() {
		this.spring.register(WebServerConfig.class, OidcProviderConfig.class, SelfLogoutUriConfig.class).autowire();
		String registrationId = this.clientRegistration.getRegistrationId();
		String sessionId = login();
		String logoutToken = this.test.get()
			.uri("/token/logout")
			.cookie("SESSION", sessionId)
			.exchange()
			.expectStatus()
			.isOk()
			.returnResult(String.class)
			.getResponseBody()
			.blockFirst();
		this.test.post()
			.uri(this.web.url("/logout/connect/back-channel/" + registrationId).toString())
			.body(BodyInserters.fromFormData("logout_token", logoutToken))
			.exchange()
			.expectStatus()
			.isOk();
		this.test.get().uri("/token/logout").cookie("SESSION", sessionId).exchange().expectStatus().isUnauthorized();
	}

	@Test
	@SuppressWarnings("removal")
	void logoutWhenDifferentCookieNameThenUses() {
		this.spring.register(OidcProviderConfig.class, CookieConfig.class).autowire();
		String registrationId = this.clientRegistration.getRegistrationId();
		String sessionId = login();
		String logoutToken = this.test.get()
			.uri("/token/logout")
			.cookie("SESSION", sessionId)
			.exchange()
			.expectStatus()
			.isOk()
			.returnResult(String.class)
			.getResponseBody()
			.blockFirst();
		this.test.post()
			.uri(this.web.url("/logout/connect/back-channel/" + registrationId).toString())
			.body(BodyInserters.fromFormData("logout_token", logoutToken))
			.exchange()
			.expectStatus()
			.isOk();
		this.test.get().uri("/token/logout").cookie("SESSION", sessionId).exchange().expectStatus().isUnauthorized();
	}

	@Test
	@SuppressWarnings("removal")
	void logoutWhenRemoteLogoutFailsThenReportsPartialLogout() {
		this.spring.register(WebServerConfig.class, OidcProviderConfig.class, WithBrokenLogoutConfig.class).autowire();
		ServerLogoutHandler logoutHandler = this.spring.getContext().getBean(ServerLogoutHandler.class);
		given(logoutHandler.logout(any(), any())).willReturn(Mono.error(() -> new IllegalStateException("illegal")));
		String registrationId = this.clientRegistration.getRegistrationId();
		String one = login();
		String logoutToken = this.test.get()
			.uri("/token/logout/all")
			.cookie("SESSION", one)
			.exchange()
			.expectStatus()
			.isOk()
			.returnResult(String.class)
			.getResponseBody()
			.blockFirst();
		this.test.post()
			.uri(this.web.url("/logout/connect/back-channel/" + registrationId).toString())
			.body(BodyInserters.fromFormData("logout_token", logoutToken))
			.exchange()
			.expectStatus()
			.isBadRequest()
			.expectBody(String.class)
			.value(containsString("partial_logout"));
		this.test.get().uri("/token/logout").cookie("SESSION", one).exchange().expectStatus().isOk();
	}

	@Test
	void logoutWhenCustomComponentsThenUses() {
		this.spring.register(WebServerConfig.class, OidcProviderConfig.class, WithCustomComponentsConfig.class)
			.autowire();
		String registrationId = this.clientRegistration.getRegistrationId();
		String sessionId = login();
		String logoutToken = this.test.get()
			.uri("/token/logout")
			.cookie("SESSION", sessionId)
			.exchange()
			.expectStatus()
			.isOk()
			.returnResult(String.class)
			.getResponseBody()
			.blockFirst();
		this.test.post()
			.uri(this.web.url("/logout/connect/back-channel/" + registrationId).toString())
			.body(BodyInserters.fromFormData("logout_token", logoutToken))
			.exchange()
			.expectStatus()
			.isOk();
		this.test.get().uri("/token/logout").cookie("SESSION", sessionId).exchange().expectStatus().isUnauthorized();
		ReactiveOidcSessionRegistry sessionRegistry = this.spring.getContext()
			.getBean(ReactiveOidcSessionRegistry.class);
		verify(sessionRegistry, atLeastOnce()).saveSessionInformation(any());
		verify(sessionRegistry, atLeastOnce()).removeSessionInformation(any(OidcLogoutToken.class));
	}

	@Test
	void logoutWhenProviderIssuerMissingThen5xxServerError() {
		this.spring.register(WebServerConfig.class, OidcProviderConfig.class, ProviderIssuerMissingConfig.class)
			.autowire();
		String registrationId = this.clientRegistration.getRegistrationId();
		String session = login();
		String logoutToken = this.test.mutateWith(session(session))
			.get()
			.uri("/token/logout")
			.exchange()
			.expectStatus()
			.isOk()
			.returnResult(String.class)
			.getResponseBody()
			.blockFirst();
		this.test.post()
			.uri(this.web.url("/logout/connect/back-channel/" + registrationId).toString())
			.body(BodyInserters.fromFormData("logout_token", logoutToken))
			.exchange()
			.expectStatus()
			.is5xxServerError();
		this.test.mutateWith(session(session)).get().uri("/token/logout").exchange().expectStatus().isOk();
	}

	private String login() {
		this.test.get().uri("/token/logout").exchange().expectStatus().isUnauthorized();
		String registrationId = this.clientRegistration.getRegistrationId();
		FluxExchangeResult<String> result = this.test.get()
			.uri("/oauth2/authorization/" + registrationId)
			.exchange()
			.expectStatus()
			.isFound()
			.returnResult(String.class);
		String sessionId = sessionId(result);
		String redirectUrl = UrlUtils.decode(result.getResponseHeaders().getLocation().toString());
		result = this.test
			.mutateWith(mockAuthentication(new TestingAuthenticationToken(this.clientRegistration.getClientId(),
					this.clientRegistration.getClientSecret(), "APP")))
			.get()
			.uri(redirectUrl)
			.exchange()
			.returnResult(String.class);
		String state = result.getResponseBody().blockFirst();
		result = this.test.mutateWith(session(sessionId))
			.get()
			.uri("/login/oauth2/code/" + registrationId + "?code=code&state=" + state)
			.exchange()
			.expectStatus()
			.isFound()
			.returnResult(String.class);
		return sessionId(result);
	}

	private String sessionId(FluxExchangeResult<?> result) {
		List<ResponseCookie> cookies = result.getResponseCookies().get(SESSION_COOKIE_NAME);
		if (cookies == null || cookies.isEmpty()) {
			return null;
		}
		return cookies.get(0).getValue();
	}

	static SessionMutator session(String session) {
		return new SessionMutator(session);
	}

	private record SessionMutator(String session) implements WebTestClientConfigurer {

		@Override
		public void afterConfigurerAdded(WebTestClient.Builder builder, WebHttpHandlerBuilder httpHandlerBuilder,
				ClientHttpConnector connector) {
			builder.defaultCookie(SESSION_COOKIE_NAME, this.session);
		}

	}

	@Configuration
	static class RegistrationConfig {

		@Autowired(required = false)
		MockWebServer web;

		@Bean
		ClientRegistration clientRegistration() {
			if (this.web == null) {
				return TestClientRegistrations.clientRegistration().build();
			}
			String issuer = this.web.url("/").toString();
			return TestClientRegistrations.clientRegistration()
				.issuerUri(issuer)
				.jwkSetUri(issuer + "jwks")
				.tokenUri(issuer + "token")
				.userInfoUri(issuer + "user")
				.scope("openid")
				.build();
		}

		@Bean
		ReactiveClientRegistrationRepository clientRegistrationRepository(ClientRegistration clientRegistration) {
			return new InMemoryReactiveClientRegistrationRepository(clientRegistration);
		}

	}

	@Configuration
	@EnableWebFluxSecurity
	@Import(RegistrationConfig.class)
	static class DefaultConfig {

		@Bean
		@Order(1)
		SecurityWebFilterChain filters(ServerHttpSecurity http) throws Exception {
		// @formatter:off
			http
					.authorizeExchange((authorize) -> authorize.anyExchange().authenticated())
					.oauth2Login(Customizer.withDefaults())
					.oidcLogout((oidc) -> oidc.backChannel(Customizer.withDefaults()));
			// @formatter:on

			return http.build();
		}

	}

	@Configuration
	@EnableWebFluxSecurity
	@Import(RegistrationConfig.class)
	static class LogoutUriConfig {

		@Bean
		@Order(1)
		SecurityWebFilterChain filters(ServerHttpSecurity http) throws Exception {
			// @formatter:off
			http
					.authorizeExchange((authorize) -> authorize.anyExchange().authenticated())
					.oauth2Login(Customizer.withDefaults())
					.oidcLogout((oidc) -> oidc
						.backChannel((backchannel) -> backchannel.logoutUri("http://localhost/wrong"))
					);
			// @formatter:on

			return http.build();
		}

	}

	@Configuration
	@EnableWebFluxSecurity
	@Import(RegistrationConfig.class)
	static class SelfLogoutUriConfig {

		@Bean
		@Order(1)
		SecurityWebFilterChain filters(ServerHttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeExchange((authorize) -> authorize.anyExchange().authenticated())
				.oauth2Login(Customizer.withDefaults())
				.oidcLogout((oidc) -> oidc
					.backChannel(Customizer.withDefaults())
				);
			// @formatter:on

			return http.build();
		}

	}

	@Configuration
	@EnableWebFluxSecurity
	@Import(RegistrationConfig.class)
	static class CookieConfig {

		private final MockWebServer server = new MockWebServer();

		@Bean
		@Order(1)
		SecurityWebFilterChain filters(ServerHttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeExchange((authorize) -> authorize.anyExchange().authenticated())
				.oauth2Login(Customizer.withDefaults())
				.oidcLogout((oidc) -> oidc
					.backChannel(Customizer.withDefaults())
				);
			// @formatter:on

			return http.build();
		}

		@Bean
		ReactiveOidcSessionRegistry oidcSessionRegistry() {
			return new InMemoryReactiveOidcSessionRegistry();
		}

		@Bean
		OidcBackChannelServerLogoutHandler oidcLogoutHandler(ReactiveOidcSessionRegistry sessionRegistry) {
			OidcBackChannelServerLogoutHandler logoutHandler = new OidcBackChannelServerLogoutHandler(sessionRegistry);
			logoutHandler.setSessionCookieName("JSESSIONID");
			return logoutHandler;
		}

		@Bean
		MockWebServer web(ObjectProvider<WebTestClient> web) {
			WebTestClientDispatcher dispatcher = new WebTestClientDispatcher(web);
			dispatcher.setAssertion((rr) -> {
				String cookie = rr.getHeaders().get("Cookie");
				if (cookie == null) {
					return;
				}
				assertThat(cookie).contains("JSESSIONID");
			});
			this.server.setDispatcher(dispatcher);
			return this.server;
		}

		@PreDestroy
		void shutdown() throws IOException {
			this.server.shutdown();
		}

	}

	@Configuration
	@EnableWebFluxSecurity
	@Import(RegistrationConfig.class)
	static class WithCustomComponentsConfig {

		ReactiveOidcSessionRegistry sessionRegistry = spy(new InMemoryReactiveOidcSessionRegistry());

		@Bean
		@Order(1)
		SecurityWebFilterChain filters(ServerHttpSecurity http) throws Exception {
		// @formatter:off
			http
					.authorizeExchange((authorize) -> authorize.anyExchange().authenticated())
					.oauth2Login(Customizer.withDefaults())
					.oidcLogout((oidc) -> oidc.backChannel(Customizer.withDefaults()));
			// @formatter:on

			return http.build();
		}

		@Bean
		ReactiveOidcSessionRegistry sessionRegistry() {
			return this.sessionRegistry;
		}

	}

	@Configuration
	@EnableWebFluxSecurity
	@Import(RegistrationConfig.class)
	static class WithBrokenLogoutConfig {

		private final ServerLogoutHandler logoutHandler = mock(ServerLogoutHandler.class);

		@Bean
		@Order(1)
		SecurityWebFilterChain filters(ServerHttpSecurity http) throws Exception {
		// @formatter:off
			http
					.authorizeExchange((authorize) -> authorize.anyExchange().authenticated())
					.logout((logout) -> logout.logoutHandler(this.logoutHandler))
					.oauth2Login(Customizer.withDefaults())
					.oidcLogout((oidc) -> oidc.backChannel(Customizer.withDefaults()));
			// @formatter:on

			return http.build();
		}

		@Bean
		ServerLogoutHandler logoutHandler() {
			return this.logoutHandler;
		}

	}

	@Configuration
	static class ProviderIssuerMissingRegistrationConfig {

		@Autowired(required = false)
		MockWebServer web;

		@Bean
		ClientRegistration clientRegistration() {
			if (this.web == null) {
				return TestClientRegistrations.clientRegistration().issuerUri(null).build();
			}
			String issuer = this.web.url("/").toString();
			return TestClientRegistrations.clientRegistration()
				.issuerUri(null)
				.jwkSetUri(issuer + "jwks")
				.tokenUri(issuer + "token")
				.userInfoUri(issuer + "user")
				.scope("openid")
				.build();
		}

		@Bean
		ReactiveClientRegistrationRepository clientRegistrationRepository(ClientRegistration clientRegistration) {
			return new InMemoryReactiveClientRegistrationRepository(clientRegistration);
		}

	}

	@Configuration
	@EnableWebFluxSecurity
	@Import(ProviderIssuerMissingRegistrationConfig.class)
	static class ProviderIssuerMissingConfig {

		@Bean
		@Order(1)
		SecurityWebFilterChain filters(ServerHttpSecurity http) throws Exception {
			// @formatter:off
			http
					.authorizeExchange((authorize) -> authorize.anyExchange().authenticated())
					.oauth2Login(Customizer.withDefaults())
					.oidcLogout((oidc) -> oidc.backChannel(Customizer.withDefaults()));
			// @formatter:on

			return http.build();
		}

	}

	@Configuration
	@EnableWebFluxSecurity
	@EnableWebFlux
	@RestController
	static class OidcProviderConfig {

		private static final RSAKey key = key();

		private static final JWKSource<SecurityContext> jwks = jwks(key);

		private static RSAKey key() {
			try {
				KeyPair pair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
				return new RSAKey.Builder((RSAPublicKey) pair.getPublic()).privateKey(pair.getPrivate()).build();
			}
			catch (Exception ex) {
				throw new RuntimeException(ex);
			}
		}

		private static JWKSource<SecurityContext> jwks(RSAKey key) {
			try {
				return new ImmutableJWKSet<>(new JWKSet(key));
			}
			catch (Exception ex) {
				throw new RuntimeException(ex);
			}
		}

		private final String username = "user";

		private final JwtEncoder encoder = new NimbusJwtEncoder(jwks);

		private String nonce;

		@Autowired
		ClientRegistration registration;

		@Autowired(required = false)
		MockWebServer web;

		static ServerWebExchangeMatcher or(String... patterns) {
			List<ServerWebExchangeMatcher> matchers = new ArrayList<>();
			for (String pattern : patterns) {
				matchers.add(new PathPatternParserServerWebExchangeMatcher(pattern));
			}
			return new OrServerWebExchangeMatcher(matchers);
		}

		@Bean
		@Order(0)
		SecurityWebFilterChain authorizationServer(ServerHttpSecurity http, ClientRegistration registration)
				throws Exception {
		// @formatter:off
			http
					.securityMatcher(or("/jwks", "/login/oauth/authorize", "/nonce", "/token", "/token/logout", "/user"))
					.authorizeExchange((authorize) -> authorize
							.pathMatchers("/jwks").permitAll()
							.anyExchange().authenticated()
					)
					.httpBasic(Customizer.withDefaults())
					.oauth2ResourceServer((oauth2) -> oauth2
							.jwt((jwt) -> jwt.jwkSetUri(registration.getProviderDetails().getJwkSetUri()))
					);
			// @formatter:off

			return http.build();
		}

		@Bean
		ReactiveUserDetailsService users(ClientRegistration registration) {
			return new MapReactiveUserDetailsService(User.withUsername(registration.getClientId())
					.password("{noop}" + registration.getClientSecret()).authorities("APP").build());
		}

		@GetMapping("/login/oauth/authorize")
		String nonce(@RequestParam("nonce") String nonce, @RequestParam("state") String state) {
			this.nonce = nonce;
			return state;
		}

		@PostMapping("/token")
		Map<String, Object> accessToken(WebSession session) {
			JwtEncoderParameters parameters = JwtEncoderParameters
					.from(JwtClaimsSet.builder().id("id").subject(this.username)
							.issuer(getIssuerUri()).issuedAt(Instant.now())
							.expiresAt(Instant.now().plusSeconds(86400)).claim("scope", "openid").build());
			String token = this.encoder.encode(parameters).getTokenValue();
			return new OIDCTokens(idToken(session.getId()), new BearerAccessToken(token, 86400, new Scope("openid")), null)
					.toJSONObject();
		}

		String idToken(String sessionId) {
			OidcIdToken token = TestOidcIdTokens.idToken().issuer(getIssuerUri())
					.subject(this.username).expiresAt(Instant.now().plusSeconds(86400))
					.audience(List.of(this.registration.getClientId())).nonce(this.nonce)
					.claim(LogoutTokenClaimNames.SID, sessionId).build();
			JwtEncoderParameters parameters = JwtEncoderParameters
					.from(JwtClaimsSet.builder().claims((claims) -> claims.putAll(token.getClaims())).build());
			return this.encoder.encode(parameters).getTokenValue();
		}

		private String getIssuerUri() {
			if (this.web == null) {
				return TestClientRegistrations.clientRegistration().build().getProviderDetails().getIssuerUri();
			}
			return this.web.url("/").toString();
		}

		@GetMapping("/user")
		Map<String, Object> userinfo() {
			return Map.of("sub", this.username, "id", this.username);
		}

		@GetMapping("/jwks")
		String jwks() {
			return new JWKSet(key).toString();
		}

		@GetMapping("/token/logout")
		String logoutToken(@AuthenticationPrincipal OidcUser user) {
			OidcLogoutToken token = TestOidcLogoutTokens.withUser(user)
					.audience(List.of(this.registration.getClientId())).build();
			JwsHeader header = JwsHeader.with(SignatureAlgorithm.RS256).type("logout+jwt").build();
			JwtClaimsSet claims = JwtClaimsSet.builder().claims((c) -> c.putAll(token.getClaims())).build();
			JwtEncoderParameters parameters = JwtEncoderParameters.from(header, claims);
			return this.encoder.encode(parameters).getTokenValue();
		}

		@GetMapping("/token/logout/all")
		String logoutTokenAll(@AuthenticationPrincipal OidcUser user) {
			OidcLogoutToken token = TestOidcLogoutTokens.withUser(user)
					.audience(List.of(this.registration.getClientId()))
					.claims((claims) -> claims.remove(LogoutTokenClaimNames.SID)).build();
			JwsHeader header = JwsHeader.with(SignatureAlgorithm.RS256).type("JWT").build();
			JwtClaimsSet claims = JwtClaimsSet.builder().claims((c) -> c.putAll(token.getClaims())).build();
			JwtEncoderParameters parameters = JwtEncoderParameters.from(header, claims);
			return this.encoder.encode(parameters).getTokenValue();
		}
	}

	@Configuration
	static class WebServerConfig {

		private final MockWebServer server = new MockWebServer();

		@Bean
		MockWebServer web(ObjectProvider<WebTestClient> web) {
			this.server.setDispatcher(new WebTestClientDispatcher(web));
			return this.server;
		}

		@PreDestroy
		void shutdown() throws IOException {
			this.server.shutdown();
		}

	}

	private static class WebTestClientDispatcher extends Dispatcher {

		private final ObjectProvider<WebTestClient> webProvider;

		private WebTestClient web;

		private Consumer<RecordedRequest> assertion = (rr) -> { };

		WebTestClientDispatcher(ObjectProvider<WebTestClient> web) {
			this.webProvider = web;
		}

		@Override
		public MockResponse dispatch(RecordedRequest request) throws InterruptedException {
			this.assertion.accept(request);
			this.web = this.webProvider.getObject();
			String method = request.getMethod();
			String path = request.getPath();
			String csrf = request.getHeader("X-CSRF-TOKEN");
			String sessionId = session(request);
			WebTestClient.RequestHeadersSpec<?> r;
			if ("GET".equals(method)) {
				r = this.web.get().uri(path);
			}
			else {
				WebTestClient.RequestBodySpec body;
				if (csrf == null) {
					body = this.web.mutateWith(csrf()).post().uri(path);
				}
				else {
					body = this.web.post().uri(path).header("X-CSRF-TOKEN", csrf);
				}
				body.body(BodyInserters.fromValue(request.getBody().readUtf8()));
				r = body;
			}
			for (Map.Entry<String, List<String>> header : request.getHeaders().toMultimap().entrySet()) {
				if (header.getKey().equalsIgnoreCase("Cookie")) {
					continue;
				}
				r.header(header.getKey(), header.getValue().iterator().next());
			}
			if (sessionId != null) {
				r.cookie(SESSION_COOKIE_NAME, sessionId);
			}

			try {
				FluxExchangeResult<String> result = r.exchange().returnResult(String.class);
				return toMockResponse(result);
			}
			catch (Exception ex) {
				MockResponse response = new MockResponse();
				response.setResponseCode(500);
				response.setBody(ex.getMessage());
				return response;
			}
		}

		void setAssertion(Consumer<RecordedRequest> assertion) {
			this.assertion = assertion;
		}

		private String session(RecordedRequest request) {
			String cookieHeaderValue = request.getHeader("Cookie");
			if (cookieHeaderValue == null) {
				return null;
			}
			String[] cookies = cookieHeaderValue.split(";");
			for (String cookie : cookies) {
				String[] parts = cookie.split("=");
				if (SESSION_COOKIE_NAME.equals(parts[0])) {
					return parts[1];
				}
				if ("JSESSIONID".equals(parts[0])) {
					return parts[1];
				}
			}
			return null;
		}

		private MockResponse toMockResponse(FluxExchangeResult<String> result) {
			MockResponse response = new MockResponse();
			response.setResponseCode(result.getStatus().value());
			for (String name : result.getResponseHeaders().headerNames()) {
				response.addHeader(name, result.getResponseHeaders().getFirst(name));
			}
			String body = result.getResponseBody().blockFirst();
			if (body != null) {
				response.setBody(body);
			}
			return response;
		}

	}

}
