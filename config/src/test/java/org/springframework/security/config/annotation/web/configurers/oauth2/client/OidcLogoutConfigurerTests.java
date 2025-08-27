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

package org.springframework.security.config.annotation.web.configurers.oauth2.client;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
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
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.htmlunit.util.UrlUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.annotation.Order;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.client.oidc.authentication.logout.LogoutTokenClaimNames;
import org.springframework.security.oauth2.client.oidc.authentication.logout.OidcLogoutToken;
import org.springframework.security.oauth2.client.oidc.authentication.logout.TestOidcLogoutTokens;
import org.springframework.security.oauth2.client.oidc.session.InMemoryOidcSessionRegistry;
import org.springframework.security.oauth2.client.oidc.session.OidcSessionRegistry;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
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
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.hamcrest.Matchers.containsString;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.willThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests for {@link OidcLogoutConfigurer}
 */
@ExtendWith(SpringTestContextExtension.class)
public class OidcLogoutConfigurerTests {

	@Autowired
	private MockMvc mvc;

	@Autowired(required = false)
	private MockWebServer web;

	@Autowired
	private ClientRegistration clientRegistration;

	public final SpringTestContext spring = new SpringTestContext(this);

	@Test
	void logoutWhenDefaultsThenRemotelyInvalidatesSessions() throws Exception {
		this.spring.register(WebServerConfig.class, OidcProviderConfig.class, DefaultConfig.class).autowire();
		String registrationId = this.clientRegistration.getRegistrationId();
		MockHttpSession session = login();
		String logoutToken = this.mvc.perform(get("/token/logout").session(session))
			.andExpect(status().isOk())
			.andReturn()
			.getResponse()
			.getContentAsString();
		this.mvc
			.perform(post(this.web.url("/logout/connect/back-channel/" + registrationId).toString())
				.param("logout_token", logoutToken))
			.andExpect(status().isOk());
		this.mvc.perform(get("/token/logout").session(session)).andExpect(status().isUnauthorized());
	}

	@Test
	void logoutWhenInvalidLogoutTokenThenBadRequest() throws Exception {
		this.spring.register(WebServerConfig.class, OidcProviderConfig.class, DefaultConfig.class).autowire();
		this.mvc.perform(get("/token/logout")).andExpect(status().isUnauthorized());
		String registrationId = this.clientRegistration.getRegistrationId();
		MvcResult result = this.mvc.perform(get("/oauth2/authorization/" + registrationId))
			.andExpect(status().isFound())
			.andReturn();
		MockHttpSession session = (MockHttpSession) result.getRequest().getSession();
		String redirectUrl = UrlUtils.decode(result.getResponse().getRedirectedUrl());
		String state = this.mvc
			.perform(get(redirectUrl)
				.with(httpBasic(this.clientRegistration.getClientId(), this.clientRegistration.getClientSecret())))
			.andReturn()
			.getResponse()
			.getContentAsString();
		result = this.mvc
			.perform(get("/login/oauth2/code/" + registrationId).param("code", "code")
				.param("state", state)
				.session(session))
			.andExpect(status().isFound())
			.andReturn();
		session = (MockHttpSession) result.getRequest().getSession();
		this.mvc
			.perform(post(this.web.url("/logout/connect/back-channel/" + registrationId).toString())
				.param("logout_token", "invalid"))
			.andExpect(status().isBadRequest());
		this.mvc.perform(get("/token/logout").session(session)).andExpect(status().isOk());
	}

	@Test
	void logoutWhenLogoutTokenSpecifiesOneSessionThenRemotelyInvalidatesOnlyThatSession() throws Exception {
		this.spring.register(WebServerConfig.class, OidcProviderConfig.class, DefaultConfig.class).autowire();
		String registrationId = this.clientRegistration.getRegistrationId();
		MockHttpSession one = login();
		MockHttpSession two = login();
		MockHttpSession three = login();
		String logoutToken = this.mvc.perform(get("/token/logout").session(one))
			.andExpect(status().isOk())
			.andReturn()
			.getResponse()
			.getContentAsString();
		this.mvc
			.perform(post(this.web.url("/logout/connect/back-channel/" + registrationId).toString())
				.param("logout_token", logoutToken))
			.andExpect(status().isOk());
		this.mvc.perform(get("/token/logout").session(one)).andExpect(status().isUnauthorized());
		this.mvc.perform(get("/token/logout").session(two)).andExpect(status().isOk());
		logoutToken = this.mvc.perform(get("/token/logout/all").session(three))
			.andExpect(status().isOk())
			.andReturn()
			.getResponse()
			.getContentAsString();
		this.mvc
			.perform(post(this.web.url("/logout/connect/back-channel/" + registrationId).toString())
				.param("logout_token", logoutToken))
			.andExpect(status().isOk());
		this.mvc.perform(get("/token/logout").session(two)).andExpect(status().isUnauthorized());
		this.mvc.perform(get("/token/logout").session(three)).andExpect(status().isUnauthorized());
	}

	@Test
	void logoutWhenRemoteLogoutUriThenUses() throws Exception {
		this.spring.register(WebServerConfig.class, OidcProviderConfig.class, LogoutUriConfig.class).autowire();
		String registrationId = this.clientRegistration.getRegistrationId();
		MockHttpSession one = login();
		String logoutToken = this.mvc.perform(get("/token/logout/all").session(one))
			.andExpect(status().isOk())
			.andReturn()
			.getResponse()
			.getContentAsString();
		this.mvc
			.perform(post(this.web.url("/logout/connect/back-channel/" + registrationId).toString())
				.param("logout_token", logoutToken))
			.andExpect(status().isBadRequest())
			.andExpect(content().string(containsString("partial_logout")))
			.andExpect(content().string(containsString("not all sessions were terminated")));
		this.mvc.perform(get("/token/logout").session(one)).andExpect(status().isOk());
	}

	@Test
	void logoutWhenSelfRemoteLogoutUriThenUses() throws Exception {
		this.spring.register(WebServerConfig.class, OidcProviderConfig.class, SelfLogoutUriConfig.class).autowire();
		String registrationId = this.clientRegistration.getRegistrationId();
		MockHttpSession session = login();
		String logoutToken = this.mvc.perform(get("/token/logout").session(session))
			.andExpect(status().isOk())
			.andReturn()
			.getResponse()
			.getContentAsString();
		this.mvc
			.perform(post(this.web.url("/logout/connect/back-channel/" + registrationId).toString())
				.param("logout_token", logoutToken))
			.andExpect(status().isOk());
		this.mvc.perform(get("/token/logout").session(session)).andExpect(status().isUnauthorized());
	}

	@Test
	void logoutWhenDifferentCookieNameThenUses() throws Exception {
		this.spring.register(OidcProviderConfig.class, CookieConfig.class).autowire();
		String registrationId = this.clientRegistration.getRegistrationId();
		MockHttpSession session = login();
		String logoutToken = this.mvc.perform(get("/token/logout").session(session))
			.andExpect(status().isOk())
			.andReturn()
			.getResponse()
			.getContentAsString();
		this.mvc
			.perform(post(this.web.url("/logout/connect/back-channel/" + registrationId).toString())
				.param("logout_token", logoutToken))
			.andExpect(status().isOk());
		this.mvc.perform(get("/token/logout").session(session)).andExpect(status().isUnauthorized());
	}

	@Test
	void logoutWhenRemoteLogoutFailsThenReportsPartialLogout() throws Exception {
		this.spring.register(WebServerConfig.class, OidcProviderConfig.class, WithBrokenLogoutConfig.class).autowire();
		LogoutHandler logoutHandler = this.spring.getContext().getBean(LogoutHandler.class);
		willThrow(IllegalStateException.class).given(logoutHandler).logout(any(), any(), any());
		String registrationId = this.clientRegistration.getRegistrationId();
		MockHttpSession one = login();
		String logoutToken = this.mvc.perform(get("/token/logout/all").session(one))
			.andExpect(status().isOk())
			.andReturn()
			.getResponse()
			.getContentAsString();
		this.mvc
			.perform(post(this.web.url("/logout/connect/back-channel/" + registrationId).toString())
				.param("logout_token", logoutToken))
			.andExpect(status().isBadRequest())
			.andExpect(content().string(containsString("partial_logout")));
		this.mvc.perform(get("/token/logout").session(one)).andExpect(status().isOk());
	}

	@Test
	void logoutWhenCustomComponentsThenUses() throws Exception {
		this.spring.register(WebServerConfig.class, OidcProviderConfig.class, WithCustomComponentsConfig.class)
			.autowire();
		String registrationId = this.clientRegistration.getRegistrationId();
		MockHttpSession session = login();
		String logoutToken = this.mvc.perform(get("/token/logout").session(session))
			.andExpect(status().isOk())
			.andReturn()
			.getResponse()
			.getContentAsString();
		this.mvc
			.perform(post(this.web.url("/logout/connect/back-channel/" + registrationId).toString())
				.param("logout_token", logoutToken))
			.andExpect(status().isOk());
		this.mvc.perform(get("/token/logout").session(session)).andExpect(status().isUnauthorized());
		OidcSessionRegistry sessionRegistry = this.spring.getContext().getBean(OidcSessionRegistry.class);
		verify(sessionRegistry).saveSessionInformation(any());
		verify(sessionRegistry).removeSessionInformation(any(OidcLogoutToken.class));
	}

	@Test
	void logoutWhenProviderIssuerMissingThenThrowIllegalArgumentException() throws Exception {
		this.spring.register(WebServerConfig.class, OidcProviderConfig.class, ProviderIssuerMissingConfig.class)
			.autowire();
		String registrationId = this.clientRegistration.getRegistrationId();
		MockHttpSession session = login();
		String logoutToken = this.mvc.perform(get("/token/logout").session(session))
			.andExpect(status().isOk())
			.andReturn()
			.getResponse()
			.getContentAsString();
		assertThatIllegalArgumentException().isThrownBy(
				() -> this.mvc.perform(post(this.web.url("/logout/connect/back-channel/" + registrationId).toString())
					.param("logout_token", logoutToken)));
	}

	@Test
	void oidcBackChannelLogoutWhenDefaultsThenRemotelyInvalidatesSessions() throws Exception {
		this.spring.register(WebServerConfig.class, OidcProviderConfig.class, WithOidcBackChannelDslConfig.class)
				.autowire();
		String registrationId = this.clientRegistration.getRegistrationId();
		MockHttpSession session = login();
		String logoutToken = this.mvc.perform(get("/token/logout").session(session))
				.andExpect(status().isOk())
				.andReturn()
				.getResponse()
				.getContentAsString();
		this.mvc.perform(post(this.web.url("/logout/connect/back-channel/" + registrationId).toString())
						.param("logout_token", logoutToken))
				.andExpect(status().isOk());
		this.mvc.perform(get("/token/logout").session(session))
				.andExpect(status().isUnauthorized());
	}

	private MockHttpSession login() throws Exception {
		MockMvcDispatcher dispatcher = (MockMvcDispatcher) this.web.getDispatcher();
		this.mvc.perform(get("/token/logout")).andExpect(status().isUnauthorized());
		String registrationId = this.clientRegistration.getRegistrationId();
		MvcResult result = this.mvc.perform(get("/oauth2/authorization/" + registrationId))
			.andExpect(status().isFound())
			.andReturn();
		MockHttpSession session = (MockHttpSession) result.getRequest().getSession();
		String redirectUrl = UrlUtils.decode(result.getResponse().getRedirectedUrl());
		String state = this.mvc
			.perform(get(redirectUrl)
				.with(httpBasic(this.clientRegistration.getClientId(), this.clientRegistration.getClientSecret())))
			.andReturn()
			.getResponse()
			.getContentAsString();
		result = this.mvc
			.perform(get("/login/oauth2/code/" + registrationId).param("code", "code")
				.param("state", state)
				.session(session))
			.andExpect(status().isFound())
			.andReturn();
		session = (MockHttpSession) result.getRequest().getSession();
		dispatcher.registerSession(session);
		return session;
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
		ClientRegistrationRepository clientRegistrationRepository(ClientRegistration clientRegistration) {
			return new InMemoryClientRegistrationRepository(clientRegistration);
		}

	}

	@Configuration
	@EnableWebSecurity
	@Import(RegistrationConfig.class)
	static class DefaultConfig {

		@Bean
		@Order(1)
		SecurityFilterChain filters(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeHttpRequests((authorize) -> authorize.anyRequest().authenticated())
				.oauth2Login(Customizer.withDefaults())
				.oidcLogout((oidc) -> oidc.backChannel(Customizer.withDefaults()));
			// @formatter:on

			return http.build();
		}

	}

	@Configuration
	@EnableWebSecurity
	@Import(RegistrationConfig.class)
	static class LogoutUriConfig {

		@Bean
		@Order(1)
		SecurityFilterChain filters(HttpSecurity http) throws Exception {
			// @formatter:off
			http
					.authorizeHttpRequests((authorize) -> authorize.anyRequest().authenticated())
					.oauth2Login(Customizer.withDefaults())
					.oidcLogout((oidc) -> oidc
						.backChannel((backchannel) -> backchannel.logoutUri("http://localhost/wrong"))
					);
			// @formatter:on

			return http.build();
		}

	}

	@Configuration
	@EnableWebSecurity
	@Import(RegistrationConfig.class)
	static class SelfLogoutUriConfig {

		@Bean
		@Order(1)
		SecurityFilterChain filters(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeHttpRequests((authorize) -> authorize.anyRequest().authenticated())
				.oauth2Login(Customizer.withDefaults())
				.oidcLogout((oidc) -> oidc
					.backChannel(Customizer.withDefaults())
				);
			// @formatter:on

			return http.build();
		}

	}

	@Configuration
	@EnableWebSecurity
	@Import(RegistrationConfig.class)
	static class CookieConfig {

		private final MockWebServer server = new MockWebServer();

		@Bean
		@Order(1)
		SecurityFilterChain filters(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeHttpRequests((authorize) -> authorize.anyRequest().authenticated())
				.oauth2Login(Customizer.withDefaults())
				.oidcLogout((oidc) -> oidc
					.backChannel(Customizer.withDefaults())
				);
			// @formatter:on

			return http.build();
		}

		@Bean
		OidcSessionRegistry sessionRegistry() {
			return new InMemoryOidcSessionRegistry();
		}

		@Bean
		OidcBackChannelLogoutHandler oidcLogoutHandler(OidcSessionRegistry sessionRegistry) {
			OidcBackChannelLogoutHandler logoutHandler = new OidcBackChannelLogoutHandler(sessionRegistry);
			logoutHandler.setSessionCookieName("SESSION");
			return logoutHandler;
		}

		@Bean
		MockWebServer web(ObjectProvider<MockMvc> mvc) {
			MockMvcDispatcher dispatcher = new MockMvcDispatcher(mvc);
			dispatcher.setAssertion((rr) -> {
				String cookie = rr.getHeaders().get("Cookie");
				if (cookie == null) {
					return;
				}
				assertThat(cookie).contains("SESSION").doesNotContain("JSESSIONID");
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
	@EnableWebSecurity
	@Import(RegistrationConfig.class)
	static class WithCustomComponentsConfig {

		OidcSessionRegistry sessionRegistry = spy(new InMemoryOidcSessionRegistry());

		@Bean
		@Order(1)
		SecurityFilterChain filters(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeHttpRequests((authorize) -> authorize.anyRequest().authenticated())
				.oauth2Login(Customizer.withDefaults())
				.oidcLogout((oidc) -> oidc.backChannel(Customizer.withDefaults()));
			// @formatter:on

			return http.build();
		}

		@Bean
		OidcSessionRegistry sessionRegistry() {
			return this.sessionRegistry;
		}

	}

	@Configuration
	@EnableWebSecurity
	@Import(RegistrationConfig.class)
	static class WithBrokenLogoutConfig {

		private final LogoutHandler logoutHandler = mock(LogoutHandler.class);

		@Bean
		@Order(1)
		SecurityFilterChain filters(HttpSecurity http) throws Exception {
			// @formatter:off
			http
					.authorizeHttpRequests((authorize) -> authorize.anyRequest().authenticated())
					.logout((logout) -> logout.addLogoutHandler(this.logoutHandler))
					.oauth2Login(Customizer.withDefaults())
					.oidcLogout((oidc) -> oidc.backChannel(Customizer.withDefaults()));
			// @formatter:on

			return http.build();
		}

		@Bean
		LogoutHandler logoutHandler() {
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
		ClientRegistrationRepository clientRegistrationRepository(ClientRegistration clientRegistration) {
			return new InMemoryClientRegistrationRepository(clientRegistration);
		}

	}

	@Configuration
	@EnableWebSecurity
	@Import(ProviderIssuerMissingRegistrationConfig.class)
	static class ProviderIssuerMissingConfig {

		@Bean
		@Order(1)
		SecurityFilterChain filters(HttpSecurity http) throws Exception {
			// @formatter:off
			http
					.authorizeHttpRequests((authorize) -> authorize.anyRequest().authenticated())
					.oauth2Login(Customizer.withDefaults())
					.oidcLogout((oidc) -> oidc.backChannel(Customizer.withDefaults()));
			// @formatter:on

			return http.build();
		}

	}

	@Configuration
	@EnableWebSecurity
	@EnableWebMvc
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

		@Bean
		@Order(0)
		SecurityFilterChain authorizationServer(HttpSecurity http, ClientRegistration registration) throws Exception {
			// @formatter:off
			http
				.securityMatcher("/jwks", "/login/oauth/authorize", "/nonce", "/token", "/token/logout", "/user")
				.authorizeHttpRequests((authorize) -> authorize
					.requestMatchers("/jwks").permitAll()
					.anyRequest().authenticated()
				)
				.httpBasic(Customizer.withDefaults())
				.oauth2ResourceServer((oauth2) -> oauth2
					.jwt((jwt) -> jwt.jwkSetUri(registration.getProviderDetails().getJwkSetUri()))
				);
			// @formatter:off

			return http.build();
		}

		@Bean
		UserDetailsService users(ClientRegistration registration) {
			return new InMemoryUserDetailsManager(User.withUsername(registration.getClientId())
					.password("{noop}" + registration.getClientSecret()).authorities("APP").build());
		}

		@GetMapping("/login/oauth/authorize")
		String nonce(@RequestParam("nonce") String nonce, @RequestParam("state") String state) {
			this.nonce = nonce;
			return state;
		}

		@PostMapping("/token")
		Map<String, Object> accessToken(HttpServletRequest request) {
			HttpSession session = request.getSession();
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
		MockWebServer web(ObjectProvider<MockMvc> mvc) {
			this.server.setDispatcher(new MockMvcDispatcher(mvc));
			return this.server;
		}

		@PreDestroy
		void shutdown() throws IOException {
			this.server.shutdown();
		}

	}

	@Configuration
	@EnableWebSecurity
	@Import(RegistrationConfig.class)
	static class WithOidcBackChannelDslConfig {

		@Bean
		@Order(1)
		SecurityFilterChain filters(HttpSecurity http) throws Exception {
			http
					.authorizeHttpRequests((authorize) -> authorize.anyRequest().authenticated())
					.oauth2Login(Customizer.withDefaults())
					.oidcBackChannelLogout(Customizer.withDefaults());
			return http.build();
		}

	}

	private static class MockMvcDispatcher extends Dispatcher {

		private final Map<String, MockHttpSession> session = new ConcurrentHashMap<>();

		private final ObjectProvider<MockMvc> mvcProvider;

		private MockMvc mvc;

		private Consumer<RecordedRequest> assertion = (rr) -> { };

		MockMvcDispatcher(ObjectProvider<MockMvc> mvc) {
			this.mvcProvider = mvc;
		}

		@Override
		public MockResponse dispatch(RecordedRequest request) throws InterruptedException {
			this.assertion.accept(request);
			this.mvc = this.mvcProvider.getObject();
			String method = request.getMethod();
			String path = request.getPath();
			String csrf = request.getHeader("X-CSRF-TOKEN");
			MockHttpSession session = session(request);
			MockHttpServletRequestBuilder builder;
			if ("GET".equals(method)) {
				builder = get(path);
			}
			else {
				builder = post(path).content(request.getBody().readUtf8());
				if (csrf != null) {
					builder.header("X-CSRF-TOKEN", csrf);
				}
				else {
					builder.with(csrf());
				}
			}
			for (Map.Entry<String, List<String>> header : request.getHeaders().toMultimap().entrySet()) {
				builder.header(header.getKey(), header.getValue().iterator().next());
			}
			try {
				MockHttpServletResponse mvcResponse = this.mvc.perform(builder.session(session)).andReturn().getResponse();
				return toMockResponse(mvcResponse);
			}
			catch (Exception ex) {
				MockResponse response = new MockResponse();
				response.setResponseCode(500);
				return response;
			}
		}

		void registerSession(MockHttpSession session) {
			this.session.put(session.getId(), session);
		}

		void setAssertion(Consumer<RecordedRequest> assertion) {
			this.assertion = assertion;
		}

		private MockHttpSession session(RecordedRequest request) {
			String cookieHeaderValue = request.getHeader("Cookie");
			if (cookieHeaderValue == null) {
				return new MockHttpSession();
			}
			String[] cookies = cookieHeaderValue.split(";");
			for (String cookie : cookies) {
				String[] parts = cookie.split("=");
				if ("JSESSIONID".equals(parts[0])) {
					return this.session.computeIfAbsent(parts[1],
							(k) -> new MockHttpSession(new MockServletContext(), parts[1]));
				}
				if ("SESSION".equals(parts[0])) {
					return this.session.computeIfAbsent(parts[1],
							(k) -> new MockHttpSession(new MockServletContext(), parts[1]));
				}
			}
			return new MockHttpSession();
		}

		private MockResponse toMockResponse(MockHttpServletResponse mvcResponse) {
			MockResponse response = new MockResponse();
			response.setResponseCode(mvcResponse.getStatus());
			for (String name : mvcResponse.getHeaderNames()) {
				response.addHeader(name, mvcResponse.getHeaderValue(name));
			}
			response.setBody(getContentAsString(mvcResponse));
			return response;
		}

		private String getContentAsString(MockHttpServletResponse response) {
			try {
				return response.getContentAsString();
			}
			catch (Exception ex) {
				throw new RuntimeException(ex);
			}
		}

	}

}
