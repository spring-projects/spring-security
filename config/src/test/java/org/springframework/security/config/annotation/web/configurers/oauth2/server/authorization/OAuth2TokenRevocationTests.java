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

package org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.function.Consumer;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabase;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.jose.TestJwks;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.TestOAuth2Authorizations;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenRevocationAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenRevocationAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository.RegisteredClientParametersMapper;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2TokenRevocationAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Integration tests for the OAuth 2.0 Token Revocation endpoint.
 *
 * @author Joe Grandja
 */
@ExtendWith(SpringTestContextExtension.class)
public class OAuth2TokenRevocationTests {

	private static final String DEFAULT_TOKEN_REVOCATION_ENDPOINT_URI = "/oauth2/revoke";

	private static EmbeddedDatabase db;

	private static JWKSource<SecurityContext> jwkSource;

	private static AuthenticationConverter authenticationConverter;

	private static Consumer<List<AuthenticationConverter>> authenticationConvertersConsumer;

	private static AuthenticationProvider authenticationProvider;

	private static Consumer<List<AuthenticationProvider>> authenticationProvidersConsumer;

	private static AuthenticationSuccessHandler authenticationSuccessHandler;

	private static AuthenticationFailureHandler authenticationFailureHandler;

	public final SpringTestContext spring = new SpringTestContext(this);

	@Autowired
	private MockMvc mvc;

	@Autowired
	private JdbcOperations jdbcOperations;

	@Autowired
	private RegisteredClientRepository registeredClientRepository;

	@Autowired
	private OAuth2AuthorizationService authorizationService;

	@BeforeAll
	public static void init() {
		JWKSet jwkSet = new JWKSet(TestJwks.DEFAULT_RSA_JWK);
		jwkSource = (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
		authenticationConverter = mock(AuthenticationConverter.class);
		authenticationConvertersConsumer = mock(Consumer.class);
		authenticationProvider = mock(AuthenticationProvider.class);
		authenticationProvidersConsumer = mock(Consumer.class);
		authenticationSuccessHandler = mock(AuthenticationSuccessHandler.class);
		authenticationFailureHandler = mock(AuthenticationFailureHandler.class);
		db = new EmbeddedDatabaseBuilder().generateUniqueName(true)
			.setType(EmbeddedDatabaseType.HSQL)
			.setScriptEncoding("UTF-8")
			.addScript("org/springframework/security/oauth2/server/authorization/oauth2-authorization-schema.sql")
			.addScript(
					"org/springframework/security/oauth2/server/authorization/client/oauth2-registered-client-schema.sql")
			.build();
	}

	@AfterEach
	public void tearDown() {
		this.jdbcOperations.update("truncate table oauth2_authorization");
		this.jdbcOperations.update("truncate table oauth2_registered_client");
	}

	@AfterAll
	public static void destroy() {
		db.shutdown();
	}

	@Test
	public void requestWhenRevokeRefreshTokenThenRevoked() throws Exception {
		this.spring.register(AuthorizationServerConfiguration.class).autowire();

		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		this.registeredClientRepository.save(registeredClient);

		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient).build();
		OAuth2RefreshToken token = authorization.getRefreshToken().getToken();
		OAuth2TokenType tokenType = OAuth2TokenType.REFRESH_TOKEN;
		this.authorizationService.save(authorization);

		this.mvc
			.perform(post(DEFAULT_TOKEN_REVOCATION_ENDPOINT_URI)
				.params(getTokenRevocationRequestParameters(token, tokenType))
				.header(HttpHeaders.AUTHORIZATION,
						"Basic " + encodeBasicAuth(registeredClient.getClientId(), registeredClient.getClientSecret())))
			.andExpect(status().isOk());

		OAuth2Authorization updatedAuthorization = this.authorizationService.findById(authorization.getId());
		OAuth2Authorization.Token<OAuth2RefreshToken> refreshToken = updatedAuthorization.getRefreshToken();
		assertThat(refreshToken.isInvalidated()).isTrue();
		OAuth2Authorization.Token<OAuth2AccessToken> accessToken = updatedAuthorization.getAccessToken();
		assertThat(accessToken.isInvalidated()).isTrue();
	}

	@Test
	public void requestWhenRevokeAccessTokenThenRevoked() throws Exception {
		this.spring.register(AuthorizationServerConfiguration.class).autowire();

		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		this.registeredClientRepository.save(registeredClient);

		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient).build();
		OAuth2AccessToken token = authorization.getAccessToken().getToken();
		OAuth2TokenType tokenType = OAuth2TokenType.ACCESS_TOKEN;
		this.authorizationService.save(authorization);

		this.mvc
			.perform(post(DEFAULT_TOKEN_REVOCATION_ENDPOINT_URI)
				.params(getTokenRevocationRequestParameters(token, tokenType))
				.header(HttpHeaders.AUTHORIZATION,
						"Basic " + encodeBasicAuth(registeredClient.getClientId(), registeredClient.getClientSecret())))
			.andExpect(status().isOk());

		OAuth2Authorization updatedAuthorization = this.authorizationService.findById(authorization.getId());
		OAuth2Authorization.Token<OAuth2AccessToken> accessToken = updatedAuthorization.getAccessToken();
		assertThat(accessToken.isInvalidated()).isTrue();
		OAuth2Authorization.Token<OAuth2RefreshToken> refreshToken = updatedAuthorization.getRefreshToken();
		assertThat(refreshToken.isInvalidated()).isFalse();
	}

	@Test
	public void requestWhenRevokeAccessTokenAndRequestIncludesIssuerPathThenRevoked() throws Exception {
		this.spring.register(AuthorizationServerConfigurationWithMultipleIssuersAllowed.class).autowire();

		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		this.registeredClientRepository.save(registeredClient);

		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient).build();
		OAuth2AccessToken token = authorization.getAccessToken().getToken();
		OAuth2TokenType tokenType = OAuth2TokenType.ACCESS_TOKEN;
		this.authorizationService.save(authorization);

		String issuer = "https://example.com:8443/issuer1";

		// @formatter:off
		this.mvc.perform(post(issuer.concat(DEFAULT_TOKEN_REVOCATION_ENDPOINT_URI))
						.params(getTokenRevocationRequestParameters(token, tokenType))
						.header(HttpHeaders.AUTHORIZATION, "Basic " + encodeBasicAuth(
								registeredClient.getClientId(), registeredClient.getClientSecret())))
				.andExpect(status().isOk());
		// @formatter:on

		OAuth2Authorization updatedAuthorization = this.authorizationService.findById(authorization.getId());
		OAuth2Authorization.Token<OAuth2AccessToken> accessToken = updatedAuthorization.getAccessToken();
		assertThat(accessToken.isInvalidated()).isTrue();
		OAuth2Authorization.Token<OAuth2RefreshToken> refreshToken = updatedAuthorization.getRefreshToken();
		assertThat(refreshToken.isInvalidated()).isFalse();
	}

	@Test
	public void requestWhenTokenRevocationEndpointCustomizedThenUsed() throws Exception {
		this.spring.register(AuthorizationServerConfigurationCustomTokenRevocationEndpoint.class).autowire();

		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		this.registeredClientRepository.save(registeredClient);

		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient).build();
		OAuth2AccessToken token = authorization.getAccessToken().getToken();
		OAuth2TokenType tokenType = OAuth2TokenType.ACCESS_TOKEN;
		this.authorizationService.save(authorization);

		Authentication clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
				ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
		OAuth2TokenRevocationAuthenticationToken tokenRevocationAuthentication = new OAuth2TokenRevocationAuthenticationToken(
				token, clientPrincipal);

		given(authenticationConverter.convert(any())).willReturn(tokenRevocationAuthentication);
		given(authenticationProvider.supports(eq(OAuth2TokenRevocationAuthenticationToken.class))).willReturn(true);
		given(authenticationProvider.authenticate(any())).willReturn(tokenRevocationAuthentication);

		this.mvc
			.perform(post(DEFAULT_TOKEN_REVOCATION_ENDPOINT_URI)
				.params(getTokenRevocationRequestParameters(token, tokenType))
				.header(HttpHeaders.AUTHORIZATION,
						"Basic " + encodeBasicAuth(registeredClient.getClientId(), registeredClient.getClientSecret())))
			.andExpect(status().isOk());

		verify(authenticationConverter).convert(any());

		@SuppressWarnings("unchecked")
		ArgumentCaptor<List<AuthenticationConverter>> authenticationConvertersCaptor = ArgumentCaptor
			.forClass(List.class);
		verify(authenticationConvertersConsumer).accept(authenticationConvertersCaptor.capture());
		List<AuthenticationConverter> authenticationConverters = authenticationConvertersCaptor.getValue();
		assertThat(authenticationConverters).allMatch((converter) -> converter == authenticationConverter
				|| converter instanceof OAuth2TokenRevocationAuthenticationConverter);

		verify(authenticationProvider).authenticate(eq(tokenRevocationAuthentication));

		@SuppressWarnings("unchecked")
		ArgumentCaptor<List<AuthenticationProvider>> authenticationProvidersCaptor = ArgumentCaptor
			.forClass(List.class);
		verify(authenticationProvidersConsumer).accept(authenticationProvidersCaptor.capture());
		List<AuthenticationProvider> authenticationProviders = authenticationProvidersCaptor.getValue();
		assertThat(authenticationProviders).allMatch((provider) -> provider == authenticationProvider
				|| provider instanceof OAuth2TokenRevocationAuthenticationProvider);

		verify(authenticationSuccessHandler).onAuthenticationSuccess(any(), any(), eq(tokenRevocationAuthentication));
	}

	private static MultiValueMap<String, String> getTokenRevocationRequestParameters(OAuth2Token token,
			OAuth2TokenType tokenType) {
		MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
		parameters.set(OAuth2ParameterNames.TOKEN, token.getTokenValue());
		parameters.set(OAuth2ParameterNames.TOKEN_TYPE_HINT, tokenType.getValue());
		return parameters;
	}

	private static String encodeBasicAuth(String clientId, String secret) throws Exception {
		clientId = URLEncoder.encode(clientId, StandardCharsets.UTF_8.name());
		secret = URLEncoder.encode(secret, StandardCharsets.UTF_8.name());
		String credentialsString = clientId + ":" + secret;
		byte[] encodedBytes = Base64.getEncoder().encode(credentialsString.getBytes(StandardCharsets.UTF_8));
		return new String(encodedBytes, StandardCharsets.UTF_8);
	}

	@EnableWebSecurity
	@Import(OAuth2AuthorizationServerConfiguration.class)
	static class AuthorizationServerConfiguration {

		@Bean
		OAuth2AuthorizationService authorizationService(JdbcOperations jdbcOperations,
				RegisteredClientRepository registeredClientRepository) {
			return new JdbcOAuth2AuthorizationService(jdbcOperations, registeredClientRepository);
		}

		@Bean
		@SuppressWarnings("removal")
		RegisteredClientRepository registeredClientRepository(JdbcOperations jdbcOperations) {
			JdbcRegisteredClientRepository jdbcRegisteredClientRepository = new JdbcRegisteredClientRepository(
					jdbcOperations);
			RegisteredClientParametersMapper registeredClientParametersMapper = new RegisteredClientParametersMapper();
			jdbcRegisteredClientRepository.setRegisteredClientParametersMapper(registeredClientParametersMapper);
			return jdbcRegisteredClientRepository;
		}

		@Bean
		JdbcOperations jdbcOperations() {
			return new JdbcTemplate(db);
		}

		@Bean
		JWKSource<SecurityContext> jwkSource() {
			return jwkSource;
		}

		@Bean
		PasswordEncoder passwordEncoder() {
			return NoOpPasswordEncoder.getInstance();
		}

	}

	@EnableWebSecurity
	@Configuration(proxyBeanMethods = false)
	static class AuthorizationServerConfigurationCustomTokenRevocationEndpoint
			extends AuthorizationServerConfiguration {

		// @formatter:off
		@Bean
		SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
			http
					.oauth2AuthorizationServer((authorizationServer) ->
							authorizationServer
									.tokenRevocationEndpoint((tokenRevocationEndpoint) ->
											tokenRevocationEndpoint
													.revocationRequestConverter(authenticationConverter)
													.revocationRequestConverters(authenticationConvertersConsumer)
													.authenticationProvider(authenticationProvider)
													.authenticationProviders(authenticationProvidersConsumer)
													.revocationResponseHandler(authenticationSuccessHandler)
													.errorResponseHandler(authenticationFailureHandler))
					)
					.authorizeHttpRequests((authorize) ->
							authorize.anyRequest().authenticated()
					);
			return http.build();
		}
		// @formatter:on

	}

	@EnableWebSecurity
	@Import(OAuth2AuthorizationServerConfiguration.class)
	static class AuthorizationServerConfigurationWithMultipleIssuersAllowed extends AuthorizationServerConfiguration {

		@Bean
		AuthorizationServerSettings authorizationServerSettings() {
			return AuthorizationServerSettings.builder().multipleIssuersAllowed(true).build();
		}

	}

}
