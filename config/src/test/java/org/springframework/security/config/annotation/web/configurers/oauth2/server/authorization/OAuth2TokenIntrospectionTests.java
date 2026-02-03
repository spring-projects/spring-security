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
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.function.Consumer;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabase;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.mock.http.client.MockClientHttpResponse;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.OAuth2TokenIntrospectionClaimNames;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenIntrospection;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.TestOAuth2Authorizations;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenIntrospectionAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenIntrospectionAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository.RegisteredClientParametersMapper;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;
import org.springframework.security.oauth2.server.authorization.http.converter.OAuth2TokenIntrospectionHttpMessageConverter;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimsContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimsSet;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2TokenIntrospectionAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Integration tests for the OAuth 2.0 Token Introspection endpoint.
 *
 * @author Gerardo Roza
 * @author Joe Grandja
 */
@ExtendWith(SpringTestContextExtension.class)
public class OAuth2TokenIntrospectionTests {

	private static EmbeddedDatabase db;

	private static OAuth2TokenCustomizer<OAuth2TokenClaimsContext> accessTokenCustomizer;

	private static AuthenticationConverter authenticationConverter;

	private static Consumer<List<AuthenticationConverter>> authenticationConvertersConsumer;

	private static AuthenticationProvider authenticationProvider;

	private static Consumer<List<AuthenticationProvider>> authenticationProvidersConsumer;

	private static AuthenticationSuccessHandler authenticationSuccessHandler;

	private static AuthenticationFailureHandler authenticationFailureHandler;

	private static final HttpMessageConverter<OAuth2TokenIntrospection> tokenIntrospectionHttpResponseConverter = new OAuth2TokenIntrospectionHttpMessageConverter();

	private static final HttpMessageConverter<OAuth2AccessTokenResponse> accessTokenHttpResponseConverter = new OAuth2AccessTokenResponseHttpMessageConverter();

	public final SpringTestContext spring = new SpringTestContext(this);

	@Autowired
	private MockMvc mvc;

	@Autowired
	private JdbcOperations jdbcOperations;

	@Autowired
	private RegisteredClientRepository registeredClientRepository;

	@Autowired
	private OAuth2AuthorizationService authorizationService;

	@Autowired
	private AuthorizationServerSettings authorizationServerSettings;

	@BeforeAll
	public static void init() {
		authenticationConverter = mock(AuthenticationConverter.class);
		authenticationConvertersConsumer = mock(Consumer.class);
		authenticationProvider = mock(AuthenticationProvider.class);
		authenticationProvidersConsumer = mock(Consumer.class);
		authenticationSuccessHandler = mock(AuthenticationSuccessHandler.class);
		authenticationFailureHandler = mock(AuthenticationFailureHandler.class);
		accessTokenCustomizer = mock(OAuth2TokenCustomizer.class);
		db = new EmbeddedDatabaseBuilder().generateUniqueName(true)
			.setType(EmbeddedDatabaseType.HSQL)
			.setScriptEncoding("UTF-8")
			.addScript("org/springframework/security/oauth2/server/authorization/oauth2-authorization-schema.sql")
			.addScript(
					"org/springframework/security/oauth2/server/authorization/client/oauth2-registered-client-schema.sql")
			.build();
	}

	@SuppressWarnings("unchecked")
	@BeforeEach
	public void setup() {
		reset(authenticationConverter);
		reset(authenticationConvertersConsumer);
		reset(authenticationProvider);
		reset(authenticationProvidersConsumer);
		reset(authenticationSuccessHandler);
		reset(authenticationFailureHandler);
		reset(accessTokenCustomizer);
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
	public void requestWhenIntrospectValidAccessTokenThenActive() throws Exception {
		this.spring.register(AuthorizationServerConfiguration.class).autowire();

		RegisteredClient introspectRegisteredClient = TestRegisteredClients.registeredClient2()
			.clientSecret("secret-2")
			.build();
		this.registeredClientRepository.save(introspectRegisteredClient);

		RegisteredClient authorizedRegisteredClient = TestRegisteredClients.registeredClient().build();
		Instant issuedAt = Instant.now();
		Instant expiresAt = issuedAt.plus(Duration.ofHours(1));
		OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "access-token",
				issuedAt, expiresAt, new HashSet<>(Arrays.asList("scope1", "scope2")));
		// @formatter:off
		OAuth2TokenClaimsSet accessTokenClaims = OAuth2TokenClaimsSet.builder()
				.issuer("https://provider.com")
				.subject("subject")
				.audience(Collections.singletonList(authorizedRegisteredClient.getClientId()))
				.issuedAt(issuedAt)
				.notBefore(issuedAt)
				.expiresAt(expiresAt)
				.claim(OAuth2TokenIntrospectionClaimNames.SCOPE, accessToken.getScopes())
				.id("id")
				.build();
		// @formatter:on
		OAuth2Authorization authorization = TestOAuth2Authorizations
			.authorization(authorizedRegisteredClient, accessToken, accessTokenClaims.getClaims())
			.build();
		this.registeredClientRepository.save(authorizedRegisteredClient);
		this.authorizationService.save(authorization);

		// @formatter:off
		MvcResult mvcResult = this.mvc.perform(post(this.authorizationServerSettings.getTokenIntrospectionEndpoint())
				.params(getTokenIntrospectionRequestParameters(accessToken, OAuth2TokenType.ACCESS_TOKEN))
				.header(HttpHeaders.AUTHORIZATION, getAuthorizationHeader(introspectRegisteredClient)))
				.andExpect(status().isOk())
				.andReturn();
		// @formatter:on

		OAuth2TokenIntrospection tokenIntrospectionResponse = readTokenIntrospectionResponse(mvcResult);
		assertThat(tokenIntrospectionResponse.isActive()).isTrue();
		assertThat(tokenIntrospectionResponse.getClientId()).isEqualTo(authorizedRegisteredClient.getClientId());
		assertThat(tokenIntrospectionResponse.getUsername()).isNull();
		assertThat(tokenIntrospectionResponse.getIssuedAt()).isBetween(accessTokenClaims.getIssuedAt().minusSeconds(1),
				accessTokenClaims.getIssuedAt().plusSeconds(1));
		assertThat(tokenIntrospectionResponse.getExpiresAt()).isBetween(
				accessTokenClaims.getExpiresAt().minusSeconds(1), accessTokenClaims.getExpiresAt().plusSeconds(1));
		assertThat(tokenIntrospectionResponse.getScopes()).containsExactlyInAnyOrderElementsOf(accessToken.getScopes());
		assertThat(tokenIntrospectionResponse.getTokenType()).isEqualTo(accessToken.getTokenType().getValue());
		assertThat(tokenIntrospectionResponse.getNotBefore()).isBetween(
				accessTokenClaims.getNotBefore().minusSeconds(1), accessTokenClaims.getNotBefore().plusSeconds(1));
		assertThat(tokenIntrospectionResponse.getSubject()).isEqualTo(accessTokenClaims.getSubject());
		assertThat(tokenIntrospectionResponse.getAudience())
			.containsExactlyInAnyOrderElementsOf(accessTokenClaims.getAudience());
		assertThat(tokenIntrospectionResponse.getIssuer()).isEqualTo(accessTokenClaims.getIssuer());
		assertThat(tokenIntrospectionResponse.getId()).isEqualTo(accessTokenClaims.getId());
	}

	@Test
	public void requestWhenIntrospectValidRefreshTokenThenActive() throws Exception {
		this.spring.register(AuthorizationServerConfiguration.class).autowire();

		RegisteredClient introspectRegisteredClient = TestRegisteredClients.registeredClient2()
			.clientSecret("secret-2")
			.build();
		this.registeredClientRepository.save(introspectRegisteredClient);

		RegisteredClient authorizedRegisteredClient = TestRegisteredClients.registeredClient().build();
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(authorizedRegisteredClient).build();
		OAuth2RefreshToken refreshToken = authorization.getRefreshToken().getToken();
		this.registeredClientRepository.save(authorizedRegisteredClient);
		this.authorizationService.save(authorization);

		// @formatter:off
		MvcResult mvcResult = this.mvc.perform(post(this.authorizationServerSettings.getTokenIntrospectionEndpoint())
				.params(getTokenIntrospectionRequestParameters(refreshToken, OAuth2TokenType.REFRESH_TOKEN))
				.header(HttpHeaders.AUTHORIZATION, getAuthorizationHeader(introspectRegisteredClient)))
				.andExpect(status().isOk())
				.andReturn();
		// @formatter:on

		OAuth2TokenIntrospection tokenIntrospectionResponse = readTokenIntrospectionResponse(mvcResult);
		assertThat(tokenIntrospectionResponse.isActive()).isTrue();
		assertThat(tokenIntrospectionResponse.getClientId()).isEqualTo(authorizedRegisteredClient.getClientId());
		assertThat(tokenIntrospectionResponse.getUsername()).isNull();
		assertThat(tokenIntrospectionResponse.getIssuedAt()).isBetween(refreshToken.getIssuedAt().minusSeconds(1),
				refreshToken.getIssuedAt().plusSeconds(1));
		assertThat(tokenIntrospectionResponse.getExpiresAt()).isBetween(refreshToken.getExpiresAt().minusSeconds(1),
				refreshToken.getExpiresAt().plusSeconds(1));
		assertThat(tokenIntrospectionResponse.getScopes()).isNull();
		assertThat(tokenIntrospectionResponse.getTokenType()).isNull();
		assertThat(tokenIntrospectionResponse.getNotBefore()).isNull();
		assertThat(tokenIntrospectionResponse.getSubject()).isNull();
		assertThat(tokenIntrospectionResponse.getAudience()).isNull();
		assertThat(tokenIntrospectionResponse.getIssuer()).isNull();
		assertThat(tokenIntrospectionResponse.getId()).isNull();
	}

	@Test
	public void requestWhenObtainReferenceAccessTokenAndIntrospectThenActive() throws Exception {
		this.spring.register(AuthorizationServerConfiguration.class).autowire();

		// @formatter:off
		TokenSettings tokenSettings = TokenSettings.builder()
				.accessTokenFormat(OAuth2TokenFormat.REFERENCE)
				.build();
		RegisteredClient authorizedRegisteredClient = TestRegisteredClients.registeredClient()
				.tokenSettings(tokenSettings)
				.clientSettings(ClientSettings.builder().requireProofKey(false).build())
				.build();
		// @formatter:on
		this.registeredClientRepository.save(authorizedRegisteredClient);

		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(authorizedRegisteredClient).build();
		this.authorizationService.save(authorization);

		// @formatter:off
		MvcResult mvcResult = this.mvc.perform(post(this.authorizationServerSettings.getTokenEndpoint())
				.params(getAuthorizationCodeTokenRequestParameters(authorizedRegisteredClient, authorization))
				.header(HttpHeaders.AUTHORIZATION, getAuthorizationHeader(authorizedRegisteredClient)))
				.andExpect(status().isOk())
				.andReturn();
		// @formatter:on

		OAuth2AccessTokenResponse accessTokenResponse = readAccessTokenResponse(mvcResult);
		OAuth2AccessToken accessToken = accessTokenResponse.getAccessToken();

		RegisteredClient introspectRegisteredClient = TestRegisteredClients.registeredClient2().build();
		this.registeredClientRepository.save(introspectRegisteredClient);

		// @formatter:off
		mvcResult = this.mvc.perform(post(this.authorizationServerSettings.getTokenIntrospectionEndpoint())
				.params(getTokenIntrospectionRequestParameters(accessToken, OAuth2TokenType.ACCESS_TOKEN))
				.header(HttpHeaders.AUTHORIZATION, getAuthorizationHeader(introspectRegisteredClient)))
				.andExpect(status().isOk())
				.andReturn();
		// @formatter:on

		OAuth2TokenIntrospection tokenIntrospectionResponse = readTokenIntrospectionResponse(mvcResult);

		ArgumentCaptor<OAuth2TokenClaimsContext> accessTokenClaimsContextCaptor = ArgumentCaptor
			.forClass(OAuth2TokenClaimsContext.class);
		verify(accessTokenCustomizer).customize(accessTokenClaimsContextCaptor.capture());

		OAuth2TokenClaimsContext accessTokenClaimsContext = accessTokenClaimsContextCaptor.getValue();
		OAuth2TokenClaimsSet accessTokenClaims = accessTokenClaimsContext.getClaims().build();

		assertThat(tokenIntrospectionResponse.isActive()).isTrue();
		assertThat(tokenIntrospectionResponse.getClientId()).isEqualTo(authorizedRegisteredClient.getClientId());
		assertThat(tokenIntrospectionResponse.getUsername()).isNull();
		assertThat(tokenIntrospectionResponse.getIssuedAt()).isBetween(accessTokenClaims.getIssuedAt().minusSeconds(1),
				accessTokenClaims.getIssuedAt().plusSeconds(1));
		assertThat(tokenIntrospectionResponse.getExpiresAt()).isBetween(
				accessTokenClaims.getExpiresAt().minusSeconds(1), accessTokenClaims.getExpiresAt().plusSeconds(1));
		List<String> scopes = new ArrayList<>(accessTokenClaims.getClaim(OAuth2ParameterNames.SCOPE));
		assertThat(tokenIntrospectionResponse.getScopes()).containsExactlyInAnyOrderElementsOf(scopes);
		assertThat(tokenIntrospectionResponse.getTokenType()).isEqualTo(accessToken.getTokenType().getValue());
		assertThat(tokenIntrospectionResponse.getNotBefore()).isBetween(
				accessTokenClaims.getNotBefore().minusSeconds(1), accessTokenClaims.getNotBefore().plusSeconds(1));
		assertThat(tokenIntrospectionResponse.getSubject()).isEqualTo(accessTokenClaims.getSubject());
		assertThat(tokenIntrospectionResponse.getAudience())
			.containsExactlyInAnyOrderElementsOf(accessTokenClaims.getAudience());
		assertThat(tokenIntrospectionResponse.getIssuer()).isEqualTo(accessTokenClaims.getIssuer());
		assertThat(tokenIntrospectionResponse.getId()).isEqualTo(accessTokenClaims.getId());
	}

	@Test
	public void requestWhenTokenIntrospectionEndpointCustomizedThenUsed() throws Exception {
		this.spring.register(AuthorizationServerConfigurationCustomTokenIntrospectionEndpoint.class).autowire();

		RegisteredClient introspectRegisteredClient = TestRegisteredClients.registeredClient2().build();
		this.registeredClientRepository.save(introspectRegisteredClient);

		RegisteredClient authorizedRegisteredClient = TestRegisteredClients.registeredClient().build();
		this.registeredClientRepository.save(authorizedRegisteredClient);

		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(authorizedRegisteredClient).build();
		this.authorizationService.save(authorization);

		OAuth2AccessToken accessToken = authorization.getAccessToken().getToken();

		Authentication clientPrincipal = new OAuth2ClientAuthenticationToken(introspectRegisteredClient,
				ClientAuthenticationMethod.CLIENT_SECRET_BASIC, introspectRegisteredClient.getClientSecret());
		OAuth2TokenIntrospectionAuthenticationToken tokenIntrospectionAuthentication = new OAuth2TokenIntrospectionAuthenticationToken(
				accessToken.getTokenValue(), clientPrincipal, null, null);

		given(authenticationConverter.convert(any())).willReturn(tokenIntrospectionAuthentication);
		given(authenticationProvider.supports(eq(OAuth2TokenIntrospectionAuthenticationToken.class))).willReturn(true);
		given(authenticationProvider.authenticate(any())).willReturn(tokenIntrospectionAuthentication);

		// @formatter:off
		this.mvc.perform(post(this.authorizationServerSettings.getTokenIntrospectionEndpoint())
				.params(getTokenIntrospectionRequestParameters(accessToken, OAuth2TokenType.ACCESS_TOKEN))
				.header(HttpHeaders.AUTHORIZATION, getAuthorizationHeader(introspectRegisteredClient)))
				.andExpect(status().isOk());
		// @formatter:on

		verify(authenticationConverter).convert(any());

		@SuppressWarnings("unchecked")
		ArgumentCaptor<List<AuthenticationConverter>> authenticationConvertersCaptor = ArgumentCaptor
			.forClass(List.class);
		verify(authenticationConvertersConsumer).accept(authenticationConvertersCaptor.capture());
		List<AuthenticationConverter> authenticationConverters = authenticationConvertersCaptor.getValue();
		assertThat(authenticationConverters).allMatch((converter) -> converter == authenticationConverter
				|| converter instanceof OAuth2TokenIntrospectionAuthenticationConverter);

		verify(authenticationProvider).authenticate(eq(tokenIntrospectionAuthentication));

		@SuppressWarnings("unchecked")
		ArgumentCaptor<List<AuthenticationProvider>> authenticationProvidersCaptor = ArgumentCaptor
			.forClass(List.class);
		verify(authenticationProvidersConsumer).accept(authenticationProvidersCaptor.capture());
		List<AuthenticationProvider> authenticationProviders = authenticationProvidersCaptor.getValue();
		assertThat(authenticationProviders).allMatch((provider) -> provider == authenticationProvider
				|| provider instanceof OAuth2TokenIntrospectionAuthenticationProvider);

		verify(authenticationSuccessHandler).onAuthenticationSuccess(any(), any(),
				eq(tokenIntrospectionAuthentication));
	}

	@Test
	public void requestWhenIntrospectionRequestIncludesIssuerPathThenActive() throws Exception {
		this.spring.register(AuthorizationServerConfigurationCustomTokenIntrospectionEndpoint.class).autowire();

		RegisteredClient introspectRegisteredClient = TestRegisteredClients.registeredClient2().build();
		this.registeredClientRepository.save(introspectRegisteredClient);

		RegisteredClient authorizedRegisteredClient = TestRegisteredClients.registeredClient().build();
		this.registeredClientRepository.save(authorizedRegisteredClient);

		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(authorizedRegisteredClient).build();
		this.authorizationService.save(authorization);

		OAuth2AccessToken accessToken = authorization.getAccessToken().getToken();

		Authentication clientPrincipal = new OAuth2ClientAuthenticationToken(introspectRegisteredClient,
				ClientAuthenticationMethod.CLIENT_SECRET_BASIC, introspectRegisteredClient.getClientSecret());
		OAuth2TokenIntrospectionAuthenticationToken tokenIntrospectionAuthentication = new OAuth2TokenIntrospectionAuthenticationToken(
				accessToken.getTokenValue(), clientPrincipal, null, null);

		given(authenticationConverter.convert(any())).willReturn(tokenIntrospectionAuthentication);
		given(authenticationProvider.supports(eq(OAuth2TokenIntrospectionAuthenticationToken.class))).willReturn(true);
		given(authenticationProvider.authenticate(any())).willReturn(tokenIntrospectionAuthentication);

		String issuer = "https://example.com:8443/issuer1";

		// @formatter:off
		this.mvc.perform(post(issuer.concat(this.authorizationServerSettings.getTokenIntrospectionEndpoint()))
						.params(getTokenIntrospectionRequestParameters(accessToken, OAuth2TokenType.ACCESS_TOKEN))
						.header(HttpHeaders.AUTHORIZATION, getAuthorizationHeader(introspectRegisteredClient)))
				.andExpect(status().isOk());
		// @formatter:on
	}

	private static MultiValueMap<String, String> getTokenIntrospectionRequestParameters(OAuth2Token token,
			OAuth2TokenType tokenType) {
		MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
		parameters.set(OAuth2ParameterNames.TOKEN, token.getTokenValue());
		parameters.set(OAuth2ParameterNames.TOKEN_TYPE_HINT, tokenType.getValue());
		return parameters;
	}

	private static OAuth2TokenIntrospection readTokenIntrospectionResponse(MvcResult mvcResult) throws Exception {
		MockHttpServletResponse servletResponse = mvcResult.getResponse();
		MockClientHttpResponse httpResponse = new MockClientHttpResponse(servletResponse.getContentAsByteArray(),
				HttpStatus.valueOf(servletResponse.getStatus()));
		return tokenIntrospectionHttpResponseConverter.read(OAuth2TokenIntrospection.class, httpResponse);
	}

	private static MultiValueMap<String, String> getAuthorizationCodeTokenRequestParameters(
			RegisteredClient registeredClient, OAuth2Authorization authorization) {
		MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
		parameters.set(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.AUTHORIZATION_CODE.getValue());
		parameters.set(OAuth2ParameterNames.CODE,
				authorization.getToken(OAuth2AuthorizationCode.class).getToken().getTokenValue());
		parameters.set(OAuth2ParameterNames.REDIRECT_URI, registeredClient.getRedirectUris().iterator().next());
		return parameters;
	}

	private static OAuth2AccessTokenResponse readAccessTokenResponse(MvcResult mvcResult) throws Exception {
		MockHttpServletResponse servletResponse = mvcResult.getResponse();
		MockClientHttpResponse httpResponse = new MockClientHttpResponse(servletResponse.getContentAsByteArray(),
				HttpStatus.valueOf(servletResponse.getStatus()));
		return accessTokenHttpResponseConverter.read(OAuth2AccessTokenResponse.class, httpResponse);
	}

	private static String getAuthorizationHeader(RegisteredClient registeredClient) throws Exception {
		String clientId = registeredClient.getClientId();
		String clientSecret = registeredClient.getClientSecret();
		clientId = URLEncoder.encode(clientId, StandardCharsets.UTF_8.name());
		clientSecret = URLEncoder.encode(clientSecret, StandardCharsets.UTF_8.name());
		String credentialsString = clientId + ":" + clientSecret;
		byte[] encodedBytes = Base64.getEncoder().encode(credentialsString.getBytes(StandardCharsets.UTF_8));
		return "Basic " + new String(encodedBytes, StandardCharsets.UTF_8);
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
		OAuth2AuthorizationConsentService authorizationConsentService(JdbcOperations jdbcOperations,
				RegisteredClientRepository registeredClientRepository) {
			return new JdbcOAuth2AuthorizationConsentService(jdbcOperations, registeredClientRepository);
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
		AuthorizationServerSettings authorizationServerSettings() {
			return AuthorizationServerSettings.builder().tokenIntrospectionEndpoint("/test/introspect").build();
		}

		@Bean
		OAuth2TokenCustomizer<OAuth2TokenClaimsContext> accessTokenCustomizer() {
			return accessTokenCustomizer;
		}

		@Bean
		PasswordEncoder passwordEncoder() {
			return NoOpPasswordEncoder.getInstance();
		}

	}

	@EnableWebSecurity
	@Configuration(proxyBeanMethods = false)
	static class AuthorizationServerConfigurationCustomTokenIntrospectionEndpoint
			extends AuthorizationServerConfiguration {

		// @formatter:off
		@Bean
		SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
			http
					.oauth2AuthorizationServer((authorizationServer) ->
							authorizationServer
									.tokenIntrospectionEndpoint((tokenIntrospectionEndpoint) ->
											tokenIntrospectionEndpoint
													.introspectionRequestConverter(authenticationConverter)
													.introspectionRequestConverters(authenticationConvertersConsumer)
													.authenticationProvider(authenticationProvider)
													.authenticationProviders(authenticationProvidersConsumer)
													.introspectionResponseHandler(authenticationSuccessHandler)
													.errorResponseHandler(authenticationFailureHandler))
					)
					.authorizeHttpRequests((authorize) ->
							authorize.anyRequest().authenticated()
					);
			return http.build();
		}
		// @formatter:on

		@Override
		AuthorizationServerSettings authorizationServerSettings() {
			return AuthorizationServerSettings.builder()
				.multipleIssuersAllowed(true)
				.tokenIntrospectionEndpoint("/test/introspect")
				.build();
		}

	}

}
