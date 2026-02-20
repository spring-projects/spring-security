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

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import javax.crypto.spec.SecretKeySpec;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import jakarta.servlet.http.HttpServletResponse;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.assertj.core.data.TemporalUnitWithinOffset;
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
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabase;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.mock.http.MockHttpOutputMessage;
import org.springframework.mock.http.client.MockClientHttpResponse;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.oauth2.jose.TestJwks;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository.RegisteredClientParametersMapper;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;
import org.springframework.security.oauth2.server.authorization.oidc.OidcClientRegistration;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcClientConfigurationAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcClientRegistrationAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcClientRegistrationAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.oidc.converter.OidcClientRegistrationRegisteredClientConverter;
import org.springframework.security.oauth2.server.authorization.oidc.converter.RegisteredClientOidcClientRegistrationConverter;
import org.springframework.security.oauth2.server.authorization.oidc.http.converter.OidcClientRegistrationHttpMessageConverter;
import org.springframework.security.oauth2.server.authorization.oidc.web.authentication.OidcClientRegistrationAuthenticationConverter;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.util.CollectionUtils;
import org.springframework.web.util.UriComponentsBuilder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.CoreMatchers.containsString;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.willAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Integration tests for OpenID Connect Dynamic Client Registration 1.0.
 *
 * @author Ovidiu Popa
 * @author Joe Grandja
 * @author Dmitriy Dubson
 */
@ExtendWith(SpringTestContextExtension.class)
public class OidcClientRegistrationTests {

	private static final String ISSUER = "https://example.com:8443/issuer1";

	private static final String DEFAULT_TOKEN_ENDPOINT_URI = "/oauth2/token";

	private static final String DEFAULT_OIDC_CLIENT_REGISTRATION_ENDPOINT_URI = "/connect/register";

	private static final HttpMessageConverter<OAuth2AccessTokenResponse> accessTokenHttpResponseConverter = new OAuth2AccessTokenResponseHttpMessageConverter();

	private static final HttpMessageConverter<OidcClientRegistration> clientRegistrationHttpMessageConverter = new OidcClientRegistrationHttpMessageConverter();

	private static EmbeddedDatabase db;

	private static JWKSource<SecurityContext> jwkSource;

	private static JWKSet clientJwkSet;

	private static JwtEncoder jwtClientAssertionEncoder;

	public final SpringTestContext spring = new SpringTestContext(this);

	@Autowired
	private MockMvc mvc;

	@Autowired
	private JdbcOperations jdbcOperations;

	@Autowired
	private RegisteredClientRepository registeredClientRepository;

	@Autowired
	private AuthorizationServerSettings authorizationServerSettings;

	private static AuthenticationConverter authenticationConverter;

	private static Consumer<List<AuthenticationConverter>> authenticationConvertersConsumer;

	private static AuthenticationProvider authenticationProvider;

	private static Consumer<List<AuthenticationProvider>> authenticationProvidersConsumer;

	private static AuthenticationSuccessHandler authenticationSuccessHandler;

	private static AuthenticationFailureHandler authenticationFailureHandler;

	private MockWebServer server;

	private String clientJwkSetUrl;

	@BeforeAll
	public static void init() {
		JWKSet jwkSet = new JWKSet(TestJwks.DEFAULT_RSA_JWK);
		jwkSource = (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
		clientJwkSet = new JWKSet(TestJwks.generateRsa().build());
		jwtClientAssertionEncoder = new NimbusJwtEncoder(
				(jwkSelector, securityContext) -> jwkSelector.select(clientJwkSet));
		db = new EmbeddedDatabaseBuilder().generateUniqueName(true)
			.setType(EmbeddedDatabaseType.HSQL)
			.setScriptEncoding("UTF-8")
			.addScript("org/springframework/security/oauth2/server/authorization/oauth2-authorization-schema.sql")
			.addScript(
					"org/springframework/security/oauth2/server/authorization/client/oauth2-registered-client-schema.sql")
			.build();
		authenticationConverter = mock(AuthenticationConverter.class);
		authenticationConvertersConsumer = mock(Consumer.class);
		authenticationProvider = mock(AuthenticationProvider.class);
		authenticationProvidersConsumer = mock(Consumer.class);
		authenticationSuccessHandler = mock(AuthenticationSuccessHandler.class);
		authenticationFailureHandler = mock(AuthenticationFailureHandler.class);
	}

	@BeforeEach
	public void setup() throws Exception {
		this.server = new MockWebServer();
		this.server.start();
		this.clientJwkSetUrl = this.server.url("/jwks").toString();
		// @formatter:off
		MockResponse response = new MockResponse()
				.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
				.setBody(clientJwkSet.toString());
		// @formatter:on
		this.server.enqueue(response);
		given(authenticationProvider.supports(OidcClientRegistrationAuthenticationToken.class)).willReturn(true);
	}

	@AfterEach
	public void tearDown() throws Exception {
		this.server.shutdown();
		this.jdbcOperations.update("truncate table oauth2_authorization");
		this.jdbcOperations.update("truncate table oauth2_registered_client");
		reset(authenticationConverter);
		reset(authenticationConvertersConsumer);
		reset(authenticationProvider);
		reset(authenticationProvidersConsumer);
		reset(authenticationSuccessHandler);
		reset(authenticationFailureHandler);
	}

	@AfterAll
	public static void destroy() {
		db.shutdown();
	}

	@Test
	public void requestWhenClientRegistrationRequestAuthorizedThenClientRegistrationResponse() throws Exception {
		this.spring.register(AuthorizationServerConfiguration.class).autowire();

		// @formatter:off
		OidcClientRegistration clientRegistration = OidcClientRegistration.builder()
				.clientName("client-name")
				.redirectUri("https://client.example.com")
				.grantType(AuthorizationGrantType.AUTHORIZATION_CODE.getValue())
				.grantType(AuthorizationGrantType.CLIENT_CREDENTIALS.getValue())
				.scope("scope1")
				.scope("scope2")
				.build();
		// @formatter:on

		OidcClientRegistration clientRegistrationResponse = registerClient(clientRegistration);

		assertThat(clientRegistrationResponse.getClientId()).isNotNull();
		assertThat(clientRegistrationResponse.getClientIdIssuedAt()).isNotNull();
		assertThat(clientRegistrationResponse.getClientSecret()).isNotNull();
		assertThat(clientRegistrationResponse.getClientSecretExpiresAt()).isNull();
		assertThat(clientRegistrationResponse.getClientName()).isEqualTo(clientRegistration.getClientName());
		assertThat(clientRegistrationResponse.getRedirectUris())
			.containsExactlyInAnyOrderElementsOf(clientRegistration.getRedirectUris());
		assertThat(clientRegistrationResponse.getGrantTypes())
			.containsExactlyInAnyOrderElementsOf(clientRegistration.getGrantTypes());
		assertThat(clientRegistrationResponse.getResponseTypes())
			.containsExactly(OAuth2AuthorizationResponseType.CODE.getValue());
		assertThat(clientRegistrationResponse.getScopes())
			.containsExactlyInAnyOrderElementsOf(clientRegistration.getScopes());
		assertThat(clientRegistrationResponse.getTokenEndpointAuthenticationMethod())
			.isEqualTo(ClientAuthenticationMethod.CLIENT_SECRET_BASIC.getValue());
		assertThat(clientRegistrationResponse.getIdTokenSignedResponseAlgorithm())
			.isEqualTo(SignatureAlgorithm.RS256.getName());
		assertThat(clientRegistrationResponse.getRegistrationClientUrl()).isNotNull();
		assertThat(clientRegistrationResponse.getRegistrationAccessToken()).isNotEmpty();
	}

	@Test
	public void requestWhenClientConfigurationRequestAuthorizedThenClientRegistrationResponse() throws Exception {
		this.spring.register(AuthorizationServerConfiguration.class).autowire();

		// @formatter:off
		OidcClientRegistration clientRegistration = OidcClientRegistration.builder()
				.clientName("client-name")
				.redirectUri("https://client.example.com")
				.grantType(AuthorizationGrantType.AUTHORIZATION_CODE.getValue())
				.grantType(AuthorizationGrantType.CLIENT_CREDENTIALS.getValue())
				.scope("scope1")
				.scope("scope2")
				.build();
		// @formatter:on

		OidcClientRegistration clientRegistrationResponse = registerClient(clientRegistration);

		HttpHeaders httpHeaders = new HttpHeaders();
		httpHeaders.setBearerAuth(clientRegistrationResponse.getRegistrationAccessToken());

		MvcResult mvcResult = this.mvc
			.perform(get(clientRegistrationResponse.getRegistrationClientUrl().toURI()).headers(httpHeaders))
			.andExpect(status().isOk())
			.andExpect(header().string(HttpHeaders.CACHE_CONTROL, containsString("no-store")))
			.andExpect(header().string(HttpHeaders.PRAGMA, containsString("no-cache")))
			.andReturn();

		OidcClientRegistration clientConfigurationResponse = readClientRegistrationResponse(mvcResult.getResponse());

		assertThat(clientConfigurationResponse.getClientId()).isEqualTo(clientRegistrationResponse.getClientId());
		assertThat(clientConfigurationResponse.getClientIdIssuedAt())
			.isEqualTo(clientRegistrationResponse.getClientIdIssuedAt());
		assertThat(clientConfigurationResponse.getClientSecret()).isNotNull();
		assertThat(clientConfigurationResponse.getClientSecretExpiresAt())
			.isEqualTo(clientRegistrationResponse.getClientSecretExpiresAt());
		assertThat(clientConfigurationResponse.getClientName()).isEqualTo(clientRegistrationResponse.getClientName());
		assertThat(clientConfigurationResponse.getRedirectUris())
			.containsExactlyInAnyOrderElementsOf(clientRegistrationResponse.getRedirectUris());
		assertThat(clientConfigurationResponse.getGrantTypes())
			.containsExactlyInAnyOrderElementsOf(clientRegistrationResponse.getGrantTypes());
		assertThat(clientConfigurationResponse.getResponseTypes())
			.containsExactlyInAnyOrderElementsOf(clientRegistrationResponse.getResponseTypes());
		assertThat(clientConfigurationResponse.getScopes())
			.containsExactlyInAnyOrderElementsOf(clientRegistrationResponse.getScopes());
		assertThat(clientConfigurationResponse.getTokenEndpointAuthenticationMethod())
			.isEqualTo(clientRegistrationResponse.getTokenEndpointAuthenticationMethod());
		assertThat(clientConfigurationResponse.getIdTokenSignedResponseAlgorithm())
			.isEqualTo(clientRegistrationResponse.getIdTokenSignedResponseAlgorithm());
		assertThat(clientConfigurationResponse.getRegistrationClientUrl())
			.isEqualTo(clientRegistrationResponse.getRegistrationClientUrl());
		assertThat(clientConfigurationResponse.getRegistrationAccessToken()).isNull();
	}

	@Test
	public void requestWhenClientRegistrationEndpointCustomizedThenUsed() throws Exception {
		this.spring.register(CustomClientRegistrationConfiguration.class).autowire();

		// @formatter:off
		OidcClientRegistration clientRegistration = OidcClientRegistration.builder()
				.clientName("client-name")
				.redirectUri("https://client.example.com")
				.grantType(AuthorizationGrantType.AUTHORIZATION_CODE.getValue())
				.grantType(AuthorizationGrantType.CLIENT_CREDENTIALS.getValue())
				.scope("scope1")
				.scope("scope2")
				.build();
		// @formatter:on

		willAnswer((invocation) -> {
			HttpServletResponse response = invocation.getArgument(1, HttpServletResponse.class);
			ServletServerHttpResponse httpResponse = new ServletServerHttpResponse(response);
			httpResponse.setStatusCode(HttpStatus.CREATED);
			new OidcClientRegistrationHttpMessageConverter().write(clientRegistration, null, httpResponse);
			return null;
		}).given(authenticationSuccessHandler).onAuthenticationSuccess(any(), any(), any());

		registerClient(clientRegistration);

		verify(authenticationConverter).convert(any());
		ArgumentCaptor<List<AuthenticationConverter>> authenticationConvertersCaptor = ArgumentCaptor
			.forClass(List.class);
		verify(authenticationConvertersConsumer).accept(authenticationConvertersCaptor.capture());
		List<AuthenticationConverter> authenticationConverters = authenticationConvertersCaptor.getValue();
		assertThat(authenticationConverters).hasSize(2)
			.allMatch((converter) -> converter == authenticationConverter
					|| converter instanceof OidcClientRegistrationAuthenticationConverter);

		verify(authenticationProvider).authenticate(any());
		ArgumentCaptor<List<AuthenticationProvider>> authenticationProvidersCaptor = ArgumentCaptor
			.forClass(List.class);
		verify(authenticationProvidersConsumer).accept(authenticationProvidersCaptor.capture());
		List<AuthenticationProvider> authenticationProviders = authenticationProvidersCaptor.getValue();
		assertThat(authenticationProviders).hasSize(3)
			.allMatch((provider) -> provider == authenticationProvider
					|| provider instanceof OidcClientRegistrationAuthenticationProvider
					|| provider instanceof OidcClientConfigurationAuthenticationProvider);

		verify(authenticationSuccessHandler).onAuthenticationSuccess(any(), any(), any());
		verifyNoInteractions(authenticationFailureHandler);
	}

	@Test
	public void requestWhenClientRegistrationEndpointCustomizedWithAuthenticationFailureHandlerThenUsed()
			throws Exception {
		this.spring.register(CustomClientRegistrationConfiguration.class).autowire();

		given(authenticationProvider.authenticate(any())).willThrow(new OAuth2AuthenticationException("error"));

		this.mvc.perform(get(ISSUER.concat(DEFAULT_OIDC_CLIENT_REGISTRATION_ENDPOINT_URI))
			.param(OAuth2ParameterNames.CLIENT_ID, "invalid")
			.with(jwt()));

		verify(authenticationFailureHandler).onAuthenticationFailure(any(), any(), any());
		verifyNoInteractions(authenticationSuccessHandler);
	}

	// gh-1056
	@Test
	public void requestWhenClientRegistersWithSecretThenClientAuthenticationSuccess() throws Exception {
		this.spring.register(AuthorizationServerConfiguration.class).autowire();

		// @formatter:off
		OidcClientRegistration clientRegistration = OidcClientRegistration.builder()
				.clientName("client-name")
				.redirectUri("https://client.example.com")
				.grantType(AuthorizationGrantType.AUTHORIZATION_CODE.getValue())
				.grantType(AuthorizationGrantType.CLIENT_CREDENTIALS.getValue())
				.scope("scope1")
				.scope("scope2")
				.build();
		// @formatter:on

		OidcClientRegistration clientRegistrationResponse = registerClient(clientRegistration);

		this.mvc
			.perform(post(ISSUER.concat(DEFAULT_TOKEN_ENDPOINT_URI))
				.param(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.CLIENT_CREDENTIALS.getValue())
				.param(OAuth2ParameterNames.SCOPE, "scope1")
				.with(httpBasic(clientRegistrationResponse.getClientId(),
						clientRegistrationResponse.getClientSecret())))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.access_token").isNotEmpty())
			.andExpect(jsonPath("$.scope").value("scope1"))
			.andReturn();
	}

	// gh-1344
	@Test
	public void requestWhenClientRegistersWithClientSecretJwtThenClientAuthenticationSuccess() throws Exception {
		this.spring.register(AuthorizationServerConfiguration.class).autowire();

		// @formatter:off
		OidcClientRegistration clientRegistration = OidcClientRegistration.builder()
				.clientName("client-name")
				.redirectUri("https://client.example.com")
				.grantType(AuthorizationGrantType.AUTHORIZATION_CODE.getValue())
				.grantType(AuthorizationGrantType.CLIENT_CREDENTIALS.getValue())
				.tokenEndpointAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_JWT.getValue())
				.scope("scope1")
				.scope("scope2")
				.build();
		// @formatter:on

		OidcClientRegistration clientRegistrationResponse = registerClient(clientRegistration);

		JwsHeader jwsHeader = JwsHeader.with(MacAlgorithm.HS256).build();

		Instant issuedAt = Instant.now();
		Instant expiresAt = issuedAt.plus(1, ChronoUnit.HOURS);
		JwtClaimsSet jwtClaimsSet = JwtClaimsSet.builder()
			.issuer(clientRegistrationResponse.getClientId())
			.subject(clientRegistrationResponse.getClientId())
			.audience(Collections.singletonList(asUrl(ISSUER, this.authorizationServerSettings.getTokenEndpoint())))
			.issuedAt(issuedAt)
			.expiresAt(expiresAt)
			.build();

		JWKSet jwkSet = new JWKSet(
				TestJwks.jwk(new SecretKeySpec(clientRegistrationResponse.getClientSecret().getBytes(), "HS256"))
					.build());
		JwtEncoder jwtClientAssertionEncoder = new NimbusJwtEncoder(
				(jwkSelector, securityContext) -> jwkSelector.select(jwkSet));

		Jwt jwtAssertion = jwtClientAssertionEncoder.encode(JwtEncoderParameters.from(jwsHeader, jwtClaimsSet));

		this.mvc
			.perform(post(ISSUER.concat(DEFAULT_TOKEN_ENDPOINT_URI))
				.param(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.CLIENT_CREDENTIALS.getValue())
				.param(OAuth2ParameterNames.SCOPE, "scope1")
				.param(OAuth2ParameterNames.CLIENT_ASSERTION_TYPE,
						"urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
				.param(OAuth2ParameterNames.CLIENT_ASSERTION, jwtAssertion.getTokenValue())
				.param(OAuth2ParameterNames.CLIENT_ID, clientRegistrationResponse.getClientId()))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.access_token").isNotEmpty())
			.andExpect(jsonPath("$.scope").value("scope1"));
	}

	@Test
	public void requestWhenClientRegistersWithCustomMetadataThenSavedToRegisteredClient() throws Exception {
		this.spring.register(CustomClientMetadataConfiguration.class).autowire();

		// @formatter:off
		OidcClientRegistration clientRegistration = OidcClientRegistration.builder()
				.clientName("client-name")
				.redirectUri("https://client.example.com")
				.grantType(AuthorizationGrantType.AUTHORIZATION_CODE.getValue())
				.grantType(AuthorizationGrantType.CLIENT_CREDENTIALS.getValue())
				.scope("scope1")
				.scope("scope2")
				.claim("custom-metadata-name-1", "value-1")
				.claim("custom-metadata-name-2", "value-2")
				.claim("non-registered-custom-metadata", "value-3")
				.build();
		// @formatter:on

		OidcClientRegistration clientRegistrationResponse = registerClient(clientRegistration);

		RegisteredClient registeredClient = this.registeredClientRepository
			.findByClientId(clientRegistrationResponse.getClientId());

		assertThat(clientRegistrationResponse.<String>getClaim("custom-metadata-name-1")).isEqualTo("value-1");
		assertThat(clientRegistrationResponse.<String>getClaim("custom-metadata-name-2")).isEqualTo("value-2");
		assertThat(clientRegistrationResponse.<String>getClaim("non-registered-custom-metadata")).isNull();

		assertThat(registeredClient.getClientSettings().<String>getSetting("custom-metadata-name-1"))
			.isEqualTo("value-1");
		assertThat(registeredClient.getClientSettings().<String>getSetting("custom-metadata-name-2"))
			.isEqualTo("value-2");
		assertThat(registeredClient.getClientSettings().<String>getSetting("non-registered-custom-metadata")).isNull();
	}

	// gh-2111
	@Test
	public void requestWhenClientRegistersWithSecretExpirationThenClientRegistrationResponse() throws Exception {
		this.spring.register(ClientSecretExpirationConfiguration.class).autowire();

		// @formatter:off
		OidcClientRegistration clientRegistration = OidcClientRegistration.builder()
				.clientName("client-name")
				.redirectUri("https://client.example.com")
				.grantType(AuthorizationGrantType.AUTHORIZATION_CODE.getValue())
				.grantType(AuthorizationGrantType.CLIENT_CREDENTIALS.getValue())
				.scope("scope1")
				.scope("scope2")
				.build();
		// @formatter:on

		OidcClientRegistration clientRegistrationResponse = registerClient(clientRegistration);

		Instant expectedSecretExpiryDate = Instant.now().plus(Duration.ofHours(24));
		TemporalUnitWithinOffset allowedDelta = new TemporalUnitWithinOffset(1, ChronoUnit.MINUTES);

		// Returned response contains expiration date
		assertThat(clientRegistrationResponse.getClientSecretExpiresAt()).isNotNull()
			.isCloseTo(expectedSecretExpiryDate, allowedDelta);

		RegisteredClient registeredClient = this.registeredClientRepository
			.findByClientId(clientRegistrationResponse.getClientId());

		// Persisted RegisteredClient contains expiration date
		assertThat(registeredClient).isNotNull();
		assertThat(registeredClient.getClientSecretExpiresAt()).isNotNull()
			.isCloseTo(expectedSecretExpiryDate, allowedDelta);
	}

	private OidcClientRegistration registerClient(OidcClientRegistration clientRegistration) throws Exception {
		// ***** (1) Obtain the "initial" access token used for registering the client

		String clientRegistrationScope = "client.create";
		// @formatter:off
		RegisteredClient clientRegistrar = RegisteredClient.withId("client-registrar-1")
				.clientId("client-registrar-1")
				.clientAuthenticationMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT)
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.scope(clientRegistrationScope)
				.clientSettings(
						ClientSettings.builder()
								.jwkSetUrl(this.clientJwkSetUrl)
								.tokenEndpointAuthenticationSigningAlgorithm(SignatureAlgorithm.RS256)
								.build()
				)
				.build();
		// @formatter:on
		this.registeredClientRepository.save(clientRegistrar);

		// @formatter:off
		JwsHeader jwsHeader = JwsHeader.with(SignatureAlgorithm.RS256)
				.build();
		JwtClaimsSet jwtClaimsSet = jwtClientAssertionClaims(clientRegistrar)
				.build();
		// @formatter:on
		Jwt jwtAssertion = jwtClientAssertionEncoder.encode(JwtEncoderParameters.from(jwsHeader, jwtClaimsSet));

		MvcResult mvcResult = this.mvc
			.perform(post(ISSUER.concat(DEFAULT_TOKEN_ENDPOINT_URI))
				.param(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.CLIENT_CREDENTIALS.getValue())
				.param(OAuth2ParameterNames.SCOPE, clientRegistrationScope)
				.param(OAuth2ParameterNames.CLIENT_ASSERTION_TYPE,
						"urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
				.param(OAuth2ParameterNames.CLIENT_ASSERTION, jwtAssertion.getTokenValue())
				.param(OAuth2ParameterNames.CLIENT_ID, clientRegistrar.getClientId()))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.access_token").isNotEmpty())
			.andExpect(jsonPath("$.scope").value(clientRegistrationScope))
			.andReturn();

		OAuth2AccessToken accessToken = readAccessTokenResponse(mvcResult.getResponse()).getAccessToken();

		// ***** (2) Register the client

		HttpHeaders httpHeaders = new HttpHeaders();
		httpHeaders.setBearerAuth(accessToken.getTokenValue());

		// Register the client
		mvcResult = this.mvc
			.perform(post(ISSUER.concat(DEFAULT_OIDC_CLIENT_REGISTRATION_ENDPOINT_URI)).headers(httpHeaders)
				.contentType(MediaType.APPLICATION_JSON)
				.content(getClientRegistrationRequestContent(clientRegistration)))
			.andExpect(status().isCreated())
			.andExpect(header().string(HttpHeaders.CACHE_CONTROL, containsString("no-store")))
			.andExpect(header().string(HttpHeaders.PRAGMA, containsString("no-cache")))
			.andReturn();

		return readClientRegistrationResponse(mvcResult.getResponse());
	}

	private JwtClaimsSet.Builder jwtClientAssertionClaims(RegisteredClient registeredClient) {
		Instant issuedAt = Instant.now();
		Instant expiresAt = issuedAt.plus(1, ChronoUnit.HOURS);
		return JwtClaimsSet.builder()
			.issuer(registeredClient.getClientId())
			.subject(registeredClient.getClientId())
			.audience(Collections.singletonList(asUrl(ISSUER, this.authorizationServerSettings.getTokenEndpoint())))
			.issuedAt(issuedAt)
			.expiresAt(expiresAt);
	}

	private static String asUrl(String uri, String path) {
		return UriComponentsBuilder.fromUriString(uri).path(path).build().toUriString();
	}

	private static OAuth2AccessTokenResponse readAccessTokenResponse(MockHttpServletResponse response)
			throws Exception {
		MockClientHttpResponse httpResponse = new MockClientHttpResponse(response.getContentAsByteArray(),
				HttpStatus.valueOf(response.getStatus()));
		return accessTokenHttpResponseConverter.read(OAuth2AccessTokenResponse.class, httpResponse);
	}

	private static byte[] getClientRegistrationRequestContent(OidcClientRegistration clientRegistration)
			throws Exception {
		MockHttpOutputMessage httpRequest = new MockHttpOutputMessage();
		clientRegistrationHttpMessageConverter.write(clientRegistration, null, httpRequest);
		return httpRequest.getBodyAsBytes();
	}

	private static OidcClientRegistration readClientRegistrationResponse(MockHttpServletResponse response)
			throws Exception {
		MockClientHttpResponse httpResponse = new MockClientHttpResponse(response.getContentAsByteArray(),
				HttpStatus.valueOf(response.getStatus()));
		return clientRegistrationHttpMessageConverter.read(OidcClientRegistration.class, httpResponse);
	}

	@EnableWebSecurity
	@Configuration(proxyBeanMethods = false)
	static class CustomClientRegistrationConfiguration extends AuthorizationServerConfiguration {

		// @formatter:off
		@Bean
		@Override
		public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
			http
					.oauth2AuthorizationServer((authorizationServer) ->
							authorizationServer
									.oidc((oidc) ->
											oidc
													.clientRegistrationEndpoint((clientRegistration) ->
															clientRegistration
																	.clientRegistrationRequestConverter(authenticationConverter)
																	.clientRegistrationRequestConverters(authenticationConvertersConsumer)
																	.authenticationProvider(authenticationProvider)
																	.authenticationProviders(authenticationProvidersConsumer)
																	.clientRegistrationResponseHandler(authenticationSuccessHandler)
																	.errorResponseHandler(authenticationFailureHandler)
													)
									)
					)
					.authorizeHttpRequests((authorize) ->
							authorize.anyRequest().authenticated()
					);
			return http.build();
		}
		// @formatter:on

	}

	@EnableWebSecurity
	@Configuration(proxyBeanMethods = false)
	static class CustomClientMetadataConfiguration extends AuthorizationServerConfiguration {

		// @formatter:off
		@Bean
		@Override
		public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
			http
					.oauth2AuthorizationServer((authorizationServer) ->
							authorizationServer
									.oidc((oidc) ->
											oidc
													.clientRegistrationEndpoint((clientRegistration) ->
															clientRegistration
																	.authenticationProviders(configureClientRegistrationConverters())
													)
									)
					)
					.authorizeHttpRequests((authorize) ->
							authorize.anyRequest().authenticated()
					);
			return http.build();
		}
		// @formatter:on

		private Consumer<List<AuthenticationProvider>> configureClientRegistrationConverters() {
			// @formatter:off
			return (authenticationProviders) ->
					authenticationProviders.forEach((authenticationProvider) -> {
						List<String> supportedCustomClientMetadata = List.of("custom-metadata-name-1", "custom-metadata-name-2");
						if (authenticationProvider instanceof OidcClientRegistrationAuthenticationProvider provider) {
							provider.setRegisteredClientConverter(new CustomRegisteredClientConverter(supportedCustomClientMetadata));
							provider.setClientRegistrationConverter(new CustomClientRegistrationConverter(supportedCustomClientMetadata));
						}
					});
			// @formatter:on
		}

	}

	@EnableWebSecurity
	@Configuration(proxyBeanMethods = false)
	static class ClientSecretExpirationConfiguration extends AuthorizationServerConfiguration {

		// @formatter:off
		@Bean
		@Override
		public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
			http
					.oauth2AuthorizationServer((authorizationServer) ->
							authorizationServer
									.oidc((oidc) ->
											oidc
													.clientRegistrationEndpoint((clientRegistration) ->
															clientRegistration
																	.authenticationProviders(configureClientRegistrationConverters())
													)
									)
					)
					.authorizeHttpRequests((authorize) ->
							authorize.anyRequest().authenticated()
					);
			return http.build();
		}
		// @formatter:on

		private Consumer<List<AuthenticationProvider>> configureClientRegistrationConverters() {
			// @formatter:off
			return (authenticationProviders) ->
					authenticationProviders.forEach((authenticationProvider) -> {
						if (authenticationProvider instanceof OidcClientRegistrationAuthenticationProvider provider) {
							provider.setRegisteredClientConverter(new ClientSecretExpirationRegisteredClientConverter());
						}
					});
			// @formatter:on
		}

	}

	@EnableWebSecurity
	@Configuration(proxyBeanMethods = false)
	static class AuthorizationServerConfiguration {

		// @formatter:off
		@Bean
		SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
			http
					.oauth2AuthorizationServer((authorizationServer) ->
							authorizationServer
									.oidc((oidc) ->
											oidc
													.clientRegistrationEndpoint(Customizer.withDefaults())
									)
					)
					.authorizeHttpRequests((authorize) ->
							authorize.anyRequest().authenticated()
					);
			return http.build();
		}
		// @formatter:on

		@Bean
		@SuppressWarnings("removal")
		RegisteredClientRepository registeredClientRepository(JdbcOperations jdbcOperations) {
			RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
			RegisteredClientParametersMapper registeredClientParametersMapper = new RegisteredClientParametersMapper();
			JdbcRegisteredClientRepository registeredClientRepository = new JdbcRegisteredClientRepository(
					jdbcOperations);
			registeredClientRepository.setRegisteredClientParametersMapper(registeredClientParametersMapper);
			registeredClientRepository.save(registeredClient);
			return registeredClientRepository;
		}

		@Bean
		OAuth2AuthorizationService authorizationService(JdbcOperations jdbcOperations,
				RegisteredClientRepository registeredClientRepository) {
			return new JdbcOAuth2AuthorizationService(jdbcOperations, registeredClientRepository);
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
		JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
			return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
		}

		@Bean
		AuthorizationServerSettings authorizationServerSettings() {
			return AuthorizationServerSettings.builder().multipleIssuersAllowed(true).build();
		}

		@Bean
		PasswordEncoder passwordEncoder() {
			return PasswordEncoderFactories.createDelegatingPasswordEncoder();
		}

	}

	private static final class CustomRegisteredClientConverter
			implements Converter<OidcClientRegistration, RegisteredClient> {

		private final OidcClientRegistrationRegisteredClientConverter delegate = new OidcClientRegistrationRegisteredClientConverter();

		private final List<String> supportedCustomClientMetadata;

		private CustomRegisteredClientConverter(List<String> supportedCustomClientMetadata) {
			this.supportedCustomClientMetadata = supportedCustomClientMetadata;
		}

		@Override
		public RegisteredClient convert(OidcClientRegistration clientRegistration) {
			RegisteredClient registeredClient = this.delegate.convert(clientRegistration);

			ClientSettings.Builder clientSettingsBuilder = ClientSettings
				.withSettings(registeredClient.getClientSettings().getSettings());
			if (!CollectionUtils.isEmpty(this.supportedCustomClientMetadata)) {
				clientRegistration.getClaims().forEach((claim, value) -> {
					if (this.supportedCustomClientMetadata.contains(claim)) {
						clientSettingsBuilder.setting(claim, value);
					}
				});
			}

			return RegisteredClient.from(registeredClient).clientSettings(clientSettingsBuilder.build()).build();
		}

	}

	private static final class CustomClientRegistrationConverter
			implements Converter<RegisteredClient, OidcClientRegistration> {

		private final RegisteredClientOidcClientRegistrationConverter delegate = new RegisteredClientOidcClientRegistrationConverter();

		private final List<String> supportedCustomClientMetadata;

		private CustomClientRegistrationConverter(List<String> supportedCustomClientMetadata) {
			this.supportedCustomClientMetadata = supportedCustomClientMetadata;
		}

		@Override
		public OidcClientRegistration convert(RegisteredClient registeredClient) {
			OidcClientRegistration clientRegistration = this.delegate.convert(registeredClient);

			Map<String, Object> clientMetadata = new HashMap<>(clientRegistration.getClaims());
			if (!CollectionUtils.isEmpty(this.supportedCustomClientMetadata)) {
				Map<String, Object> clientSettings = registeredClient.getClientSettings().getSettings();
				this.supportedCustomClientMetadata.forEach((customClaim) -> {
					if (clientSettings.containsKey(customClaim)) {
						clientMetadata.put(customClaim, clientSettings.get(customClaim));
					}
				});
			}

			return OidcClientRegistration.withClaims(clientMetadata).build();
		}

	}

	/**
	 * This customization adds client secret expiration time by setting
	 * {@code RegisteredClient.clientSecretExpiresAt} during
	 * {@code OidcClientRegistration} -> {@code RegisteredClient} conversion
	 */
	private static final class ClientSecretExpirationRegisteredClientConverter
			implements Converter<OidcClientRegistration, RegisteredClient> {

		private static final OidcClientRegistrationRegisteredClientConverter delegate = new OidcClientRegistrationRegisteredClientConverter();

		@Override
		public RegisteredClient convert(OidcClientRegistration clientRegistration) {
			RegisteredClient registeredClient = delegate.convert(clientRegistration);
			RegisteredClient.Builder registeredClientBuilder = RegisteredClient.from(registeredClient);

			Instant clientSecretExpiresAt = Instant.now().plus(Duration.ofHours(24));
			registeredClientBuilder.clientSecretExpiresAt(clientSecretExpiresAt);

			return registeredClientBuilder.build();
		}

	}

}
