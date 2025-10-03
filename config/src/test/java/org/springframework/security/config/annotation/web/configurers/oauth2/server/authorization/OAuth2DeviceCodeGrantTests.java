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

import java.security.Principal;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.function.Function;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabase;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.mock.http.client.MockClientHttpResponse;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2DeviceCode;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.OAuth2UserCode;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2DeviceAuthorizationResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.oauth2.core.http.converter.OAuth2DeviceAuthorizationResponseHttpMessageConverter;
import org.springframework.security.oauth2.jose.TestJwks;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Integration tests for OAuth 2.0 Device Grant.
 *
 * @author Steve Riesenberg
 */
@ExtendWith(SpringTestContextExtension.class)
public class OAuth2DeviceCodeGrantTests {

	private static final String DEFAULT_DEVICE_AUTHORIZATION_ENDPOINT_URI = "/oauth2/device_authorization";

	private static final String DEFAULT_DEVICE_VERIFICATION_ENDPOINT_URI = "/oauth2/device_verification";

	private static final String DEFAULT_TOKEN_ENDPOINT_URI = "/oauth2/token";

	private static final OAuth2TokenType DEVICE_CODE_TOKEN_TYPE = new OAuth2TokenType(OAuth2ParameterNames.DEVICE_CODE);

	private static final String USER_CODE = "ABCD-EFGH";

	private static final String STATE = "123";

	private static final String DEVICE_CODE = "abc-XYZ";

	private static EmbeddedDatabase db;

	private static JWKSource<SecurityContext> jwkSource;

	private static NimbusJwtEncoder dPoPProofJwtEncoder;

	private static final HttpMessageConverter<OAuth2DeviceAuthorizationResponse> deviceAuthorizationResponseHttpMessageConverter = new OAuth2DeviceAuthorizationResponseHttpMessageConverter();

	private static final HttpMessageConverter<OAuth2AccessTokenResponse> accessTokenResponseHttpMessageConverter = new OAuth2AccessTokenResponseHttpMessageConverter();

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
	private OAuth2AuthorizationConsentService authorizationConsentService;

	@BeforeAll
	public static void init() {
		JWKSet jwkSet = new JWKSet(TestJwks.DEFAULT_RSA_JWK);
		jwkSource = (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
		JWKSet clientJwkSet = new JWKSet(TestJwks.DEFAULT_EC_JWK);
		JWKSource<SecurityContext> clientJwkSource = (jwkSelector, securityContext) -> jwkSelector.select(clientJwkSet);
		dPoPProofJwtEncoder = new NimbusJwtEncoder(clientJwkSource);
		// @formatter:off
		db = new EmbeddedDatabaseBuilder()
				.generateUniqueName(true)
				.setType(EmbeddedDatabaseType.HSQL)
				.setScriptEncoding("UTF-8")
				.addScript("org/springframework/security/oauth2/server/authorization/oauth2-authorization-schema.sql")
				.addScript("org/springframework/security/oauth2/server/authorization/oauth2-authorization-consent-schema.sql")
				.addScript("org/springframework/security/oauth2/server/authorization/client/oauth2-registered-client-schema.sql")
				.build();
		// @formatter:on
	}

	@AfterEach
	public void tearDown() {
		this.jdbcOperations.update("truncate table oauth2_authorization");
		this.jdbcOperations.update("truncate table oauth2_authorization_consent");
		this.jdbcOperations.update("truncate table oauth2_registered_client");
	}

	@AfterAll
	public static void destroy() {
		db.shutdown();
	}

	@Test
	public void requestWhenDeviceAuthorizationRequestNotAuthenticatedThenUnauthorized() throws Exception {
		this.spring.register(AuthorizationServerConfiguration.class).autowire();

		// @formatter:off
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
				.authorizationGrantType(AuthorizationGrantType.DEVICE_CODE)
				.build();
		// @formatter:on
		this.registeredClientRepository.save(registeredClient);

		MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
		parameters.set(OAuth2ParameterNames.CLIENT_ID, registeredClient.getClientId());
		parameters.set(OAuth2ParameterNames.SCOPE,
				StringUtils.collectionToDelimitedString(registeredClient.getScopes(), " "));

		// @formatter:off
		this.mvc.perform(post(DEFAULT_DEVICE_AUTHORIZATION_ENDPOINT_URI)
				.params(parameters))
				.andExpect(status().isUnauthorized());
		// @formatter:on
	}

	@Test
	public void requestWhenRegisteredClientMissingThenUnauthorized() throws Exception {
		this.spring.register(AuthorizationServerConfiguration.class).autowire();

		// @formatter:off
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
				.authorizationGrantType(AuthorizationGrantType.DEVICE_CODE)
				.build();
		// @formatter:on

		MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
		parameters.set(OAuth2ParameterNames.CLIENT_ID, registeredClient.getClientId());
		parameters.set(OAuth2ParameterNames.SCOPE,
				StringUtils.collectionToDelimitedString(registeredClient.getScopes(), " "));

		// @formatter:off
		this.mvc.perform(post(DEFAULT_DEVICE_AUTHORIZATION_ENDPOINT_URI)
				.params(parameters)
				.headers(withClientAuth(registeredClient)))
				.andExpect(status().isUnauthorized());
		// @formatter:on
	}

	@Test
	public void requestWhenDeviceAuthorizationRequestValidThenReturnDeviceAuthorizationResponse() throws Exception {
		this.spring.register(AuthorizationServerConfigurationWithMultipleIssuersAllowed.class).autowire();

		// @formatter:off
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
				.authorizationGrantType(AuthorizationGrantType.DEVICE_CODE)
				.build();
		// @formatter:on
		this.registeredClientRepository.save(registeredClient);

		MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
		parameters.set(OAuth2ParameterNames.CLIENT_ID, registeredClient.getClientId());
		parameters.set(OAuth2ParameterNames.SCOPE,
				StringUtils.collectionToDelimitedString(registeredClient.getScopes(), " "));

		String issuer = "https://example.com:8443/issuer1";

		// @formatter:off
		MvcResult mvcResult = this.mvc.perform(post(issuer.concat(DEFAULT_DEVICE_AUTHORIZATION_ENDPOINT_URI))
				.params(parameters)
				.headers(withClientAuth(registeredClient)))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.device_code").isNotEmpty())
				.andExpect(jsonPath("$.user_code").isNotEmpty())
				.andExpect(jsonPath("$.expires_in").isNumber())
				.andExpect(jsonPath("$.verification_uri").isNotEmpty())
				.andExpect(jsonPath("$.verification_uri_complete").isNotEmpty())
				.andReturn();
		// @formatter:on

		MockHttpServletResponse servletResponse = mvcResult.getResponse();
		MockClientHttpResponse httpResponse = new MockClientHttpResponse(servletResponse.getContentAsByteArray(),
				HttpStatus.OK);
		OAuth2DeviceAuthorizationResponse deviceAuthorizationResponse = deviceAuthorizationResponseHttpMessageConverter
			.read(OAuth2DeviceAuthorizationResponse.class, httpResponse);
		String userCode = deviceAuthorizationResponse.getUserCode().getTokenValue();
		assertThat(userCode).matches("[A-Z]{4}-[A-Z]{4}");
		assertThat(deviceAuthorizationResponse.getVerificationUri())
			.isEqualTo("https://example.com:8443/oauth2/device_verification");
		assertThat(deviceAuthorizationResponse.getVerificationUriComplete())
			.isEqualTo("https://example.com:8443/oauth2/device_verification?user_code=" + userCode);

		String deviceCode = deviceAuthorizationResponse.getDeviceCode().getTokenValue();
		OAuth2Authorization authorization = this.authorizationService.findByToken(deviceCode, DEVICE_CODE_TOKEN_TYPE);
		assertThat(authorization.getToken(OAuth2DeviceCode.class)).isNotNull();
		assertThat(authorization.getToken(OAuth2UserCode.class)).isNotNull();
	}

	@Test
	public void requestWhenDeviceVerificationRequestUnauthenticatedThenUnauthorized() throws Exception {
		this.spring.register(AuthorizationServerConfiguration.class).autowire();

		// @formatter:off
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
				.authorizationGrantType(AuthorizationGrantType.DEVICE_CODE)
				.build();
		// @formatter:on
		this.registeredClientRepository.save(registeredClient);

		Instant issuedAt = Instant.now();
		Instant expiresAt = issuedAt.plusSeconds(300);
		// @formatter:off
		OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(registeredClient)
				.principalName(registeredClient.getClientId())
				.authorizationGrantType(AuthorizationGrantType.DEVICE_CODE)
				.token(new OAuth2DeviceCode(DEVICE_CODE, issuedAt, expiresAt))
				.token(new OAuth2UserCode(USER_CODE, issuedAt, expiresAt))
				.attribute(OAuth2ParameterNames.SCOPE, registeredClient.getScopes())
				.build();
		// @formatter:on
		this.authorizationService.save(authorization);

		MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
		parameters.set(OAuth2ParameterNames.USER_CODE, USER_CODE);

		// @formatter:off
		this.mvc.perform(get(DEFAULT_DEVICE_VERIFICATION_ENDPOINT_URI)
				.queryParams(parameters))
				.andExpect(status().isUnauthorized());
		// @formatter:on
	}

	@Test
	public void requestWhenDeviceVerificationRequestValidThenDisplaysConsentPage() throws Exception {
		this.spring.register(AuthorizationServerConfigurationWithMultipleIssuersAllowed.class).autowire();

		// @formatter:off
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
				.authorizationGrantType(AuthorizationGrantType.DEVICE_CODE)
				.build();
		// @formatter:on
		this.registeredClientRepository.save(registeredClient);

		Instant issuedAt = Instant.now();
		Instant expiresAt = issuedAt.plusSeconds(300);
		// @formatter:off
		OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(registeredClient)
				.principalName(registeredClient.getClientId())
				.authorizationGrantType(AuthorizationGrantType.DEVICE_CODE)
				.token(new OAuth2DeviceCode(DEVICE_CODE, issuedAt, expiresAt))
				.token(new OAuth2UserCode(USER_CODE, issuedAt, expiresAt))
				.attribute(OAuth2ParameterNames.SCOPE, registeredClient.getScopes())
				.build();
		// @formatter:on
		this.authorizationService.save(authorization);

		MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
		parameters.set(OAuth2ParameterNames.USER_CODE, USER_CODE);

		String issuer = "https://example.com:8443/issuer1";

		// @formatter:off
		MvcResult mvcResult = this.mvc.perform(get(issuer.concat(DEFAULT_DEVICE_VERIFICATION_ENDPOINT_URI))
				.queryParams(parameters)
				.with(user("user")))
				.andExpect(status().isOk())
				.andExpect(content().contentTypeCompatibleWith(MediaType.TEXT_HTML))
				.andReturn();
		// @formatter:on

		String responseHtml = mvcResult.getResponse().getContentAsString();
		assertThat(responseHtml).contains("Consent required");

		OAuth2Authorization updatedAuthorization = this.authorizationService.findById(authorization.getId());
		assertThat(updatedAuthorization.getPrincipalName()).isEqualTo("user");
		assertThat(updatedAuthorization).isNotNull();
		// @formatter:off
		assertThat(updatedAuthorization.getToken(OAuth2UserCode.class))
				.extracting(isInvalidated())
				.isEqualTo(false);
		// @formatter:on
	}

	@Test
	public void requestWhenDeviceAuthorizationConsentRequestUnauthenticatedThenBadRequest() throws Exception {
		this.spring.register(AuthorizationServerConfiguration.class).autowire();

		// @formatter:off
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
				.authorizationGrantType(AuthorizationGrantType.DEVICE_CODE)
				.build();
		// @formatter:on
		this.registeredClientRepository.save(registeredClient);

		Instant issuedAt = Instant.now();
		Instant expiresAt = issuedAt.plusSeconds(300);
		// @formatter:off
		OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(registeredClient)
				.principalName("user")
				.authorizationGrantType(AuthorizationGrantType.DEVICE_CODE)
				.token(new OAuth2DeviceCode(DEVICE_CODE, issuedAt, expiresAt))
				.token(new OAuth2UserCode(USER_CODE, issuedAt, expiresAt))
				.attribute(OAuth2ParameterNames.SCOPE, registeredClient.getScopes())
				.attribute(OAuth2ParameterNames.STATE, STATE)
				.build();
		// @formatter:on
		this.authorizationService.save(authorization);

		MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
		parameters.set(OAuth2ParameterNames.USER_CODE, USER_CODE);
		parameters.set(OAuth2ParameterNames.CLIENT_ID, registeredClient.getClientId());
		parameters.set(OAuth2ParameterNames.SCOPE, registeredClient.getScopes().iterator().next());
		parameters.set(OAuth2ParameterNames.STATE, STATE);

		// @formatter:off
		this.mvc.perform(post(DEFAULT_DEVICE_VERIFICATION_ENDPOINT_URI)
				.params(parameters))
				.andExpect(status().isBadRequest());
		// @formatter:on
	}

	@Test
	public void requestWhenDeviceAuthorizationConsentRequestValidThenRedirectsToSuccessPage() throws Exception {
		this.spring.register(AuthorizationServerConfiguration.class).autowire();

		// @formatter:off
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
				.authorizationGrantType(AuthorizationGrantType.DEVICE_CODE)
				.build();
		// @formatter:on
		this.registeredClientRepository.save(registeredClient);

		Instant issuedAt = Instant.now();
		Instant expiresAt = issuedAt.plusSeconds(300);
		// @formatter:off
		OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(registeredClient)
				.principalName("user")
				.authorizationGrantType(AuthorizationGrantType.DEVICE_CODE)
				.token(new OAuth2DeviceCode(DEVICE_CODE, issuedAt, expiresAt))
				.token(new OAuth2UserCode(USER_CODE, issuedAt, expiresAt))
				.attribute(OAuth2ParameterNames.SCOPE, registeredClient.getScopes())
				.attribute(OAuth2ParameterNames.STATE, STATE)
				.build();
		// @formatter:on
		this.authorizationService.save(authorization);

		MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
		parameters.set(OAuth2ParameterNames.USER_CODE, USER_CODE);
		parameters.set(OAuth2ParameterNames.CLIENT_ID, registeredClient.getClientId());
		parameters.set(OAuth2ParameterNames.SCOPE, registeredClient.getScopes().iterator().next());
		parameters.set(OAuth2ParameterNames.STATE, STATE);

		// @formatter:off
		MvcResult mvcResult = this.mvc.perform(post(DEFAULT_DEVICE_VERIFICATION_ENDPOINT_URI)
				.params(parameters)
				.with(user("user")))
				.andExpect(status().is3xxRedirection())
				.andReturn();
		// @formatter:on

		assertThat(mvcResult.getResponse().getHeader(HttpHeaders.LOCATION)).isEqualTo("/?success");

		OAuth2Authorization updatedAuthorization = this.authorizationService.findById(authorization.getId());
		assertThat(updatedAuthorization).isNotNull();
		// @formatter:off
		assertThat(updatedAuthorization.getToken(OAuth2UserCode.class))
				.extracting(isInvalidated())
				.isEqualTo(true);
		// @formatter:on
	}

	@Test
	public void requestWhenAccessTokenRequestUnauthenticatedThenUnauthorized() throws Exception {
		this.spring.register(AuthorizationServerConfiguration.class).autowire();

		// @formatter:off
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
				.authorizationGrantType(AuthorizationGrantType.DEVICE_CODE)
				.build();
		// @formatter:on
		this.registeredClientRepository.save(registeredClient);

		Instant issuedAt = Instant.now();
		Instant expiresAt = issuedAt.plusSeconds(300);
		// @formatter:off
		OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(registeredClient)
				.principalName(registeredClient.getClientId())
				.authorizationGrantType(AuthorizationGrantType.DEVICE_CODE)
				.token(new OAuth2DeviceCode(DEVICE_CODE, issuedAt, expiresAt))
				.token(new OAuth2UserCode(USER_CODE, issuedAt, expiresAt), withInvalidated())
				.authorizedScopes(registeredClient.getScopes())
				.attribute(Principal.class.getName(), new UsernamePasswordAuthenticationToken("user", null))
				.build();
		// @formatter:on
		this.authorizationService.save(authorization);

		MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
		parameters.set(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.DEVICE_CODE.getValue());
		parameters.set(OAuth2ParameterNames.DEVICE_CODE, DEVICE_CODE);

		// @formatter:off
		this.mvc.perform(post(DEFAULT_TOKEN_ENDPOINT_URI)
				.params(parameters))
				.andExpect(status().isUnauthorized());
		// @formatter:on
	}

	@Test
	public void requestWhenAccessTokenRequestValidThenReturnAccessTokenResponse() throws Exception {
		this.spring.register(AuthorizationServerConfiguration.class).autowire();

		// @formatter:off
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
				.authorizationGrantType(AuthorizationGrantType.DEVICE_CODE)
				.build();
		// @formatter:on
		this.registeredClientRepository.save(registeredClient);

		Instant issuedAt = Instant.now();
		Instant expiresAt = issuedAt.plusSeconds(300);
		// @formatter:off
		OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(registeredClient)
				.principalName(registeredClient.getClientId())
				.authorizationGrantType(AuthorizationGrantType.DEVICE_CODE)
				.token(new OAuth2DeviceCode(DEVICE_CODE, issuedAt, expiresAt))
				.token(new OAuth2UserCode(USER_CODE, issuedAt, expiresAt), withInvalidated())
				.authorizedScopes(registeredClient.getScopes())
				.attribute(Principal.class.getName(), new UsernamePasswordAuthenticationToken("user", null))
				.build();
		// @formatter:on
		this.authorizationService.save(authorization);

		// @formatter:off
		OAuth2AuthorizationConsent authorizationConsent =
				OAuth2AuthorizationConsent.withId(registeredClient.getClientId(), "user")
						.scope(registeredClient.getScopes().iterator().next())
						.build();
		// @formatter:on
		this.authorizationConsentService.save(authorizationConsent);

		MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
		parameters.set(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.DEVICE_CODE.getValue());
		parameters.set(OAuth2ParameterNames.DEVICE_CODE, DEVICE_CODE);

		// @formatter:off
		MvcResult mvcResult = this.mvc.perform(post(DEFAULT_TOKEN_ENDPOINT_URI)
				.params(parameters)
				.headers(withClientAuth(registeredClient)))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.access_token").isNotEmpty())
				.andExpect(jsonPath("$.refresh_token").isNotEmpty())
				.andExpect(jsonPath("$.expires_in").isNumber())
				.andExpect(jsonPath("$.scope").isNotEmpty())
				.andExpect(jsonPath("$.token_type").isNotEmpty())
				.andReturn();
		// @formatter:on

		OAuth2Authorization updatedAuthorization = this.authorizationService.findById(authorization.getId());
		assertThat(updatedAuthorization).isNotNull();
		assertThat(updatedAuthorization.getAccessToken()).isNotNull();
		assertThat(updatedAuthorization.getRefreshToken()).isNotNull();
		// @formatter:off
		assertThat(updatedAuthorization.getToken(OAuth2DeviceCode.class))
				.extracting(isInvalidated())
				.isEqualTo(true);
		// @formatter:on

		MockHttpServletResponse servletResponse = mvcResult.getResponse();
		MockClientHttpResponse httpResponse = new MockClientHttpResponse(servletResponse.getContentAsByteArray(),
				HttpStatus.OK);
		OAuth2AccessTokenResponse accessTokenResponse = accessTokenResponseHttpMessageConverter
			.read(OAuth2AccessTokenResponse.class, httpResponse);

		String accessToken = accessTokenResponse.getAccessToken().getTokenValue();
		OAuth2Authorization accessTokenAuthorization = this.authorizationService.findByToken(accessToken,
				OAuth2TokenType.ACCESS_TOKEN);
		assertThat(accessTokenAuthorization).isEqualTo(updatedAuthorization);
	}

	@Test
	public void requestWhenAccessTokenRequestWithDPoPProofThenReturnDPoPBoundAccessToken() throws Exception {
		this.spring.register(AuthorizationServerConfiguration.class).autowire();

		// @formatter:off
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
				.authorizationGrantType(AuthorizationGrantType.DEVICE_CODE)
				.build();
		// @formatter:on
		this.registeredClientRepository.save(registeredClient);

		Instant issuedAt = Instant.now();
		Instant expiresAt = issuedAt.plusSeconds(300);
		// @formatter:off
		OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(registeredClient)
				.principalName(registeredClient.getClientId())
				.authorizationGrantType(AuthorizationGrantType.DEVICE_CODE)
				.token(new OAuth2DeviceCode(DEVICE_CODE, issuedAt, expiresAt))
				.token(new OAuth2UserCode(USER_CODE, issuedAt, expiresAt), withInvalidated())
				.authorizedScopes(registeredClient.getScopes())
				.attribute(Principal.class.getName(), new UsernamePasswordAuthenticationToken("user", null))
				.build();
		// @formatter:on
		this.authorizationService.save(authorization);

		// @formatter:off
		OAuth2AuthorizationConsent authorizationConsent =
				OAuth2AuthorizationConsent.withId(registeredClient.getClientId(), "user")
						.scope(registeredClient.getScopes().iterator().next())
						.build();
		// @formatter:on
		this.authorizationConsentService.save(authorizationConsent);

		MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
		parameters.set(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.DEVICE_CODE.getValue());
		parameters.set(OAuth2ParameterNames.DEVICE_CODE, DEVICE_CODE);

		String tokenEndpointUri = "http://localhost" + DEFAULT_TOKEN_ENDPOINT_URI;
		String dPoPProof = generateDPoPProof(tokenEndpointUri);

		// @formatter:off
		this.mvc.perform(post(DEFAULT_TOKEN_ENDPOINT_URI)
						.params(parameters)
						.headers(withClientAuth(registeredClient))
						.header(OAuth2AccessToken.TokenType.DPOP.getValue(), dPoPProof))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.token_type").value(OAuth2AccessToken.TokenType.DPOP.getValue()));
		// @formatter:on

		authorization = this.authorizationService.findById(authorization.getId());
		assertThat(authorization.getAccessToken().getClaims()).containsKey("cnf");
		@SuppressWarnings("unchecked")
		Map<String, Object> cnfClaims = (Map<String, Object>) authorization.getAccessToken().getClaims().get("cnf");
		assertThat(cnfClaims).containsKey("jkt");
		String jwkThumbprintClaim = (String) cnfClaims.get("jkt");
		assertThat(jwkThumbprintClaim).isEqualTo(TestJwks.DEFAULT_EC_JWK.toPublicJWK().computeThumbprint().toString());
	}

	private static String generateDPoPProof(String tokenEndpointUri) {
		// @formatter:off
		Map<String, Object> publicJwk = TestJwks.DEFAULT_EC_JWK
				.toPublicJWK()
				.toJSONObject();
		JwsHeader jwsHeader = JwsHeader.with(SignatureAlgorithm.ES256)
				.type("dpop+jwt")
				.jwk(publicJwk)
				.build();
		JwtClaimsSet claims = JwtClaimsSet.builder()
				.issuedAt(Instant.now())
				.claim("htm", "POST")
				.claim("htu", tokenEndpointUri)
				.id(UUID.randomUUID().toString())
				.build();
		// @formatter:on
		Jwt jwt = dPoPProofJwtEncoder.encode(JwtEncoderParameters.from(jwsHeader, claims));
		return jwt.getTokenValue();
	}

	private static HttpHeaders withClientAuth(RegisteredClient registeredClient) {
		HttpHeaders headers = new HttpHeaders();
		headers.setBasicAuth(registeredClient.getClientId(), registeredClient.getClientSecret());
		return headers;
	}

	private static Consumer<Map<String, Object>> withInvalidated() {
		return (metadata) -> metadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, true);
	}

	private static Function<OAuth2Authorization.Token<? extends OAuth2Token>, Boolean> isInvalidated() {
		return (token) -> token.getMetadata(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME);
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
									.deviceAuthorizationEndpoint(Customizer.withDefaults())
									.deviceVerificationEndpoint(Customizer.withDefaults())
					)
					.authorizeHttpRequests((authorize) ->
							authorize.anyRequest().authenticated()
					);
			return http.build();
		}
		// @formatter:on

		@Bean
		RegisteredClientRepository registeredClientRepository(JdbcOperations jdbcOperations) {
			return new JdbcRegisteredClientRepository(jdbcOperations);
		}

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
		JdbcOperations jdbcOperations() {
			return new JdbcTemplate(db);
		}

		@Bean
		JWKSource<SecurityContext> jwkSource() {
			return jwkSource;
		}

		@Bean
		AuthorizationServerSettings authorizationServerSettings() {
			return AuthorizationServerSettings.builder().build();
		}

		@Bean
		PasswordEncoder passwordEncoder() {
			return NoOpPasswordEncoder.getInstance();
		}

	}

	@EnableWebSecurity
	@Configuration(proxyBeanMethods = false)
	static class AuthorizationServerConfigurationWithMultipleIssuersAllowed extends AuthorizationServerConfiguration {

		// @formatter:off
		@Bean
		SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
			http
					.oauth2AuthorizationServer((authorizationServer) ->
							authorizationServer
									.deviceAuthorizationEndpoint(Customizer.withDefaults())
									.deviceVerificationEndpoint(Customizer.withDefaults())
					)
					.authorizeHttpRequests((authorize) ->
							authorize.anyRequest().authenticated()
					);
			return http.build();
		}
		// @formatter:on

		@Bean
		AuthorizationServerSettings authorizationServerSettings() {
			return AuthorizationServerSettings.builder().multipleIssuersAllowed(true).build();
		}

	}

}
