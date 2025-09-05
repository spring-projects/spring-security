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

package org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers;

import java.security.Principal;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
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
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
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
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.TestOAuth2Authorizations;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenExchangeCompositeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.test.SpringTestContext;
import org.springframework.security.oauth2.server.authorization.test.SpringTestContextExtension;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimNames;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Integration tests for OAuth 2.0 Token Exchange Grant.
 *
 * @author Steve Riesenberg
 */
@ExtendWith(SpringTestContextExtension.class)
public class OAuth2TokenExchangeGrantTests {

	private static final String DEFAULT_TOKEN_ENDPOINT_URI = "/oauth2/token";

	private static final String RESOURCE = "https://mydomain.com/resource";

	private static final String AUDIENCE = "audience";

	private static final String SUBJECT_TOKEN = "EfYu_0jEL";

	private static final String ACTOR_TOKEN = "JlNE_xR1f";

	private static final String ACCESS_TOKEN_TYPE_VALUE = "urn:ietf:params:oauth:token-type:access_token";

	private static final String JWT_TOKEN_TYPE_VALUE = "urn:ietf:params:oauth:token-type:jwt";

	private static NimbusJwtEncoder dPoPProofJwtEncoder;

	public final SpringTestContext spring = new SpringTestContext();

	private final HttpMessageConverter<OAuth2AccessTokenResponse> accessTokenResponseHttpMessageConverter = new OAuth2AccessTokenResponseHttpMessageConverter();

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
		AuthorizationServerConfiguration.JWK_SOURCE = (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
		JWKSet clientJwkSet = new JWKSet(TestJwks.DEFAULT_EC_JWK);
		JWKSource<SecurityContext> clientJwkSource = (jwkSelector, securityContext) -> jwkSelector.select(clientJwkSet);
		dPoPProofJwtEncoder = new NimbusJwtEncoder(clientJwkSource);
		// @formatter:off
		AuthorizationServerConfiguration.DB = new EmbeddedDatabaseBuilder()
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
		AuthorizationServerConfiguration.DB.shutdown();
	}

	@Test
	public void requestWhenAccessTokenRequestNotAuthenticatedThenUnauthorized() throws Exception {
		this.spring.register(AuthorizationServerConfiguration.class).autowire();

		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
			.authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
			.build();
		this.registeredClientRepository.save(registeredClient);

		MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
		parameters.set(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.TOKEN_EXCHANGE.getValue());
		parameters.set(OAuth2ParameterNames.CLIENT_ID, registeredClient.getClientId());
		parameters.set(OAuth2ParameterNames.SCOPE,
				StringUtils.collectionToDelimitedString(registeredClient.getScopes(), " "));

		// @formatter:off
		this.mvc.perform(post(DEFAULT_TOKEN_ENDPOINT_URI).params(parameters))
				.andExpect(status().isUnauthorized());
		// @formatter:on
	}

	@Test
	public void requestWhenAccessTokenRequestValidAndNoActorTokenThenReturnAccessTokenResponseForImpersonation()
			throws Exception {
		this.spring.register(AuthorizationServerConfiguration.class).autowire();

		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
			.authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
			.build();
		this.registeredClientRepository.save(registeredClient);

		UsernamePasswordAuthenticationToken userPrincipal = createUserPrincipal("user");
		OAuth2Authorization subjectAuthorization = TestOAuth2Authorizations.authorization(registeredClient)
			.attribute(Principal.class.getName(), userPrincipal)
			.build();
		this.authorizationService.save(subjectAuthorization);

		MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
		parameters.set(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.TOKEN_EXCHANGE.getValue());
		parameters.set(OAuth2ParameterNames.CLIENT_ID, registeredClient.getClientId());
		parameters.set(OAuth2ParameterNames.REQUESTED_TOKEN_TYPE, JWT_TOKEN_TYPE_VALUE);
		parameters.set(OAuth2ParameterNames.SUBJECT_TOKEN,
				subjectAuthorization.getAccessToken().getToken().getTokenValue());
		parameters.set(OAuth2ParameterNames.SUBJECT_TOKEN_TYPE, JWT_TOKEN_TYPE_VALUE);
		parameters.set(OAuth2ParameterNames.RESOURCE, RESOURCE);
		parameters.set(OAuth2ParameterNames.AUDIENCE, AUDIENCE);
		parameters.set(OAuth2ParameterNames.SCOPE,
				StringUtils.collectionToDelimitedString(registeredClient.getScopes(), " "));

		// @formatter:off
		MvcResult mvcResult = this.mvc.perform(post(DEFAULT_TOKEN_ENDPOINT_URI)
				.params(parameters)
				.headers(withClientAuth(registeredClient)))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.access_token").isNotEmpty())
				.andExpect(jsonPath("$.refresh_token").doesNotExist())
				.andExpect(jsonPath("$.expires_in").isNumber())
				.andExpect(jsonPath("$.scope").isNotEmpty())
				.andExpect(jsonPath("$.token_type").isNotEmpty())
				.andExpect(jsonPath("$.issued_token_type").isNotEmpty())
				.andReturn();
		// @formatter:on

		MockHttpServletResponse servletResponse = mvcResult.getResponse();
		MockClientHttpResponse httpResponse = new MockClientHttpResponse(servletResponse.getContentAsByteArray(),
				HttpStatus.OK);
		OAuth2AccessTokenResponse accessTokenResponse = this.accessTokenResponseHttpMessageConverter
			.read(OAuth2AccessTokenResponse.class, httpResponse);

		String accessToken = accessTokenResponse.getAccessToken().getTokenValue();
		OAuth2Authorization authorization = this.authorizationService.findByToken(accessToken,
				OAuth2TokenType.ACCESS_TOKEN);
		assertThat(authorization).isNotNull();
		assertThat(authorization.getAccessToken()).isNotNull();
		assertThat(authorization.getAccessToken().getClaims()).isNotNull();
		// We do not populate claims (e.g. `aud`) based on the resource or audience
		// parameters
		assertThat(authorization.getAccessToken().getClaims().get(OAuth2TokenClaimNames.AUD))
			.isEqualTo(List.of(registeredClient.getClientId()));
		assertThat(authorization.getRefreshToken()).isNull();
		assertThat(authorization.<Authentication>getAttribute(Principal.class.getName())).isEqualTo(userPrincipal);
	}

	@Test
	public void requestWhenAccessTokenRequestValidAndActorTokenThenReturnAccessTokenResponseForDelegation()
			throws Exception {
		this.spring.register(AuthorizationServerConfiguration.class).autowire();

		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
			.authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
			.build();
		this.registeredClientRepository.save(registeredClient);

		UsernamePasswordAuthenticationToken userPrincipal = createUserPrincipal("user");
		UsernamePasswordAuthenticationToken adminPrincipal = createUserPrincipal("admin");
		Map<String, Object> actorTokenClaims = new HashMap<>();
		actorTokenClaims.put(OAuth2TokenClaimNames.ISS, "issuer2");
		actorTokenClaims.put(OAuth2TokenClaimNames.SUB, "admin");
		Map<String, Object> subjectTokenClaims = new HashMap<>();
		subjectTokenClaims.put(OAuth2TokenClaimNames.ISS, "issuer1");
		subjectTokenClaims.put(OAuth2TokenClaimNames.SUB, "user");
		subjectTokenClaims.put("may_act", actorTokenClaims);
		OAuth2AccessToken subjectToken = createAccessToken(SUBJECT_TOKEN);
		OAuth2AccessToken actorToken = createAccessToken(ACTOR_TOKEN);
		// @formatter:off
		OAuth2Authorization subjectAuthorization = TestOAuth2Authorizations.authorization(registeredClient, subjectToken, subjectTokenClaims)
				.id(UUID.randomUUID().toString())
				.attribute(Principal.class.getName(), userPrincipal)
				.build();
		OAuth2Authorization actorAuthorization = TestOAuth2Authorizations.authorization(registeredClient, actorToken, actorTokenClaims)
				.id(UUID.randomUUID().toString())
				.attribute(Principal.class.getName(), adminPrincipal)
				.build();
		// @formatter:on
		this.authorizationService.save(subjectAuthorization);
		this.authorizationService.save(actorAuthorization);

		MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
		parameters.set(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.TOKEN_EXCHANGE.getValue());
		parameters.set(OAuth2ParameterNames.CLIENT_ID, registeredClient.getClientId());
		parameters.set(OAuth2ParameterNames.REQUESTED_TOKEN_TYPE, JWT_TOKEN_TYPE_VALUE);
		parameters.set(OAuth2ParameterNames.SUBJECT_TOKEN, SUBJECT_TOKEN);
		parameters.set(OAuth2ParameterNames.SUBJECT_TOKEN_TYPE, JWT_TOKEN_TYPE_VALUE);
		parameters.set(OAuth2ParameterNames.ACTOR_TOKEN, ACTOR_TOKEN);
		parameters.set(OAuth2ParameterNames.ACTOR_TOKEN_TYPE, ACCESS_TOKEN_TYPE_VALUE);
		parameters.set(OAuth2ParameterNames.SCOPE,
				StringUtils.collectionToDelimitedString(registeredClient.getScopes(), " "));

		// @formatter:off
		MvcResult mvcResult = this.mvc.perform(post(DEFAULT_TOKEN_ENDPOINT_URI)
				.params(parameters)
				.headers(withClientAuth(registeredClient)))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.access_token").isNotEmpty())
				.andExpect(jsonPath("$.refresh_token").doesNotExist())
				.andExpect(jsonPath("$.expires_in").isNumber())
				.andExpect(jsonPath("$.scope").isNotEmpty())
				.andExpect(jsonPath("$.token_type").isNotEmpty())
				.andExpect(jsonPath("$.issued_token_type").isNotEmpty())
				.andReturn();
		// @formatter:on

		MockHttpServletResponse servletResponse = mvcResult.getResponse();
		MockClientHttpResponse httpResponse = new MockClientHttpResponse(servletResponse.getContentAsByteArray(),
				HttpStatus.OK);
		OAuth2AccessTokenResponse accessTokenResponse = this.accessTokenResponseHttpMessageConverter
			.read(OAuth2AccessTokenResponse.class, httpResponse);

		String accessToken = accessTokenResponse.getAccessToken().getTokenValue();
		OAuth2Authorization authorization = this.authorizationService.findByToken(accessToken,
				OAuth2TokenType.ACCESS_TOKEN);
		assertThat(authorization).isNotNull();
		assertThat(authorization.getAccessToken()).isNotNull();
		assertThat(authorization.getAccessToken().getClaims()).isNotNull();
		assertThat(authorization.getAccessToken().getClaims().get("act")).isNotNull();
		assertThat(authorization.getRefreshToken()).isNull();
		assertThat(authorization.<Authentication>getAttribute(Principal.class.getName()))
			.isInstanceOf(OAuth2TokenExchangeCompositeAuthenticationToken.class);
	}

	@Test
	public void requestWhenAccessTokenRequestWithDPoPProofThenReturnDPoPBoundAccessToken() throws Exception {
		this.spring.register(AuthorizationServerConfiguration.class).autowire();

		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
			.authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
			.build();
		this.registeredClientRepository.save(registeredClient);

		UsernamePasswordAuthenticationToken userPrincipal = createUserPrincipal("user");
		UsernamePasswordAuthenticationToken adminPrincipal = createUserPrincipal("admin");
		Map<String, Object> actorTokenClaims = new HashMap<>();
		actorTokenClaims.put(OAuth2TokenClaimNames.ISS, "issuer2");
		actorTokenClaims.put(OAuth2TokenClaimNames.SUB, "admin");
		Map<String, Object> subjectTokenClaims = new HashMap<>();
		subjectTokenClaims.put(OAuth2TokenClaimNames.ISS, "issuer1");
		subjectTokenClaims.put(OAuth2TokenClaimNames.SUB, "user");
		subjectTokenClaims.put("may_act", actorTokenClaims);
		OAuth2AccessToken subjectToken = createAccessToken(SUBJECT_TOKEN);
		OAuth2AccessToken actorToken = createAccessToken(ACTOR_TOKEN);
		// @formatter:off
		OAuth2Authorization subjectAuthorization = TestOAuth2Authorizations.authorization(registeredClient, subjectToken, subjectTokenClaims)
				.id(UUID.randomUUID().toString())
				.attribute(Principal.class.getName(), userPrincipal)
				.build();
		OAuth2Authorization actorAuthorization = TestOAuth2Authorizations.authorization(registeredClient, actorToken, actorTokenClaims)
				.id(UUID.randomUUID().toString())
				.attribute(Principal.class.getName(), adminPrincipal)
				.build();
		// @formatter:on
		this.authorizationService.save(subjectAuthorization);
		this.authorizationService.save(actorAuthorization);

		MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
		parameters.set(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.TOKEN_EXCHANGE.getValue());
		parameters.set(OAuth2ParameterNames.CLIENT_ID, registeredClient.getClientId());
		parameters.set(OAuth2ParameterNames.REQUESTED_TOKEN_TYPE, JWT_TOKEN_TYPE_VALUE);
		parameters.set(OAuth2ParameterNames.SUBJECT_TOKEN, SUBJECT_TOKEN);
		parameters.set(OAuth2ParameterNames.SUBJECT_TOKEN_TYPE, JWT_TOKEN_TYPE_VALUE);
		parameters.set(OAuth2ParameterNames.ACTOR_TOKEN, ACTOR_TOKEN);
		parameters.set(OAuth2ParameterNames.ACTOR_TOKEN_TYPE, ACCESS_TOKEN_TYPE_VALUE);
		parameters.set(OAuth2ParameterNames.SCOPE,
				StringUtils.collectionToDelimitedString(registeredClient.getScopes(), " "));

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
	}

	private static OAuth2AccessToken createAccessToken(String tokenValue) {
		Instant issuedAt = Instant.now();
		Instant expiresAt = issuedAt.plusSeconds(300);
		return new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, tokenValue, issuedAt, expiresAt);
	}

	private static UsernamePasswordAuthenticationToken createUserPrincipal(String username) {
		User user = new User(username, "", AuthorityUtils.createAuthorityList("ROLE_USER"));
		return UsernamePasswordAuthenticationToken.authenticated(user, null, user.getAuthorities());
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

	@EnableWebSecurity
	@Import(OAuth2AuthorizationServerConfiguration.class)
	static class AuthorizationServerConfiguration {

		static JWKSource<SecurityContext> JWK_SOURCE;

		static EmbeddedDatabase DB;

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
			return new JdbcTemplate(DB);
		}

		@Bean
		JWKSource<SecurityContext> jwkSource() {
			return JWK_SOURCE;
		}

		@Bean
		PasswordEncoder passwordEncoder() {
			return NoOpPasswordEncoder.getInstance();
		}

	}

}
