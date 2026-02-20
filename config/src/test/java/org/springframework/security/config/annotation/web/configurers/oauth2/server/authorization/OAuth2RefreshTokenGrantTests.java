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
import java.security.MessageDigest;
import java.security.Principal;
import java.security.PublicKey;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

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
import org.springframework.lang.Nullable;
import org.springframework.mock.http.client.MockClientHttpResponse;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.Transient;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.oauth2.jose.TestJwks;
import org.springframework.security.oauth2.jose.TestKeys;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.TestOAuth2Authorizations;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository.RegisteredClientParametersMapper;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.util.Assert;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.CoreMatchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Integration tests for the OAuth 2.0 Refresh Token Grant.
 *
 * @author Alexey Nesterov
 * @since 7.0
 */
@ExtendWith(SpringTestContextExtension.class)
public class OAuth2RefreshTokenGrantTests {

	private static final String DEFAULT_TOKEN_ENDPOINT_URI = "/oauth2/token";

	private static final String DEFAULT_TOKEN_REVOCATION_ENDPOINT_URI = "/oauth2/revoke";

	private static final String AUTHORITIES_CLAIM = "authorities";

	private static EmbeddedDatabase db;

	private static JWKSource<SecurityContext> jwkSource;

	private static NimbusJwtDecoder jwtDecoder;

	private static NimbusJwtEncoder dPoPProofJwtEncoder;

	private static HttpMessageConverter<OAuth2AccessTokenResponse> accessTokenHttpResponseConverter = new OAuth2AccessTokenResponseHttpMessageConverter();

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
		jwtDecoder = NimbusJwtDecoder.withPublicKey(TestKeys.DEFAULT_PUBLIC_KEY).build();
		JWKSet clientJwkSet = new JWKSet(TestJwks.DEFAULT_EC_JWK);
		JWKSource<SecurityContext> clientJwkSource = (jwkSelector, securityContext) -> jwkSelector.select(clientJwkSet);
		dPoPProofJwtEncoder = new NimbusJwtEncoder(clientJwkSource);
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
	public void requestWhenRefreshTokenRequestValidThenReturnAccessTokenResponse() throws Exception {
		this.spring.register(AuthorizationServerConfiguration.class).autowire();

		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		this.registeredClientRepository.save(registeredClient);

		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient).build();
		this.authorizationService.save(authorization);

		MvcResult mvcResult = this.mvc
			.perform(post(DEFAULT_TOKEN_ENDPOINT_URI).params(getRefreshTokenRequestParameters(authorization))
				.header(HttpHeaders.AUTHORIZATION,
						"Basic " + encodeBasicAuth(registeredClient.getClientId(), registeredClient.getClientSecret())))
			.andExpect(status().isOk())
			.andExpect(header().string(HttpHeaders.CACHE_CONTROL, containsString("no-store")))
			.andExpect(header().string(HttpHeaders.PRAGMA, containsString("no-cache")))
			.andExpect(jsonPath("$.access_token").isNotEmpty())
			.andExpect(jsonPath("$.token_type").isNotEmpty())
			.andExpect(jsonPath("$.expires_in").isNotEmpty())
			.andExpect(jsonPath("$.refresh_token").isNotEmpty())
			.andExpect(jsonPath("$.scope").isNotEmpty())
			.andReturn();

		MockHttpServletResponse servletResponse = mvcResult.getResponse();
		MockClientHttpResponse httpResponse = new MockClientHttpResponse(servletResponse.getContentAsByteArray(),
				HttpStatus.valueOf(servletResponse.getStatus()));
		OAuth2AccessTokenResponse accessTokenResponse = accessTokenHttpResponseConverter
			.read(OAuth2AccessTokenResponse.class, httpResponse);

		// Assert user authorities was propagated as claim in JWT
		Jwt jwt = jwtDecoder.decode(accessTokenResponse.getAccessToken().getTokenValue());
		List<String> authoritiesClaim = jwt.getClaim(AUTHORITIES_CLAIM);
		Authentication principal = authorization.getAttribute(Principal.class.getName());
		Set<String> userAuthorities = new HashSet<>();
		for (GrantedAuthority authority : principal.getAuthorities()) {
			userAuthorities.add(authority.getAuthority());
		}
		assertThat(authoritiesClaim).containsExactlyInAnyOrderElementsOf(userAuthorities);
	}

	// gh-432
	@Test
	public void requestWhenRevokeAndRefreshThenAccessTokenActive() throws Exception {
		this.spring.register(AuthorizationServerConfiguration.class).autowire();

		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		this.registeredClientRepository.save(registeredClient);

		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient).build();
		this.authorizationService.save(authorization);

		OAuth2AccessToken token = authorization.getAccessToken().getToken();
		OAuth2TokenType tokenType = OAuth2TokenType.ACCESS_TOKEN;

		this.mvc
			.perform(post(DEFAULT_TOKEN_REVOCATION_ENDPOINT_URI)
				.params(getTokenRevocationRequestParameters(token, tokenType))
				.header(HttpHeaders.AUTHORIZATION,
						"Basic " + encodeBasicAuth(registeredClient.getClientId(), registeredClient.getClientSecret())))
			.andExpect(status().isOk());

		this.mvc
			.perform(post(DEFAULT_TOKEN_ENDPOINT_URI).params(getRefreshTokenRequestParameters(authorization))
				.header(HttpHeaders.AUTHORIZATION,
						"Basic " + encodeBasicAuth(registeredClient.getClientId(), registeredClient.getClientSecret())))
			.andExpect(status().isOk());

		OAuth2Authorization updatedAuthorization = this.authorizationService.findById(authorization.getId());
		OAuth2Authorization.Token<OAuth2AccessToken> accessToken = updatedAuthorization.getAccessToken();
		assertThat(accessToken.isActive()).isTrue();
	}

	// gh-1430
	@Test
	public void requestWhenRefreshTokenRequestWithPublicClientThenReturnAccessTokenResponse() throws Exception {
		this.spring.register(AuthorizationServerConfigurationWithPublicClientAuthentication.class).autowire();

		RegisteredClient registeredClient = TestRegisteredClients.registeredPublicClient()
			.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
			.build();
		this.registeredClientRepository.save(registeredClient);

		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient).build();
		this.authorizationService.save(authorization);

		this.mvc
			.perform(post(DEFAULT_TOKEN_ENDPOINT_URI).params(getRefreshTokenRequestParameters(authorization))
				.param(OAuth2ParameterNames.CLIENT_ID, registeredClient.getClientId()))
			.andExpect(status().isOk())
			.andExpect(header().string(HttpHeaders.CACHE_CONTROL, containsString("no-store")))
			.andExpect(header().string(HttpHeaders.PRAGMA, containsString("no-cache")))
			.andExpect(jsonPath("$.access_token").isNotEmpty())
			.andExpect(jsonPath("$.token_type").isNotEmpty())
			.andExpect(jsonPath("$.expires_in").isNotEmpty())
			.andExpect(jsonPath("$.refresh_token").isNotEmpty())
			.andExpect(jsonPath("$.scope").isNotEmpty());
	}

	@Test
	public void requestWhenRefreshTokenRequestWithPublicClientAndDPoPProofThenReturnDPoPBoundAccessToken()
			throws Exception {
		this.spring.register(AuthorizationServerConfigurationWithPublicClientAuthentication.class).autowire();

		RegisteredClient registeredClient = TestRegisteredClients.registeredPublicClient()
			.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
			.build();
		this.registeredClientRepository.save(registeredClient);

		OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.DPOP,
				"dpop-bound-access-token", Instant.now(), Instant.now().plusSeconds(300));
		Map<String, Object> accessTokenClaims = new HashMap<>();
		Map<String, Object> cnfClaim = new HashMap<>();
		cnfClaim.put("jkt", TestJwks.DEFAULT_EC_JWK.toPublicJWK().computeThumbprint().toString());
		accessTokenClaims.put("cnf", cnfClaim);
		OAuth2Authorization authorization = TestOAuth2Authorizations
			.authorization(registeredClient, accessToken, accessTokenClaims)
			.build();
		this.authorizationService.save(authorization);

		String tokenEndpointUri = "http://localhost" + DEFAULT_TOKEN_ENDPOINT_URI;
		String dPoPProof = generateDPoPProof(tokenEndpointUri);

		this.mvc
			.perform(post(DEFAULT_TOKEN_ENDPOINT_URI).params(getRefreshTokenRequestParameters(authorization))
				.param(OAuth2ParameterNames.CLIENT_ID, registeredClient.getClientId())
				.header(OAuth2AccessToken.TokenType.DPOP.getValue(), dPoPProof))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.token_type").value(OAuth2AccessToken.TokenType.DPOP.getValue()));

		authorization = this.authorizationService.findById(authorization.getId());
		assertThat(authorization.getAccessToken().getClaims()).containsKey("cnf");
		@SuppressWarnings("unchecked")
		Map<String, Object> cnfClaims = (Map<String, Object>) authorization.getAccessToken().getClaims().get("cnf");
		assertThat(cnfClaims).containsKey("jkt");
		String jwkThumbprintClaim = (String) cnfClaims.get("jkt");
		assertThat(jwkThumbprintClaim).isEqualTo(TestJwks.DEFAULT_EC_JWK.toPublicJWK().computeThumbprint().toString());
	}

	@Test
	public void requestWhenRefreshTokenRequestWithPublicClientAndDPoPProofAndAccessTokenNotBoundThenBadRequest()
			throws Exception {
		this.spring.register(AuthorizationServerConfigurationWithPublicClientAuthentication.class).autowire();

		RegisteredClient registeredClient = TestRegisteredClients.registeredPublicClient()
			.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
			.build();
		this.registeredClientRepository.save(registeredClient);

		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient).build();
		this.authorizationService.save(authorization);

		String tokenEndpointUri = "http://localhost" + DEFAULT_TOKEN_ENDPOINT_URI;
		String dPoPProof = generateDPoPProof(tokenEndpointUri);

		this.mvc
			.perform(post(DEFAULT_TOKEN_ENDPOINT_URI).params(getRefreshTokenRequestParameters(authorization))
				.param(OAuth2ParameterNames.CLIENT_ID, registeredClient.getClientId())
				.header(OAuth2AccessToken.TokenType.DPOP.getValue(), dPoPProof))
			.andExpect(status().isBadRequest())
			.andExpect(jsonPath("$.error").value(OAuth2ErrorCodes.INVALID_DPOP_PROOF))
			.andExpect(jsonPath("$.error_description").value("jkt claim is missing."));
	}

	@Test
	public void requestWhenRefreshTokenRequestWithPublicClientAndDPoPProofAndDifferentPublicKeyThenBadRequest()
			throws Exception {
		this.spring.register(AuthorizationServerConfigurationWithPublicClientAuthentication.class).autowire();

		RegisteredClient registeredClient = TestRegisteredClients.registeredPublicClient()
			.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
			.build();
		this.registeredClientRepository.save(registeredClient);

		OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.DPOP,
				"dpop-bound-access-token", Instant.now(), Instant.now().plusSeconds(300));
		Map<String, Object> accessTokenClaims = new HashMap<>();
		// Bind access token to different public key
		PublicKey publicKey = TestJwks.DEFAULT_RSA_JWK.toPublicKey();
		Map<String, Object> cnfClaim = new HashMap<>();
		cnfClaim.put("jkt", computeSHA256(publicKey));
		accessTokenClaims.put("cnf", cnfClaim);
		OAuth2Authorization authorization = TestOAuth2Authorizations
			.authorization(registeredClient, accessToken, accessTokenClaims)
			.build();
		this.authorizationService.save(authorization);

		String tokenEndpointUri = "http://localhost" + DEFAULT_TOKEN_ENDPOINT_URI;
		String dPoPProof = generateDPoPProof(tokenEndpointUri);

		this.mvc
			.perform(post(DEFAULT_TOKEN_ENDPOINT_URI).params(getRefreshTokenRequestParameters(authorization))
				.param(OAuth2ParameterNames.CLIENT_ID, registeredClient.getClientId())
				.header(OAuth2AccessToken.TokenType.DPOP.getValue(), dPoPProof))
			.andExpect(status().isBadRequest())
			.andExpect(jsonPath("$.error").value(OAuth2ErrorCodes.INVALID_DPOP_PROOF))
			.andExpect(jsonPath("$.error_description").value("jwk header is invalid."));
	}

	@Test
	public void requestWhenRefreshTokenRequestWithDPoPProofThenReturnDPoPBoundAccessToken() throws Exception {
		this.spring.register(AuthorizationServerConfiguration.class).autowire();

		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		this.registeredClientRepository.save(registeredClient);

		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient).build();
		this.authorizationService.save(authorization);

		String tokenEndpointUri = "http://localhost" + DEFAULT_TOKEN_ENDPOINT_URI;
		String dPoPProof = generateDPoPProof(tokenEndpointUri);

		this.mvc
			.perform(post(DEFAULT_TOKEN_ENDPOINT_URI).params(getRefreshTokenRequestParameters(authorization))
				.header(HttpHeaders.AUTHORIZATION,
						"Basic " + encodeBasicAuth(registeredClient.getClientId(), registeredClient.getClientSecret()))
				.header(OAuth2AccessToken.TokenType.DPOP.getValue(), dPoPProof))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.token_type").value(OAuth2AccessToken.TokenType.DPOP.getValue()));

		authorization = this.authorizationService.findById(authorization.getId());
		assertThat(authorization.getAccessToken().getClaims()).containsKey("cnf");
		@SuppressWarnings("unchecked")
		Map<String, Object> cnfClaims = (Map<String, Object>) authorization.getAccessToken().getClaims().get("cnf");
		assertThat(cnfClaims).containsKey("jkt");
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

	private static String computeSHA256(PublicKey publicKey) throws Exception {
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		byte[] digest = md.digest(publicKey.getEncoded());
		return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
	}

	private static MultiValueMap<String, String> getRefreshTokenRequestParameters(OAuth2Authorization authorization) {
		MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
		parameters.set(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.REFRESH_TOKEN.getValue());
		parameters.set(OAuth2ParameterNames.REFRESH_TOKEN, authorization.getRefreshToken().getToken().getTokenValue());
		return parameters;
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
		OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer() {
			return (context) -> {
				if (AuthorizationGrantType.REFRESH_TOKEN.equals(context.getAuthorizationGrantType())) {
					Authentication principal = context.getPrincipal();
					Set<String> authorities = new HashSet<>();
					for (GrantedAuthority authority : principal.getAuthorities()) {
						authorities.add(authority.getAuthority());
					}
					context.getClaims().claim(AUTHORITIES_CLAIM, authorities);
				}
			};
		}

		@Bean
		PasswordEncoder passwordEncoder() {
			return NoOpPasswordEncoder.getInstance();
		}

	}

	@EnableWebSecurity
	@Configuration(proxyBeanMethods = false)
	static class AuthorizationServerConfigurationWithPublicClientAuthentication
			extends AuthorizationServerConfiguration {

		// @formatter:off
		@Bean
		SecurityFilterChain authorizationServerSecurityFilterChain(
				HttpSecurity http, RegisteredClientRepository registeredClientRepository) throws Exception {

			http
					.oauth2AuthorizationServer((authorizationServer) ->
							authorizationServer
									.clientAuthentication((clientAuthentication) ->
											clientAuthentication
													.authenticationConverter(
															new PublicClientRefreshTokenAuthenticationConverter())
													.authenticationProvider(
															new PublicClientRefreshTokenAuthenticationProvider(registeredClientRepository)))
					)
					.authorizeHttpRequests((authorize) ->
							authorize.anyRequest().authenticated()
					);
			return http.build();
		}
		// @formatter:on

	}

	@Transient
	private static final class PublicClientRefreshTokenAuthenticationToken extends OAuth2ClientAuthenticationToken {

		private PublicClientRefreshTokenAuthenticationToken(String clientId) {
			super(clientId, ClientAuthenticationMethod.NONE, null, null);
		}

		private PublicClientRefreshTokenAuthenticationToken(RegisteredClient registeredClient) {
			super(registeredClient, ClientAuthenticationMethod.NONE, null);
		}

	}

	private static final class PublicClientRefreshTokenAuthenticationConverter implements AuthenticationConverter {

		@Nullable
		@Override
		public Authentication convert(HttpServletRequest request) {
			// grant_type (REQUIRED)
			String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);
			if (!AuthorizationGrantType.REFRESH_TOKEN.getValue().equals(grantType)) {
				return null;
			}

			// client_id (REQUIRED)
			String clientId = request.getParameter(OAuth2ParameterNames.CLIENT_ID);
			if (!StringUtils.hasText(clientId)) {
				return null;
			}

			return new PublicClientRefreshTokenAuthenticationToken(clientId);
		}

	}

	private static final class PublicClientRefreshTokenAuthenticationProvider implements AuthenticationProvider {

		private final RegisteredClientRepository registeredClientRepository;

		private PublicClientRefreshTokenAuthenticationProvider(RegisteredClientRepository registeredClientRepository) {
			Assert.notNull(registeredClientRepository, "registeredClientRepository cannot be null");
			this.registeredClientRepository = registeredClientRepository;
		}

		@Override
		public Authentication authenticate(Authentication authentication) throws AuthenticationException {
			PublicClientRefreshTokenAuthenticationToken publicClientAuthentication = (PublicClientRefreshTokenAuthenticationToken) authentication;

			if (!ClientAuthenticationMethod.NONE.equals(publicClientAuthentication.getClientAuthenticationMethod())) {
				return null;
			}

			String clientId = publicClientAuthentication.getPrincipal().toString();
			RegisteredClient registeredClient = this.registeredClientRepository.findByClientId(clientId);
			if (registeredClient == null) {
				throwInvalidClient(OAuth2ParameterNames.CLIENT_ID);
			}

			if (!registeredClient.getClientAuthenticationMethods()
				.contains(publicClientAuthentication.getClientAuthenticationMethod())) {
				throwInvalidClient("authentication_method");
			}

			return new PublicClientRefreshTokenAuthenticationToken(registeredClient);
		}

		@Override
		public boolean supports(Class<?> authentication) {
			return PublicClientRefreshTokenAuthenticationToken.class.isAssignableFrom(authentication);
		}

		private static void throwInvalidClient(String parameterName) {
			OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT,
					"Public client authentication failed: " + parameterName, null);
			throw new OAuth2AuthenticationException(error);
		}

	}

}
