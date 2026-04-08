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

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.Principal;
import java.text.MessageFormat;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.function.Consumer;

import com.jayway.jsonpath.JsonPath;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.assertj.core.matcher.AssertionMatcher;
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
import org.springframework.lang.Nullable;
import org.springframework.mock.http.client.MockClientHttpResponse;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.oauth2.jose.TestJwks;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.TestOAuth2Authorizations;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationConsentAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationConsentAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationConsentAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository.RegisteredClientParametersMapper;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2RefreshTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2AuthorizationCodeRequestAuthenticationConverter;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2AuthorizationConsentAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.CoreMatchers.containsString;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Integration tests for the OAuth 2.0 Authorization Code Grant.
 *
 * @author Joe Grandja
 * @author Daniel Garnier-Moiroux
 * @author Dmitriy Dubson
 * @author Steve Riesenberg
 * @author Greg Li
 */
@ExtendWith(SpringTestContextExtension.class)
public class OAuth2AuthorizationCodeGrantTests {

	private static final String DEFAULT_AUTHORIZATION_ENDPOINT_URI = "/oauth2/authorize";

	private static final String DEFAULT_TOKEN_ENDPOINT_URI = "/oauth2/token";

	// See RFC 7636: Appendix B. Example for the S256 code_challenge_method
	// https://tools.ietf.org/html/rfc7636#appendix-B
	private static final String S256_CODE_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

	private static final String S256_CODE_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

	private static final String AUTHORITIES_CLAIM = "authorities";

	private static final String STATE_URL_UNENCODED = "awrD0fCnEcTUPFgmyy2SU89HZNcnAJ60ZW6l39YI0KyVjmIZ+004pwm9j55li7BoydXYysH4enZMF21Q";

	private static final String STATE_URL_ENCODED = "awrD0fCnEcTUPFgmyy2SU89HZNcnAJ60ZW6l39YI0KyVjmIZ%2B004pwm9j55li7BoydXYysH4enZMF21Q";

	private static final OAuth2TokenType AUTHORIZATION_CODE_TOKEN_TYPE = new OAuth2TokenType(OAuth2ParameterNames.CODE);

	private static final OAuth2TokenType STATE_TOKEN_TYPE = new OAuth2TokenType(OAuth2ParameterNames.STATE);

	private static EmbeddedDatabase db;

	private static JWKSource<SecurityContext> jwkSource;

	private static NimbusJwtEncoder jwtEncoder;

	private static NimbusJwtEncoder dPoPProofJwtEncoder;

	private static AuthorizationServerSettings authorizationServerSettings;

	private static HttpMessageConverter<OAuth2AccessTokenResponse> accessTokenHttpResponseConverter = new OAuth2AccessTokenResponseHttpMessageConverter();

	private static AuthenticationConverter authorizationRequestConverter;

	private static Consumer<List<AuthenticationConverter>> authorizationRequestConvertersConsumer;

	private static AuthenticationProvider authorizationRequestAuthenticationProvider;

	private static Consumer<List<AuthenticationProvider>> authorizationRequestAuthenticationProvidersConsumer;

	private static AuthenticationSuccessHandler authorizationResponseHandler;

	private static AuthenticationFailureHandler authorizationErrorResponseHandler;

	private static SecurityContextRepository securityContextRepository;

	private static String consentPage = "/oauth2/consent";

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
	private JwtDecoder jwtDecoder;

	@Autowired(required = false)
	private OAuth2TokenGenerator<?> tokenGenerator;

	@BeforeAll
	public static void init() {
		JWKSet jwkSet = new JWKSet(TestJwks.DEFAULT_RSA_JWK);
		jwkSource = (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
		jwtEncoder = new NimbusJwtEncoder(jwkSource);
		JWKSet clientJwkSet = new JWKSet(TestJwks.DEFAULT_EC_JWK);
		JWKSource<SecurityContext> clientJwkSource = (jwkSelector, securityContext) -> jwkSelector.select(clientJwkSet);
		dPoPProofJwtEncoder = new NimbusJwtEncoder(clientJwkSource);
		authorizationServerSettings = AuthorizationServerSettings.builder()
			.authorizationEndpoint("/test/authorize")
			.tokenEndpoint("/test/token")
			.build();
		authorizationRequestConverter = mock(AuthenticationConverter.class);
		authorizationRequestConvertersConsumer = mock(Consumer.class);
		authorizationRequestAuthenticationProvider = mock(AuthenticationProvider.class);
		authorizationRequestAuthenticationProvidersConsumer = mock(Consumer.class);
		authorizationResponseHandler = mock(AuthenticationSuccessHandler.class);
		authorizationErrorResponseHandler = mock(AuthenticationFailureHandler.class);
		securityContextRepository = spy(new HttpSessionSecurityContextRepository());
		db = new EmbeddedDatabaseBuilder().generateUniqueName(true)
			.setType(EmbeddedDatabaseType.HSQL)
			.setScriptEncoding("UTF-8")
			.addScript("org/springframework/security/oauth2/server/authorization/oauth2-authorization-schema.sql")
			.addScript(
					"org/springframework/security/oauth2/server/authorization/oauth2-authorization-consent-schema.sql")
			.addScript(
					"org/springframework/security/oauth2/server/authorization/client/oauth2-registered-client-schema.sql")
			.build();
	}

	@BeforeEach
	public void setup() {
		reset(securityContextRepository);
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
	public void requestWhenAuthorizationRequestNotAuthenticatedThenUnauthorized() throws Exception {
		this.spring.register(AuthorizationServerConfiguration.class).autowire();

		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		this.registeredClientRepository.save(registeredClient);

		this.mvc
			.perform(get(DEFAULT_AUTHORIZATION_ENDPOINT_URI)
				.queryParams(getAuthorizationRequestParameters(registeredClient)))
			.andExpect(status().isUnauthorized())
			.andReturn();
	}

	@Test
	public void requestWhenRegisteredClientMissingThenBadRequest() throws Exception {
		this.spring.register(AuthorizationServerConfiguration.class).autowire();

		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();

		this.mvc
			.perform(get(DEFAULT_AUTHORIZATION_ENDPOINT_URI)
				.queryParams(getAuthorizationRequestParameters(registeredClient)))
			.andExpect(status().isBadRequest())
			.andReturn();
	}

	@Test
	public void requestWhenAuthorizationRequestAuthenticatedThenRedirectToClient() throws Exception {
		this.spring.register(AuthorizationServerConfiguration.class).autowire();

		assertAuthorizationRequestRedirectsToClient(DEFAULT_AUTHORIZATION_ENDPOINT_URI);
	}

	@Test
	public void requestWhenAuthorizationRequestCustomEndpointThenRedirectToClient() throws Exception {
		this.spring.register(AuthorizationServerConfigurationCustomEndpoints.class).autowire();

		assertAuthorizationRequestRedirectsToClient(authorizationServerSettings.getAuthorizationEndpoint());
	}

	private void assertAuthorizationRequestRedirectsToClient(String authorizationEndpointUri) throws Exception {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().redirectUris((redirectUris) -> {
			redirectUris.clear();
			redirectUris.add("https://example.com/callback-1?param=encoded%20parameter%20value"); // gh-1011
		}).build();
		this.registeredClientRepository.save(registeredClient);

		MultiValueMap<String, String> authorizationRequestParameters = getAuthorizationRequestParameters(
				registeredClient);
		MvcResult mvcResult = this.mvc
			.perform(get(authorizationEndpointUri).queryParams(authorizationRequestParameters).with(user("user")))
			.andExpect(status().is3xxRedirection())
			.andReturn();
		String redirectedUrl = mvcResult.getResponse().getRedirectedUrl();
		String redirectUri = authorizationRequestParameters.getFirst(OAuth2ParameterNames.REDIRECT_URI);
		String code = extractParameterFromRedirectUri(redirectedUrl, "code");
		assertThat(redirectedUrl).isEqualTo(redirectUri + "&code=" + code + "&state=" + STATE_URL_ENCODED);

		String authorizationCode = extractParameterFromRedirectUri(redirectedUrl, "code");
		OAuth2Authorization authorization = this.authorizationService.findByToken(authorizationCode,
				AUTHORIZATION_CODE_TOKEN_TYPE);
		assertThat(authorization).isNotNull();
		assertThat(authorization.getAuthorizationGrantType()).isEqualTo(AuthorizationGrantType.AUTHORIZATION_CODE);
	}

	@Test
	public void requestWhenTokenRequestValidThenReturnAccessTokenResponse() throws Exception {
		this.spring.register(AuthorizationServerConfiguration.class).autowire();

		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		this.registeredClientRepository.save(registeredClient);

		OAuth2Authorization authorization = createAuthorization(registeredClient);
		this.authorizationService.save(authorization);

		OAuth2AccessTokenResponse accessTokenResponse = assertTokenRequestReturnsAccessTokenResponse(registeredClient,
				authorization, DEFAULT_TOKEN_ENDPOINT_URI);

		// Assert user authorities was propagated as claim in JWT
		Jwt jwt = this.jwtDecoder.decode(accessTokenResponse.getAccessToken().getTokenValue());
		List<String> authoritiesClaim = jwt.getClaim(AUTHORITIES_CLAIM);
		Authentication principal = authorization.getAttribute(Principal.class.getName());
		Set<String> userAuthorities = new HashSet<>();
		for (GrantedAuthority authority : principal.getAuthorities()) {
			userAuthorities.add(authority.getAuthority());
		}

		assertThat(authoritiesClaim).containsExactlyInAnyOrderElementsOf(userAuthorities);
	}

	@Test
	public void requestWhenTokenRequestCustomEndpointThenReturnAccessTokenResponse() throws Exception {
		this.spring.register(AuthorizationServerConfigurationCustomEndpoints.class).autowire();

		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		this.registeredClientRepository.save(registeredClient);

		OAuth2Authorization authorization = createAuthorization(registeredClient);
		this.authorizationService.save(authorization);

		assertTokenRequestReturnsAccessTokenResponse(registeredClient, authorization,
				authorizationServerSettings.getTokenEndpoint());
	}

	private OAuth2AccessTokenResponse assertTokenRequestReturnsAccessTokenResponse(RegisteredClient registeredClient,
			OAuth2Authorization authorization, String tokenEndpointUri) throws Exception {
		MvcResult mvcResult = this.mvc
			.perform(post(tokenEndpointUri).params(getTokenRequestParameters(registeredClient, authorization))
				.header(HttpHeaders.AUTHORIZATION, getAuthorizationHeader(registeredClient)))
			.andExpect(status().isOk())
			.andExpect(header().string(HttpHeaders.CACHE_CONTROL, containsString("no-store")))
			.andExpect(header().string(HttpHeaders.PRAGMA, containsString("no-cache")))
			.andExpect(jsonPath("$.access_token").isNotEmpty())
			.andExpect(jsonPath("$.token_type").isNotEmpty())
			.andExpect(jsonPath("$.expires_in").isNotEmpty())
			.andExpect(jsonPath("$.refresh_token").isNotEmpty())
			.andExpect(jsonPath("$.scope").isNotEmpty())
			.andReturn();

		OAuth2Authorization accessTokenAuthorization = this.authorizationService.findById(authorization.getId());
		assertThat(accessTokenAuthorization).isNotNull();
		assertThat(accessTokenAuthorization.getAccessToken()).isNotNull();
		assertThat(accessTokenAuthorization.getRefreshToken()).isNotNull();

		OAuth2Authorization.Token<OAuth2AuthorizationCode> authorizationCodeToken = accessTokenAuthorization
			.getToken(OAuth2AuthorizationCode.class);
		assertThat(authorizationCodeToken).isNotNull();
		assertThat(authorizationCodeToken.getMetadata().get(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME))
			.isEqualTo(true);

		MockHttpServletResponse servletResponse = mvcResult.getResponse();
		MockClientHttpResponse httpResponse = new MockClientHttpResponse(servletResponse.getContentAsByteArray(),
				HttpStatus.valueOf(servletResponse.getStatus()));
		return accessTokenHttpResponseConverter.read(OAuth2AccessTokenResponse.class, httpResponse);
	}

	@Test
	public void requestWhenPublicClientWithPkceThenReturnAccessTokenResponse() throws Exception {
		this.spring.register(AuthorizationServerConfiguration.class).autowire();

		RegisteredClient registeredClient = TestRegisteredClients.registeredPublicClient().build();
		this.registeredClientRepository.save(registeredClient);

		MvcResult mvcResult = this.mvc
			.perform(get(DEFAULT_AUTHORIZATION_ENDPOINT_URI)
				.queryParams(getAuthorizationRequestParameters(registeredClient))
				.with(user("user")))
			.andExpect(status().is3xxRedirection())
			.andReturn();
		String redirectedUrl = mvcResult.getResponse().getRedirectedUrl();
		assertThat(redirectedUrl).matches("https://example.com\\?code=.{15,}&state=" + STATE_URL_ENCODED);

		String authorizationCode = extractParameterFromRedirectUri(redirectedUrl, "code");
		OAuth2Authorization authorizationCodeAuthorization = this.authorizationService.findByToken(authorizationCode,
				AUTHORIZATION_CODE_TOKEN_TYPE);
		assertThat(authorizationCodeAuthorization).isNotNull();
		assertThat(authorizationCodeAuthorization.getAuthorizationGrantType())
			.isEqualTo(AuthorizationGrantType.AUTHORIZATION_CODE);

		this.mvc
			.perform(post(DEFAULT_TOKEN_ENDPOINT_URI)
				.params(getTokenRequestParameters(registeredClient, authorizationCodeAuthorization))
				.param(OAuth2ParameterNames.CLIENT_ID, registeredClient.getClientId()))
			.andExpect(header().string(HttpHeaders.CACHE_CONTROL, containsString("no-store")))
			.andExpect(header().string(HttpHeaders.PRAGMA, containsString("no-cache")))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.access_token").isNotEmpty())
			.andExpect(jsonPath("$.token_type").isNotEmpty())
			.andExpect(jsonPath("$.expires_in").isNotEmpty())
			.andExpect(jsonPath("$.refresh_token").doesNotExist())
			.andExpect(jsonPath("$.scope").isNotEmpty());

		OAuth2Authorization accessTokenAuthorization = this.authorizationService
			.findById(authorizationCodeAuthorization.getId());
		assertThat(accessTokenAuthorization).isNotNull();
		assertThat(accessTokenAuthorization.getAccessToken()).isNotNull();

		OAuth2Authorization.Token<OAuth2AuthorizationCode> authorizationCodeToken = accessTokenAuthorization
			.getToken(OAuth2AuthorizationCode.class);
		assertThat(authorizationCodeToken).isNotNull();
		assertThat(authorizationCodeToken.getMetadata().get(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME))
			.isEqualTo(true);
	}

	// gh-1430
	@Test
	public void requestWhenPublicClientWithPkceAndCustomRefreshTokenGeneratorThenReturnRefreshToken() throws Exception {
		this.spring.register(AuthorizationServerConfigurationWithCustomRefreshTokenGenerator.class).autowire();

		RegisteredClient registeredClient = TestRegisteredClients.registeredPublicClient()
			.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
			.build();
		this.registeredClientRepository.save(registeredClient);

		MvcResult mvcResult = this.mvc
			.perform(get(DEFAULT_AUTHORIZATION_ENDPOINT_URI)
				.queryParams(getAuthorizationRequestParameters(registeredClient))
				.with(user("user")))
			.andExpect(status().is3xxRedirection())
			.andReturn();
		String redirectedUrl = mvcResult.getResponse().getRedirectedUrl();
		assertThat(redirectedUrl).matches("https://example.com\\?code=.{15,}&state=" + STATE_URL_ENCODED);

		String authorizationCode = extractParameterFromRedirectUri(redirectedUrl, "code");
		OAuth2Authorization authorizationCodeAuthorization = this.authorizationService.findByToken(authorizationCode,
				AUTHORIZATION_CODE_TOKEN_TYPE);
		assertThat(authorizationCodeAuthorization).isNotNull();
		assertThat(authorizationCodeAuthorization.getAuthorizationGrantType())
			.isEqualTo(AuthorizationGrantType.AUTHORIZATION_CODE);

		this.mvc
			.perform(post(DEFAULT_TOKEN_ENDPOINT_URI)
				.params(getTokenRequestParameters(registeredClient, authorizationCodeAuthorization))
				.param(OAuth2ParameterNames.CLIENT_ID, registeredClient.getClientId()))
			.andExpect(header().string(HttpHeaders.CACHE_CONTROL, containsString("no-store")))
			.andExpect(header().string(HttpHeaders.PRAGMA, containsString("no-cache")))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.access_token").isNotEmpty())
			.andExpect(jsonPath("$.token_type").isNotEmpty())
			.andExpect(jsonPath("$.expires_in").isNotEmpty())
			.andExpect(jsonPath("$.refresh_token").isNotEmpty())
			.andExpect(jsonPath("$.scope").isNotEmpty());

		OAuth2Authorization authorization = this.authorizationService.findById(authorizationCodeAuthorization.getId());
		assertThat(authorization).isNotNull();
		assertThat(authorization.getAccessToken()).isNotNull();
		assertThat(authorization.getRefreshToken()).isNotNull();

		OAuth2Authorization.Token<OAuth2AuthorizationCode> authorizationCodeToken = authorization
			.getToken(OAuth2AuthorizationCode.class);
		assertThat(authorizationCodeToken).isNotNull();
		assertThat(authorizationCodeToken.getMetadata().get(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME))
			.isEqualTo(true);
	}

	// gh-1680
	@Test
	public void requestWhenPublicClientWithPkceAndEmptyCodeThenBadRequest() throws Exception {
		this.spring.register(AuthorizationServerConfiguration.class).autowire();

		RegisteredClient registeredClient = TestRegisteredClients.registeredPublicClient().build();
		this.registeredClientRepository.save(registeredClient);

		MultiValueMap<String, String> tokenRequestParameters = new LinkedMultiValueMap<>();
		tokenRequestParameters.set(OAuth2ParameterNames.GRANT_TYPE,
				AuthorizationGrantType.AUTHORIZATION_CODE.getValue());
		tokenRequestParameters.set(OAuth2ParameterNames.CODE, "");
		tokenRequestParameters.set(OAuth2ParameterNames.REDIRECT_URI,
				registeredClient.getRedirectUris().iterator().next());
		tokenRequestParameters.set(PkceParameterNames.CODE_VERIFIER, S256_CODE_VERIFIER);

		this.mvc
			.perform(post(DEFAULT_TOKEN_ENDPOINT_URI).params(tokenRequestParameters)
				.param(OAuth2ParameterNames.CLIENT_ID, registeredClient.getClientId()))
			.andExpect(status().isBadRequest());
	}

	@Test
	public void requestWhenConfidentialClientWithPkceAndMissingCodeVerifierThenBadRequest() throws Exception {
		this.spring.register(AuthorizationServerConfiguration.class).autowire();

		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		this.registeredClientRepository.save(registeredClient);

		MultiValueMap<String, String> authorizationRequestParameters = getAuthorizationRequestParameters(
				registeredClient);
		MvcResult mvcResult = this.mvc
			.perform(get(DEFAULT_AUTHORIZATION_ENDPOINT_URI).queryParams(authorizationRequestParameters)
				.with(user("user")))
			.andExpect(status().is3xxRedirection())
			.andReturn();
		String redirectedUrl = mvcResult.getResponse().getRedirectedUrl();
		String expectedRedirectUri = authorizationRequestParameters.getFirst(OAuth2ParameterNames.REDIRECT_URI);
		assertThat(redirectedUrl).matches(expectedRedirectUri + "\\?code=.{15,}&state=" + STATE_URL_ENCODED);

		String authorizationCode = extractParameterFromRedirectUri(redirectedUrl, "code");
		OAuth2Authorization authorizationCodeAuthorization = this.authorizationService.findByToken(authorizationCode,
				AUTHORIZATION_CODE_TOKEN_TYPE);
		assertThat(authorizationCodeAuthorization).isNotNull();
		assertThat(authorizationCodeAuthorization.getAuthorizationGrantType())
			.isEqualTo(AuthorizationGrantType.AUTHORIZATION_CODE);

		MultiValueMap<String, String> tokenRequestParameters = getTokenRequestParameters(registeredClient,
				authorizationCodeAuthorization);
		tokenRequestParameters.remove(PkceParameterNames.CODE_VERIFIER);

		this.mvc
			.perform(post(DEFAULT_TOKEN_ENDPOINT_URI).params(tokenRequestParameters)
				.param(OAuth2ParameterNames.CLIENT_ID, registeredClient.getClientId())
				.header(HttpHeaders.AUTHORIZATION, getAuthorizationHeader(registeredClient)))
			.andExpect(status().isBadRequest());
	}

	// gh-1011
	@Test
	public void requestWhenConfidentialClientWithPkceAndMissingCodeChallengeThenErrorResponseEncoded()
			throws Exception {
		this.spring.register(AuthorizationServerConfiguration.class).autowire();

		String redirectUri = "https://example.com/callback-1?param=encoded%20parameter%20value";
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().redirectUris((redirectUris) -> {
			redirectUris.clear();
			redirectUris.add(redirectUri);
		}).build();
		this.registeredClientRepository.save(registeredClient);

		MultiValueMap<String, String> authorizationRequestParameters = getAuthorizationRequestParameters(
				registeredClient);
		authorizationRequestParameters.remove(PkceParameterNames.CODE_CHALLENGE);
		MvcResult mvcResult = this.mvc
			.perform(get(DEFAULT_AUTHORIZATION_ENDPOINT_URI).queryParams(authorizationRequestParameters)
				.with(user("user")))
			.andExpect(status().is3xxRedirection())
			.andReturn();
		String redirectedUrl = mvcResult.getResponse().getRedirectedUrl();
		String expectedRedirectUri = redirectUri + "&" + "error=invalid_request&" + "error_description="
				+ UriUtils.encode("OAuth 2.0 Parameter: code_challenge", StandardCharsets.UTF_8) + "&" + "error_uri="
				+ UriUtils.encode("https://datatracker.ietf.org/doc/html/rfc7636#section-4.4.1", StandardCharsets.UTF_8)
				+ "&" + "state=" + STATE_URL_ENCODED;
		assertThat(redirectedUrl).isEqualTo(expectedRedirectUri);
	}

	@Test
	public void requestWhenConfidentialClientWithPkceAndMissingCodeChallengeButCodeVerifierProvidedThenBadRequest()
			throws Exception {
		this.spring.register(AuthorizationServerConfiguration.class).autowire();

		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
			.clientSettings(ClientSettings.builder().requireProofKey(false).build())
			.build();
		this.registeredClientRepository.save(registeredClient);

		MultiValueMap<String, String> authorizationRequestParameters = getAuthorizationRequestParameters(
				registeredClient);
		authorizationRequestParameters.remove(PkceParameterNames.CODE_CHALLENGE);
		MvcResult mvcResult = this.mvc
			.perform(get(DEFAULT_AUTHORIZATION_ENDPOINT_URI).queryParams(authorizationRequestParameters)
				.with(user("user")))
			.andExpect(status().is3xxRedirection())
			.andReturn();
		String redirectedUrl = mvcResult.getResponse().getRedirectedUrl();
		String expectedRedirectUri = authorizationRequestParameters.getFirst(OAuth2ParameterNames.REDIRECT_URI);
		assertThat(redirectedUrl).matches(expectedRedirectUri + "\\?code=.{15,}&state=" + STATE_URL_ENCODED);

		String authorizationCode = extractParameterFromRedirectUri(redirectedUrl, "code");
		OAuth2Authorization authorizationCodeAuthorization = this.authorizationService.findByToken(authorizationCode,
				AUTHORIZATION_CODE_TOKEN_TYPE);
		assertThat(authorizationCodeAuthorization).isNotNull();
		assertThat(authorizationCodeAuthorization.getAuthorizationGrantType())
			.isEqualTo(AuthorizationGrantType.AUTHORIZATION_CODE);

		this.mvc
			.perform(post(DEFAULT_TOKEN_ENDPOINT_URI)
				.params(getTokenRequestParameters(registeredClient, authorizationCodeAuthorization))
				.header(HttpHeaders.AUTHORIZATION, getAuthorizationHeader(registeredClient)))
			.andExpect(status().isBadRequest());
	}

	@Test
	public void requestWhenCustomTokenGeneratorThenUsed() throws Exception {
		this.spring.register(AuthorizationServerConfigurationWithTokenGenerator.class).autowire();

		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		this.registeredClientRepository.save(registeredClient);

		OAuth2Authorization authorization = createAuthorization(registeredClient);
		this.authorizationService.save(authorization);

		this.mvc
			.perform(post(DEFAULT_TOKEN_ENDPOINT_URI).params(getTokenRequestParameters(registeredClient, authorization))
				.header(HttpHeaders.AUTHORIZATION, getAuthorizationHeader(registeredClient)))
			.andExpect(status().isOk());

		verify(this.tokenGenerator, times(2)).generate(any());
	}

	@Test
	public void requestWhenRequiresConsentThenDisplaysConsentPage() throws Exception {
		this.spring.register(AuthorizationServerConfiguration.class).autowire();

		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().scopes((scopes) -> {
			scopes.clear();
			scopes.add("message.read");
			scopes.add("message.write");
		}).clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build()).build();
		this.registeredClientRepository.save(registeredClient);

		String consentPage = this.mvc
			.perform(get(DEFAULT_AUTHORIZATION_ENDPOINT_URI)
				.queryParams(getAuthorizationRequestParameters(registeredClient))
				.with(user("user")))
			.andExpect(status().is2xxSuccessful())
			.andReturn()
			.getResponse()
			.getContentAsString();

		assertThat(consentPage).contains("Consent required");
		assertThat(consentPage).contains(scopeCheckbox("message.read"));
		assertThat(consentPage).contains(scopeCheckbox("message.write"));
	}

	@Test
	public void requestWhenConsentRequestThenReturnAccessTokenResponse() throws Exception {
		this.spring.register(AuthorizationServerConfiguration.class).autowire();

		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().scopes((scopes) -> {
			scopes.clear();
			scopes.add("message.read");
			scopes.add("message.write");
		}).clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build()).build();
		this.registeredClientRepository.save(registeredClient);

		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient)
			.principalName("user")
			.build();
		Map<String, Object> additionalParameters = new HashMap<>();
		additionalParameters.put(PkceParameterNames.CODE_CHALLENGE, S256_CODE_CHALLENGE);
		additionalParameters.put(PkceParameterNames.CODE_CHALLENGE_METHOD, "S256");
		OAuth2AuthorizationRequest authorizationRequest = authorization
			.getAttribute(OAuth2AuthorizationRequest.class.getName());
		OAuth2AuthorizationRequest updatedAuthorizationRequest = OAuth2AuthorizationRequest.from(authorizationRequest)
			.state(STATE_URL_UNENCODED)
			.additionalParameters(additionalParameters)
			.build();
		authorization = OAuth2Authorization.from(authorization)
			.attribute(OAuth2AuthorizationRequest.class.getName(), updatedAuthorizationRequest)
			.build();
		this.authorizationService.save(authorization);

		MvcResult mvcResult = this.mvc
			.perform(post(DEFAULT_AUTHORIZATION_ENDPOINT_URI)
				.param(OAuth2ParameterNames.CLIENT_ID, registeredClient.getClientId())
				.param(OAuth2ParameterNames.SCOPE, "message.read")
				.param(OAuth2ParameterNames.SCOPE, "message.write")
				.param(OAuth2ParameterNames.STATE, authorization.<String>getAttribute(OAuth2ParameterNames.STATE))
				.with(user("user")))
			.andExpect(status().is3xxRedirection())
			.andReturn();

		String redirectedUrl = mvcResult.getResponse().getRedirectedUrl();
		assertThat(redirectedUrl)
			.matches(authorizationRequest.getRedirectUri() + "\\?code=.{15,}&state=" + STATE_URL_ENCODED);

		String authorizationCode = extractParameterFromRedirectUri(redirectedUrl, "code");
		OAuth2Authorization authorizationCodeAuthorization = this.authorizationService.findByToken(authorizationCode,
				AUTHORIZATION_CODE_TOKEN_TYPE);

		this.mvc
			.perform(post(DEFAULT_TOKEN_ENDPOINT_URI)
				.params(getTokenRequestParameters(registeredClient, authorizationCodeAuthorization))
				.header(HttpHeaders.AUTHORIZATION, getAuthorizationHeader(registeredClient)))
			.andExpect(status().isOk())
			.andExpect(header().string(HttpHeaders.CACHE_CONTROL, containsString("no-store")))
			.andExpect(header().string(HttpHeaders.PRAGMA, containsString("no-cache")))
			.andExpect(jsonPath("$.access_token").isNotEmpty())
			.andExpect(jsonPath("$.token_type").isNotEmpty())
			.andExpect(jsonPath("$.expires_in").isNotEmpty())
			.andExpect(jsonPath("$.refresh_token").isNotEmpty())
			.andExpect(jsonPath("$.scope").isNotEmpty())
			.andReturn();
	}

	@Test
	public void requestWhenCustomConsentPageConfiguredThenRedirect() throws Exception {
		this.spring.register(AuthorizationServerConfigurationCustomConsentPage.class).autowire();

		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().scopes((scopes) -> {
			scopes.clear();
			scopes.add("message.read");
			scopes.add("message.write");
		}).clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build()).build();
		this.registeredClientRepository.save(registeredClient);

		MvcResult mvcResult = this.mvc
			.perform(get(DEFAULT_AUTHORIZATION_ENDPOINT_URI)
				.queryParams(getAuthorizationRequestParameters(registeredClient))
				.with(user("user")))
			.andExpect(status().is3xxRedirection())
			.andReturn();
		String redirectedUrl = mvcResult.getResponse().getRedirectedUrl();
		assertThat(redirectedUrl).matches("http://localhost/oauth2/consent\\?scope=.+&client_id=.+&state=.+");

		String locationHeader = URLDecoder.decode(redirectedUrl, StandardCharsets.UTF_8.name());
		UriComponents uriComponents = UriComponentsBuilder.fromUriString(locationHeader).build();
		MultiValueMap<String, String> redirectQueryParams = uriComponents.getQueryParams();

		assertThat(uriComponents.getPath()).isEqualTo(consentPage);
		assertThat(redirectQueryParams.getFirst(OAuth2ParameterNames.SCOPE)).isEqualTo("message.read message.write");
		assertThat(redirectQueryParams.getFirst(OAuth2ParameterNames.CLIENT_ID))
			.isEqualTo(registeredClient.getClientId());

		String state = extractParameterFromRedirectUri(redirectedUrl, "state");
		OAuth2Authorization authorization = this.authorizationService.findByToken(state, STATE_TOKEN_TYPE);
		assertThat(authorization).isNotNull();
	}

	@Test
	public void requestWhenCustomConsentCustomizerConfiguredThenUsed() throws Exception {
		this.spring.register(AuthorizationServerConfigurationCustomConsentRequest.class).autowire();

		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
			.clientSettings(ClientSettings.builder()
				.requireAuthorizationConsent(true)
				.setting("custom.allowed-authorities", "authority-1 authority-2")
				.build())
			.build();
		this.registeredClientRepository.save(registeredClient);

		OAuth2Authorization authorization = createAuthorization(registeredClient);
		OAuth2AuthorizationRequest authorizationRequest = authorization
			.getAttribute(OAuth2AuthorizationRequest.class.getName());
		OAuth2AuthorizationRequest updatedAuthorizationRequest = OAuth2AuthorizationRequest.from(authorizationRequest)
			.state(STATE_URL_UNENCODED)
			.build();
		authorization = OAuth2Authorization.from(authorization)
			.attribute(OAuth2AuthorizationRequest.class.getName(), updatedAuthorizationRequest)
			.build();
		this.authorizationService.save(authorization);

		MvcResult mvcResult = this.mvc
			.perform(post(DEFAULT_AUTHORIZATION_ENDPOINT_URI)
				.param(OAuth2ParameterNames.CLIENT_ID, registeredClient.getClientId())
				.param("authority", "authority-1 authority-2")
				.param(OAuth2ParameterNames.STATE, authorization.<String>getAttribute(OAuth2ParameterNames.STATE))
				.with(user("principal")))
			.andExpect(status().is3xxRedirection())
			.andReturn();

		String redirectedUrl = mvcResult.getResponse().getRedirectedUrl();
		assertThat(redirectedUrl)
			.matches(authorizationRequest.getRedirectUri() + "\\?code=.{15,}&state=" + STATE_URL_ENCODED);

		String authorizationCode = extractParameterFromRedirectUri(redirectedUrl, "code");
		OAuth2Authorization authorizationCodeAuthorization = this.authorizationService.findByToken(authorizationCode,
				AUTHORIZATION_CODE_TOKEN_TYPE);

		mvcResult = this.mvc
			.perform(post(DEFAULT_TOKEN_ENDPOINT_URI)
				.params(getTokenRequestParameters(registeredClient, authorizationCodeAuthorization))
				.header(HttpHeaders.AUTHORIZATION, getAuthorizationHeader(registeredClient)))
			.andExpect(status().isOk())
			.andExpect(header().string(HttpHeaders.CACHE_CONTROL, containsString("no-store")))
			.andExpect(header().string(HttpHeaders.PRAGMA, containsString("no-cache")))
			.andExpect(jsonPath("$.access_token").isNotEmpty())
			.andExpect(jsonPath("$.access_token").value(new AssertionMatcher<String>() {
				@Override
				public void assertion(String accessToken) throws AssertionError {
					Jwt jwt = OAuth2AuthorizationCodeGrantTests.this.jwtDecoder.decode(accessToken);
					assertThat(jwt.getClaimAsStringList(AUTHORITIES_CLAIM)).containsExactlyInAnyOrder("authority-1",
							"authority-2");
				}
			}))
			.andExpect(jsonPath("$.token_type").isNotEmpty())
			.andExpect(jsonPath("$.expires_in").isNotEmpty())
			.andExpect(jsonPath("$.refresh_token").isNotEmpty())
			.andExpect(jsonPath("$.scope").doesNotExist())
			.andReturn();
	}

	@Test
	public void requestWhenAuthorizationEndpointCustomizedThenUsed() throws Exception {
		this.spring.register(AuthorizationServerConfigurationCustomAuthorizationEndpoint.class).autowire();

		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		this.registeredClientRepository.save(registeredClient);

		TestingAuthenticationToken principal = new TestingAuthenticationToken("principalName", "password");
		Map<String, Object> additionalParameters = new HashMap<>();
		additionalParameters.put(PkceParameterNames.CODE_CHALLENGE, S256_CODE_CHALLENGE);
		additionalParameters.put(PkceParameterNames.CODE_CHALLENGE_METHOD, "S256");
		OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication = new OAuth2AuthorizationCodeRequestAuthenticationToken(
				"https://provider.com/oauth2/authorize", registeredClient.getClientId(), principal,
				registeredClient.getRedirectUris().iterator().next(), STATE_URL_UNENCODED, registeredClient.getScopes(),
				additionalParameters);
		OAuth2AuthorizationCode authorizationCode = new OAuth2AuthorizationCode("code", Instant.now(),
				Instant.now().plus(5, ChronoUnit.MINUTES));
		OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthenticationResult = new OAuth2AuthorizationCodeRequestAuthenticationToken(
				"https://provider.com/oauth2/authorize", registeredClient.getClientId(), principal, authorizationCode,
				registeredClient.getRedirectUris().iterator().next(), STATE_URL_UNENCODED,
				registeredClient.getScopes());
		given(authorizationRequestConverter.convert(any())).willReturn(authorizationCodeRequestAuthentication);
		given(authorizationRequestAuthenticationProvider
			.supports(eq(OAuth2AuthorizationCodeRequestAuthenticationToken.class))).willReturn(true);
		given(authorizationRequestAuthenticationProvider.authenticate(any()))
			.willReturn(authorizationCodeRequestAuthenticationResult);

		this.mvc
			.perform(get(DEFAULT_AUTHORIZATION_ENDPOINT_URI)
				.queryParams(getAuthorizationRequestParameters(registeredClient))
				.with(user("user")))
			.andExpect(status().isOk());

		verify(authorizationRequestConverter).convert(any());

		@SuppressWarnings("unchecked")
		ArgumentCaptor<List<AuthenticationConverter>> authenticationConvertersCaptor = ArgumentCaptor
			.forClass(List.class);
		verify(authorizationRequestConvertersConsumer).accept(authenticationConvertersCaptor.capture());
		List<AuthenticationConverter> authenticationConverters = authenticationConvertersCaptor.getValue();
		assertThat(authenticationConverters).allMatch((converter) -> converter == authorizationRequestConverter
				|| converter instanceof OAuth2AuthorizationCodeRequestAuthenticationConverter
				|| converter instanceof OAuth2AuthorizationConsentAuthenticationConverter);

		verify(authorizationRequestAuthenticationProvider).authenticate(eq(authorizationCodeRequestAuthentication));

		@SuppressWarnings("unchecked")
		ArgumentCaptor<List<AuthenticationProvider>> authenticationProvidersCaptor = ArgumentCaptor
			.forClass(List.class);
		verify(authorizationRequestAuthenticationProvidersConsumer).accept(authenticationProvidersCaptor.capture());
		List<AuthenticationProvider> authenticationProviders = authenticationProvidersCaptor.getValue();
		assertThat(authenticationProviders)
			.allMatch((provider) -> provider == authorizationRequestAuthenticationProvider
					|| provider instanceof OAuth2AuthorizationCodeRequestAuthenticationProvider
					|| provider instanceof OAuth2AuthorizationConsentAuthenticationProvider);

		verify(authorizationResponseHandler).onAuthenticationSuccess(any(), any(),
				eq(authorizationCodeRequestAuthenticationResult));
	}

	// gh-482
	@Test
	public void requestWhenClientObtainsAccessTokenThenClientAuthenticationNotPersisted() throws Exception {
		this.spring.register(AuthorizationServerConfigurationWithSecurityContextRepository.class).autowire();

		RegisteredClient registeredClient = TestRegisteredClients.registeredPublicClient().build();
		this.registeredClientRepository.save(registeredClient);

		MvcResult mvcResult = this.mvc
			.perform(get(DEFAULT_AUTHORIZATION_ENDPOINT_URI)
				.queryParams(getAuthorizationRequestParameters(registeredClient))
				.with(user("user")))
			.andExpect(status().is3xxRedirection())
			.andReturn();

		ArgumentCaptor<org.springframework.security.core.context.SecurityContext> securityContextCaptor = ArgumentCaptor
			.forClass(org.springframework.security.core.context.SecurityContext.class);
		verify(securityContextRepository, times(1)).saveContext(securityContextCaptor.capture(), any(), any());
		assertThat(securityContextCaptor.getValue().getAuthentication())
			.isInstanceOf(UsernamePasswordAuthenticationToken.class);
		reset(securityContextRepository);

		String authorizationCode = extractParameterFromRedirectUri(mvcResult.getResponse().getRedirectedUrl(), "code");
		OAuth2Authorization authorizationCodeAuthorization = this.authorizationService.findByToken(authorizationCode,
				AUTHORIZATION_CODE_TOKEN_TYPE);

		mvcResult = this.mvc
			.perform(post(DEFAULT_TOKEN_ENDPOINT_URI)
				.params(getTokenRequestParameters(registeredClient, authorizationCodeAuthorization))
				.param(OAuth2ParameterNames.CLIENT_ID, registeredClient.getClientId()))
			.andExpect(header().string(HttpHeaders.CACHE_CONTROL, containsString("no-store")))
			.andExpect(header().string(HttpHeaders.PRAGMA, containsString("no-cache")))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.access_token").isNotEmpty())
			.andExpect(jsonPath("$.token_type").isNotEmpty())
			.andExpect(jsonPath("$.expires_in").isNotEmpty())
			.andExpect(jsonPath("$.refresh_token").doesNotExist())
			.andExpect(jsonPath("$.scope").isNotEmpty())
			.andReturn();

		org.springframework.security.core.context.SecurityContext securityContext = securityContextRepository
			.loadDeferredContext(mvcResult.getRequest())
			.get();
		assertThat(securityContext.getAuthentication()).isNull();
	}

	@Test
	public void requestWhenAuthorizationAndTokenRequestIncludesIssuerPathThenIssuerResolvedWithPath() throws Exception {
		this.spring.register(AuthorizationServerConfigurationWithMultipleIssuersAllowed.class).autowire();

		RegisteredClient registeredClient = TestRegisteredClients.registeredPublicClient().build();
		this.registeredClientRepository.save(registeredClient);

		String issuer = "https://example.com:8443/issuer1";

		MvcResult mvcResult = this.mvc
			.perform(get(issuer.concat(DEFAULT_AUTHORIZATION_ENDPOINT_URI))
				.queryParams(getAuthorizationRequestParameters(registeredClient))
				.with(user("user")))
			.andExpect(status().is3xxRedirection())
			.andReturn();

		String authorizationCode = extractParameterFromRedirectUri(mvcResult.getResponse().getRedirectedUrl(), "code");
		OAuth2Authorization authorizationCodeAuthorization = this.authorizationService.findByToken(authorizationCode,
				AUTHORIZATION_CODE_TOKEN_TYPE);

		this.mvc
			.perform(post(issuer.concat(DEFAULT_TOKEN_ENDPOINT_URI))
				.params(getTokenRequestParameters(registeredClient, authorizationCodeAuthorization))
				.param(OAuth2ParameterNames.CLIENT_ID, registeredClient.getClientId()))
			.andExpect(header().string(HttpHeaders.CACHE_CONTROL, containsString("no-store")))
			.andExpect(header().string(HttpHeaders.PRAGMA, containsString("no-cache")))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.access_token").isNotEmpty())
			.andExpect(jsonPath("$.token_type").isNotEmpty())
			.andExpect(jsonPath("$.expires_in").isNotEmpty())
			.andExpect(jsonPath("$.refresh_token").doesNotExist())
			.andExpect(jsonPath("$.scope").isNotEmpty())
			.andReturn();

		ArgumentCaptor<OAuth2TokenContext> tokenContextCaptor = ArgumentCaptor.forClass(OAuth2TokenContext.class);
		verify(this.tokenGenerator).generate(tokenContextCaptor.capture());
		OAuth2TokenContext tokenContext = tokenContextCaptor.getValue();
		assertThat(tokenContext.getAuthorizationServerContext().getIssuer()).isEqualTo(issuer);
	}

	@Test
	public void requestWhenTokenRequestWithDPoPProofThenReturnDPoPBoundAccessToken() throws Exception {
		this.spring.register(AuthorizationServerConfiguration.class).autowire();

		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		this.registeredClientRepository.save(registeredClient);

		OAuth2Authorization authorization = createAuthorization(registeredClient);
		this.authorizationService.save(authorization);

		String tokenEndpointUri = "http://localhost" + DEFAULT_TOKEN_ENDPOINT_URI;
		String dPoPProof = generateDPoPProof(tokenEndpointUri);

		this.mvc
			.perform(post(DEFAULT_TOKEN_ENDPOINT_URI).params(getTokenRequestParameters(registeredClient, authorization))
				.header(HttpHeaders.AUTHORIZATION, getAuthorizationHeader(registeredClient))
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
	public void requestWhenPushedAuthorizationRequestThenReturnAccessTokenResponse() throws Exception {
		this.spring.register(AuthorizationServerConfigurationWithPushedAuthorizationRequests.class).autowire();

		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		this.registeredClientRepository.save(registeredClient);

		MvcResult mvcResult = this.mvc
			.perform(post("/oauth2/par").params(getAuthorizationRequestParameters(registeredClient))
				.header(HttpHeaders.AUTHORIZATION, getAuthorizationHeader(registeredClient)))
			.andExpect(header().string(HttpHeaders.CACHE_CONTROL, containsString("no-store")))
			.andExpect(header().string(HttpHeaders.PRAGMA, containsString("no-cache")))
			.andExpect(status().isCreated())
			.andExpect(jsonPath("$.request_uri").isNotEmpty())
			.andExpect(jsonPath("$.expires_in").isNotEmpty())
			.andReturn();

		String requestUri = JsonPath.read(mvcResult.getResponse().getContentAsString(), "$.request_uri");

		mvcResult = this.mvc
			.perform(get(DEFAULT_AUTHORIZATION_ENDPOINT_URI)
				.queryParam(OAuth2ParameterNames.CLIENT_ID, registeredClient.getClientId())
				.queryParam(OAuth2ParameterNames.REQUEST_URI, requestUri)
				.with(user("user")))
			.andExpect(status().is3xxRedirection())
			.andReturn();

		String authorizationCode = extractParameterFromRedirectUri(mvcResult.getResponse().getRedirectedUrl(), "code");
		OAuth2Authorization authorizationCodeAuthorization = this.authorizationService.findByToken(authorizationCode,
				AUTHORIZATION_CODE_TOKEN_TYPE);

		this.mvc
			.perform(post(DEFAULT_TOKEN_ENDPOINT_URI)
				.params(getTokenRequestParameters(registeredClient, authorizationCodeAuthorization))
				.param(OAuth2ParameterNames.CLIENT_ID, registeredClient.getClientId())
				.header(HttpHeaders.AUTHORIZATION, getAuthorizationHeader(registeredClient)))
			.andExpect(header().string(HttpHeaders.CACHE_CONTROL, containsString("no-store")))
			.andExpect(header().string(HttpHeaders.PRAGMA, containsString("no-cache")))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.access_token").isNotEmpty())
			.andExpect(jsonPath("$.token_type").isNotEmpty())
			.andExpect(jsonPath("$.expires_in").isNotEmpty())
			.andExpect(jsonPath("$.refresh_token").isNotEmpty())
			.andExpect(jsonPath("$.scope").isNotEmpty())
			.andReturn();

		OAuth2Authorization accessTokenAuthorization = this.authorizationService
			.findById(authorizationCodeAuthorization.getId());
		assertThat(accessTokenAuthorization).isNotNull();
		assertThat(accessTokenAuthorization.getAccessToken()).isNotNull();

		OAuth2Authorization.Token<OAuth2AuthorizationCode> authorizationCodeToken = accessTokenAuthorization
			.getToken(OAuth2AuthorizationCode.class);
		assertThat(authorizationCodeToken).isNotNull();
		assertThat(authorizationCodeToken.getMetadata().get(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME))
			.isEqualTo(true);
	}

	// gh-2182
	@Test
	public void requestWhenPushedAuthorizationRequestAndRequiresConsentThenDisplaysConsentPage() throws Exception {
		this.spring.register(AuthorizationServerConfigurationWithPushedAuthorizationRequests.class).autowire();

		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().scopes((scopes) -> {
			scopes.clear();
			scopes.add("message.read");
			scopes.add("message.write");
		}).clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build()).build();
		this.registeredClientRepository.save(registeredClient);

		MvcResult mvcResult = this.mvc
			.perform(post("/oauth2/par").params(getAuthorizationRequestParameters(registeredClient))
				.header(HttpHeaders.AUTHORIZATION, getAuthorizationHeader(registeredClient)))
			.andExpect(header().string(HttpHeaders.CACHE_CONTROL, containsString("no-store")))
			.andExpect(header().string(HttpHeaders.PRAGMA, containsString("no-cache")))
			.andExpect(status().isCreated())
			.andExpect(jsonPath("$.request_uri").isNotEmpty())
			.andExpect(jsonPath("$.expires_in").isNotEmpty())
			.andReturn();

		String requestUri = JsonPath.read(mvcResult.getResponse().getContentAsString(), "$.request_uri");

		String consentPage = this.mvc
			.perform(get(DEFAULT_AUTHORIZATION_ENDPOINT_URI)
				.queryParam(OAuth2ParameterNames.CLIENT_ID, registeredClient.getClientId())
				.queryParam(OAuth2ParameterNames.REQUEST_URI, requestUri)
				.with(user("user")))
			.andExpect(status().is2xxSuccessful())
			.andReturn()
			.getResponse()
			.getContentAsString();

		assertThat(consentPage).contains("Consent required");
		assertThat(consentPage).contains(scopeCheckbox("message.read"));
		assertThat(consentPage).contains(scopeCheckbox("message.write"));
	}

	// gh-2182
	@Test
	public void requestWhenPushedAuthorizationRequestAndCustomConsentPageConfiguredThenRedirect() throws Exception {
		this.spring.register(AuthorizationServerConfigurationWithPushedAuthorizationRequestsAndCustomConsentPage.class)
			.autowire();

		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().scopes((scopes) -> {
			scopes.clear();
			scopes.add("message.read");
			scopes.add("message.write");
		}).clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build()).build();
		this.registeredClientRepository.save(registeredClient);

		MvcResult mvcResult = this.mvc
			.perform(post("/oauth2/par").params(getAuthorizationRequestParameters(registeredClient))
				.header(HttpHeaders.AUTHORIZATION, getAuthorizationHeader(registeredClient)))
			.andExpect(header().string(HttpHeaders.CACHE_CONTROL, containsString("no-store")))
			.andExpect(header().string(HttpHeaders.PRAGMA, containsString("no-cache")))
			.andExpect(status().isCreated())
			.andExpect(jsonPath("$.request_uri").isNotEmpty())
			.andExpect(jsonPath("$.expires_in").isNotEmpty())
			.andReturn();

		String requestUri = JsonPath.read(mvcResult.getResponse().getContentAsString(), "$.request_uri");

		mvcResult = this.mvc
			.perform(get(DEFAULT_AUTHORIZATION_ENDPOINT_URI)
				.queryParam(OAuth2ParameterNames.CLIENT_ID, registeredClient.getClientId())
				.queryParam(OAuth2ParameterNames.REQUEST_URI, requestUri)
				.with(user("user")))
			.andExpect(status().is3xxRedirection())
			.andReturn();
		String redirectedUrl = mvcResult.getResponse().getRedirectedUrl();
		assertThat(redirectedUrl).matches("http://localhost/oauth2/consent\\?scope=.+&client_id=.+&state=.+");

		String locationHeader = URLDecoder.decode(redirectedUrl, StandardCharsets.UTF_8.name());
		UriComponents uriComponents = UriComponentsBuilder.fromUriString(locationHeader).build();
		MultiValueMap<String, String> redirectQueryParams = uriComponents.getQueryParams();

		assertThat(uriComponents.getPath()).isEqualTo(consentPage);
		assertThat(redirectQueryParams.getFirst(OAuth2ParameterNames.SCOPE)).isEqualTo("message.read message.write");
		assertThat(redirectQueryParams.getFirst(OAuth2ParameterNames.CLIENT_ID))
			.isEqualTo(registeredClient.getClientId());

		String state = extractParameterFromRedirectUri(redirectedUrl, "state");
		OAuth2Authorization authorization = this.authorizationService.findByToken(state, STATE_TOKEN_TYPE);
		assertThat(authorization).isNotNull();
	}

	private static OAuth2Authorization createAuthorization(RegisteredClient registeredClient) {
		Map<String, Object> additionalParameters = new HashMap<>();
		additionalParameters.put(PkceParameterNames.CODE_CHALLENGE, S256_CODE_CHALLENGE);
		additionalParameters.put(PkceParameterNames.CODE_CHALLENGE_METHOD, "S256");
		return TestOAuth2Authorizations.authorization(registeredClient, additionalParameters).build();
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

	private static MultiValueMap<String, String> getAuthorizationRequestParameters(RegisteredClient registeredClient) {
		MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
		parameters.set(OAuth2ParameterNames.RESPONSE_TYPE, OAuth2AuthorizationResponseType.CODE.getValue());
		parameters.set(OAuth2ParameterNames.CLIENT_ID, registeredClient.getClientId());
		parameters.set(OAuth2ParameterNames.REDIRECT_URI, registeredClient.getRedirectUris().iterator().next());
		parameters.set(OAuth2ParameterNames.SCOPE,
				StringUtils.collectionToDelimitedString(registeredClient.getScopes(), " "));
		parameters.set(OAuth2ParameterNames.STATE, STATE_URL_UNENCODED);
		parameters.set(PkceParameterNames.CODE_CHALLENGE, S256_CODE_CHALLENGE);
		parameters.set(PkceParameterNames.CODE_CHALLENGE_METHOD, "S256");
		return parameters;
	}

	private static MultiValueMap<String, String> getTokenRequestParameters(RegisteredClient registeredClient,
			OAuth2Authorization authorization) {
		MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
		parameters.set(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.AUTHORIZATION_CODE.getValue());
		parameters.set(OAuth2ParameterNames.CODE,
				authorization.getToken(OAuth2AuthorizationCode.class).getToken().getTokenValue());
		parameters.set(OAuth2ParameterNames.REDIRECT_URI, registeredClient.getRedirectUris().iterator().next());
		parameters.set(PkceParameterNames.CODE_VERIFIER, S256_CODE_VERIFIER);
		return parameters;
	}

	private static String getAuthorizationHeader(RegisteredClient registeredClient) throws Exception {
		String clientId = registeredClient.getClientId();
		String clientSecret = registeredClient.getClientSecret();
		clientId = URLEncoder.encode(clientId, StandardCharsets.UTF_8);
		clientSecret = URLEncoder.encode(clientSecret, StandardCharsets.UTF_8);
		String credentialsString = clientId + ":" + clientSecret;
		byte[] encodedBytes = Base64.getEncoder().encode(credentialsString.getBytes(StandardCharsets.UTF_8));
		return "Basic " + new String(encodedBytes, StandardCharsets.UTF_8);
	}

	private static String scopeCheckbox(String scope) {
		return MessageFormat.format(
				"<input class=\"form-check-input\" type=\"checkbox\" name=\"scope\" value=\"{0}\" id=\"{0}\">", scope);
	}

	private String extractParameterFromRedirectUri(String redirectUri, String param)
			throws UnsupportedEncodingException {
		String locationHeader = URLDecoder.decode(redirectUri, StandardCharsets.UTF_8.name());
		UriComponents uriComponents = UriComponentsBuilder.fromUriString(locationHeader).build();
		return uriComponents.getQueryParams().getFirst(param);
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
		JWKSource<SecurityContext> jwkSource() {
			return jwkSource;
		}

		@Bean
		JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
			return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
		}

		@Bean
		OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer() {
			return (context) -> {
				if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(context.getAuthorizationGrantType())
						&& OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
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
	@Import(OAuth2AuthorizationServerConfiguration.class)
	static class AuthorizationServerConfigurationWithCustomRefreshTokenGenerator
			extends AuthorizationServerConfiguration {

		@Bean
		JwtEncoder jwtEncoder() {
			return jwtEncoder;
		}

		@Bean
		OAuth2TokenGenerator<?> tokenGenerator() {
			JwtGenerator jwtGenerator = new JwtGenerator(jwtEncoder());
			jwtGenerator.setJwtCustomizer(jwtCustomizer());
			OAuth2TokenGenerator<OAuth2RefreshToken> refreshTokenGenerator = new CustomRefreshTokenGenerator();
			return new DelegatingOAuth2TokenGenerator(jwtGenerator, refreshTokenGenerator);
		}

		private static final class CustomRefreshTokenGenerator implements OAuth2TokenGenerator<OAuth2RefreshToken> {

			private final StringKeyGenerator refreshTokenGenerator = new Base64StringKeyGenerator(
					Base64.getUrlEncoder().withoutPadding(), 96);

			@Nullable
			@Override
			public OAuth2RefreshToken generate(OAuth2TokenContext context) {
				if (!OAuth2TokenType.REFRESH_TOKEN.equals(context.getTokenType())) {
					return null;
				}
				Instant issuedAt = Instant.now();
				Instant expiresAt = issuedAt
					.plus(context.getRegisteredClient().getTokenSettings().getRefreshTokenTimeToLive());
				return new OAuth2RefreshToken(this.refreshTokenGenerator.generateKey(), issuedAt, expiresAt);
			}

		}

	}

	@EnableWebSecurity
	@Configuration(proxyBeanMethods = false)
	static class AuthorizationServerConfigurationWithSecurityContextRepository
			extends AuthorizationServerConfiguration {

		// @formatter:off
		@Bean
		SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
			http
					.oauth2AuthorizationServer(Customizer.withDefaults())
					.authorizeHttpRequests((authorize) ->
							authorize.anyRequest().authenticated()
					)
					.securityContext((securityContext) ->
							securityContext.securityContextRepository(securityContextRepository));
			return http.build();
		}
		// @formatter:on

	}

	@EnableWebSecurity
	@Import(OAuth2AuthorizationServerConfiguration.class)
	static class AuthorizationServerConfigurationWithTokenGenerator extends AuthorizationServerConfiguration {

		@Bean
		JwtEncoder jwtEncoder() {
			return jwtEncoder;
		}

		@Bean
		OAuth2TokenGenerator<?> tokenGenerator() {
			JwtGenerator jwtGenerator = new JwtGenerator(jwtEncoder());
			jwtGenerator.setJwtCustomizer(jwtCustomizer());
			OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();
			OAuth2TokenGenerator<OAuth2Token> delegatingTokenGenerator = new DelegatingOAuth2TokenGenerator(
					jwtGenerator, refreshTokenGenerator);
			return spy(new OAuth2TokenGenerator<OAuth2Token>() {
				@Override
				public OAuth2Token generate(OAuth2TokenContext context) {
					return delegatingTokenGenerator.generate(context);
				}
			});
		}

	}

	@EnableWebSecurity
	@Import(OAuth2AuthorizationServerConfiguration.class)
	static class AuthorizationServerConfigurationCustomEndpoints extends AuthorizationServerConfiguration {

		@Bean
		AuthorizationServerSettings authorizationServerSettings() {
			return authorizationServerSettings;
		}

	}

	@EnableWebSecurity
	@Configuration(proxyBeanMethods = false)
	static class AuthorizationServerConfigurationCustomConsentPage extends AuthorizationServerConfiguration {

		// @formatter:off
		@Bean
		SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
			http
					.oauth2AuthorizationServer((authorizationServer) ->
							authorizationServer
									.authorizationEndpoint((authorizationEndpoint) ->
											authorizationEndpoint.consentPage(consentPage))
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
	static class AuthorizationServerConfigurationCustomConsentRequest extends AuthorizationServerConfiguration {

		@Autowired
		private OAuth2AuthorizationConsentService authorizationConsentService;

		// @formatter:off
		@Bean
		SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
			http
					.oauth2AuthorizationServer((authorizationServer) ->
							authorizationServer
									.authorizationEndpoint((authorizationEndpoint) ->
											authorizationEndpoint.authenticationProviders(configureAuthenticationProviders()))
					)
					.authorizeHttpRequests((authorize) ->
							authorize.anyRequest().authenticated()
					);
			return http.build();
		}
		// @formatter:on

		@Bean
		@Override
		OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer() {
			return (context) -> {
				if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(context.getAuthorizationGrantType())
						&& OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
					OAuth2AuthorizationConsent authorizationConsent = this.authorizationConsentService
						.findById(context.getRegisteredClient().getId(), context.getPrincipal().getName());

					Set<String> authorities = new HashSet<>();
					for (GrantedAuthority authority : authorizationConsent.getAuthorities()) {
						authorities.add(authority.getAuthority());
					}
					context.getClaims().claim(AUTHORITIES_CLAIM, authorities);
				}
			};
		}

		private Consumer<List<AuthenticationProvider>> configureAuthenticationProviders() {
			return (authenticationProviders) -> authenticationProviders.forEach((authenticationProvider) -> {
				if (authenticationProvider instanceof OAuth2AuthorizationConsentAuthenticationProvider) {
					((OAuth2AuthorizationConsentAuthenticationProvider) authenticationProvider)
						.setAuthorizationConsentCustomizer(new AuthorizationConsentCustomizer());
				}
			});
		}

		static class AuthorizationConsentCustomizer
				implements Consumer<OAuth2AuthorizationConsentAuthenticationContext> {

			@Override
			public void accept(
					OAuth2AuthorizationConsentAuthenticationContext authorizationConsentAuthenticationContext) {
				OAuth2AuthorizationConsent.Builder authorizationConsentBuilder = authorizationConsentAuthenticationContext
					.getAuthorizationConsent();
				OAuth2AuthorizationConsentAuthenticationToken authorizationConsentAuthentication = authorizationConsentAuthenticationContext
					.getAuthentication();
				Map<String, Object> additionalParameters = authorizationConsentAuthentication.getAdditionalParameters();
				RegisteredClient registeredClient = authorizationConsentAuthenticationContext.getRegisteredClient();
				ClientSettings clientSettings = registeredClient.getClientSettings();

				Set<String> requestedAuthorities = authorities((String) additionalParameters.get("authority"));
				Set<String> allowedAuthorities = authorities(clientSettings.getSetting("custom.allowed-authorities"));
				for (String requestedAuthority : requestedAuthorities) {
					if (allowedAuthorities.contains(requestedAuthority)) {
						authorizationConsentBuilder.authority(new SimpleGrantedAuthority(requestedAuthority));
					}
				}
			}

			private static Set<String> authorities(String param) {
				Set<String> authorities = new HashSet<>();
				if (param != null) {
					List<String> authorityValues = Arrays.asList(param.split(" "));
					authorities.addAll(authorityValues);
				}

				return authorities;
			}

		}

	}

	@EnableWebSecurity
	@Configuration(proxyBeanMethods = false)
	static class AuthorizationServerConfigurationCustomAuthorizationEndpoint extends AuthorizationServerConfiguration {

		// @formatter:off
		@Bean
		SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
			http
					.oauth2AuthorizationServer((authorizationServer) ->
							authorizationServer
									.authorizationEndpoint((authorizationEndpoint) ->
											authorizationEndpoint
													.authorizationRequestConverter(authorizationRequestConverter)
													.authorizationRequestConverters(authorizationRequestConvertersConsumer)
													.authenticationProvider(authorizationRequestAuthenticationProvider)
													.authenticationProviders(authorizationRequestAuthenticationProvidersConsumer)
													.authorizationResponseHandler(authorizationResponseHandler)
													.errorResponseHandler(authorizationErrorResponseHandler))
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
	static class AuthorizationServerConfigurationWithMultipleIssuersAllowed
			extends AuthorizationServerConfigurationWithTokenGenerator {

		@Bean
		AuthorizationServerSettings authorizationServerSettings() {
			return AuthorizationServerSettings.builder().multipleIssuersAllowed(true).build();
		}

	}

	@EnableWebSecurity
	@Configuration(proxyBeanMethods = false)
	static class AuthorizationServerConfigurationWithPushedAuthorizationRequests
			extends AuthorizationServerConfiguration {

		// @formatter:off
		@Bean
		SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
			http
					.oauth2AuthorizationServer((authorizationServer) ->
							authorizationServer
									.pushedAuthorizationRequestEndpoint(Customizer.withDefaults())
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
	static class AuthorizationServerConfigurationWithPushedAuthorizationRequestsAndCustomConsentPage
			extends AuthorizationServerConfiguration {

		// @formatter:off
		@Bean
		SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
			http
					.oauth2AuthorizationServer((authorizationServer) ->
							authorizationServer
									.pushedAuthorizationRequestEndpoint(Customizer.withDefaults())
									.authorizationEndpoint((authorizationEndpoint) ->
											authorizationEndpoint.consentPage(consentPage))
					)
					.authorizeHttpRequests((authorize) ->
							authorize.anyRequest().authenticated()
					);
			return http.build();
		}
		// @formatter:on

	}

}
