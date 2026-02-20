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
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

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
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabase;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.lang.Nullable;
import org.springframework.mock.http.client.MockClientHttpResponse;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.jose.TestJwks;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.TestOAuth2Authorizations;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository.RegisteredClientParametersMapper;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2RefreshTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.CoreMatchers.containsString;
import static org.mockito.ArgumentMatchers.any;
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
 * Integration tests for OpenID Connect 1.0.
 *
 * @author Daniel Garnier-Moiroux
 * @author Joe Grandja
 */
@ExtendWith(SpringTestContextExtension.class)
public class OidcTests {

	private static final String DEFAULT_AUTHORIZATION_ENDPOINT_URI = "/oauth2/authorize";

	private static final String DEFAULT_TOKEN_ENDPOINT_URI = "/oauth2/token";

	private static final String DEFAULT_OIDC_LOGOUT_ENDPOINT_URI = "/connect/logout";

	// See RFC 7636: Appendix B. Example for the S256 code_challenge_method
	// https://tools.ietf.org/html/rfc7636#appendix-B
	private static final String S256_CODE_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

	private static final String S256_CODE_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

	private static final String AUTHORITIES_CLAIM = "authorities";

	private static final OAuth2TokenType AUTHORIZATION_CODE_TOKEN_TYPE = new OAuth2TokenType(OAuth2ParameterNames.CODE);

	private static EmbeddedDatabase db;

	private static JWKSource<SecurityContext> jwkSource;

	private static HttpMessageConverter<OAuth2AccessTokenResponse> accessTokenHttpResponseConverter = new OAuth2AccessTokenResponseHttpMessageConverter();

	private static SessionRegistry sessionRegistry;

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
		db = new EmbeddedDatabaseBuilder().generateUniqueName(true)
			.setType(EmbeddedDatabaseType.HSQL)
			.setScriptEncoding("UTF-8")
			.addScript("org/springframework/security/oauth2/server/authorization/oauth2-authorization-schema.sql")
			.addScript(
					"org/springframework/security/oauth2/server/authorization/client/oauth2-registered-client-schema.sql")
			.build();
		sessionRegistry = spy(new SessionRegistryImpl());
	}

	@AfterEach
	public void tearDown() {
		if (this.jdbcOperations != null) {
			this.jdbcOperations.update("truncate table oauth2_authorization");
			this.jdbcOperations.update("truncate table oauth2_registered_client");
		}
	}

	@AfterAll
	public static void destroy() {
		db.shutdown();
	}

	@Test
	public void requestWhenAuthenticationRequestThenTokenResponseIncludesIdToken() throws Exception {
		this.spring.register(AuthorizationServerConfiguration.class).autowire();

		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().scope(OidcScopes.OPENID).build();
		this.registeredClientRepository.save(registeredClient);

		MultiValueMap<String, String> authorizationRequestParameters = getAuthorizationRequestParameters(
				registeredClient);
		MvcResult mvcResult = this.mvc
			.perform(get(DEFAULT_AUTHORIZATION_ENDPOINT_URI).queryParams(authorizationRequestParameters)
				.with(user("user").roles("A", "B")))
			.andExpect(status().is3xxRedirection())
			.andReturn();
		String redirectedUrl = mvcResult.getResponse().getRedirectedUrl();
		String expectedRedirectUri = authorizationRequestParameters.getFirst(OAuth2ParameterNames.REDIRECT_URI);
		assertThat(redirectedUrl).matches(expectedRedirectUri + "\\?code=.{15,}&state=state");

		String authorizationCode = extractParameterFromRedirectUri(redirectedUrl, "code");
		OAuth2Authorization authorization = this.authorizationService.findByToken(authorizationCode,
				AUTHORIZATION_CODE_TOKEN_TYPE);

		mvcResult = this.mvc
			.perform(post(DEFAULT_TOKEN_ENDPOINT_URI).params(getTokenRequestParameters(registeredClient, authorization))
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
			.andExpect(jsonPath("$.id_token").isNotEmpty())
			.andReturn();

		MockHttpServletResponse servletResponse = mvcResult.getResponse();
		MockClientHttpResponse httpResponse = new MockClientHttpResponse(servletResponse.getContentAsByteArray(),
				HttpStatus.valueOf(servletResponse.getStatus()));
		OAuth2AccessTokenResponse accessTokenResponse = accessTokenHttpResponseConverter
			.read(OAuth2AccessTokenResponse.class, httpResponse);

		Jwt idToken = this.jwtDecoder
			.decode((String) accessTokenResponse.getAdditionalParameters().get(OidcParameterNames.ID_TOKEN));

		// Assert user authorities was propagated as claim in ID Token
		List<String> authoritiesClaim = idToken.getClaim(AUTHORITIES_CLAIM);
		Authentication principal = authorization.getAttribute(Principal.class.getName());
		Set<String> userAuthorities = new HashSet<>();
		for (GrantedAuthority authority : principal.getAuthorities()) {
			userAuthorities.add(authority.getAuthority());
		}
		assertThat(authoritiesClaim).containsExactlyInAnyOrderElementsOf(userAuthorities);

		// Assert sid claim was added in ID Token
		assertThat(idToken.<String>getClaim("sid")).isNotNull();
	}

	// gh-1224
	@Test
	public void requestWhenRefreshTokenRequestThenIdTokenContainsSidClaim() throws Exception {
		this.spring.register(AuthorizationServerConfiguration.class).autowire();

		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().scope(OidcScopes.OPENID).build();
		this.registeredClientRepository.save(registeredClient);

		MultiValueMap<String, String> authorizationRequestParameters = getAuthorizationRequestParameters(
				registeredClient);
		MvcResult mvcResult = this.mvc
			.perform(get(DEFAULT_AUTHORIZATION_ENDPOINT_URI).queryParams(authorizationRequestParameters)
				.with(user("user").roles("A", "B")))
			.andExpect(status().is3xxRedirection())
			.andReturn();
		String redirectedUrl = mvcResult.getResponse().getRedirectedUrl();
		String expectedRedirectUri = authorizationRequestParameters.getFirst(OAuth2ParameterNames.REDIRECT_URI);
		assertThat(redirectedUrl).matches(expectedRedirectUri + "\\?code=.{15,}&state=state");

		String authorizationCode = extractParameterFromRedirectUri(redirectedUrl, "code");
		OAuth2Authorization authorization = this.authorizationService.findByToken(authorizationCode,
				AUTHORIZATION_CODE_TOKEN_TYPE);

		mvcResult = this.mvc
			.perform(post(DEFAULT_TOKEN_ENDPOINT_URI).params(getTokenRequestParameters(registeredClient, authorization))
				.header(HttpHeaders.AUTHORIZATION,
						"Basic " + encodeBasicAuth(registeredClient.getClientId(), registeredClient.getClientSecret())))
			.andExpect(status().isOk())
			.andReturn();

		MockHttpServletResponse servletResponse = mvcResult.getResponse();
		MockClientHttpResponse httpResponse = new MockClientHttpResponse(servletResponse.getContentAsByteArray(),
				HttpStatus.valueOf(servletResponse.getStatus()));
		OAuth2AccessTokenResponse accessTokenResponse = accessTokenHttpResponseConverter
			.read(OAuth2AccessTokenResponse.class, httpResponse);

		Jwt idToken = this.jwtDecoder
			.decode((String) accessTokenResponse.getAdditionalParameters().get(OidcParameterNames.ID_TOKEN));

		String sidClaim = idToken.getClaim("sid");
		assertThat(sidClaim).isNotNull();

		// Refresh access token
		mvcResult = this.mvc
			.perform(post(DEFAULT_TOKEN_ENDPOINT_URI)
				.param(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.REFRESH_TOKEN.getValue())
				.param(OAuth2ParameterNames.REFRESH_TOKEN, accessTokenResponse.getRefreshToken().getTokenValue())
				.header(HttpHeaders.AUTHORIZATION,
						"Basic " + encodeBasicAuth(registeredClient.getClientId(), registeredClient.getClientSecret())))
			.andExpect(status().isOk())
			.andReturn();

		servletResponse = mvcResult.getResponse();
		httpResponse = new MockClientHttpResponse(servletResponse.getContentAsByteArray(),
				HttpStatus.valueOf(servletResponse.getStatus()));
		accessTokenResponse = accessTokenHttpResponseConverter.read(OAuth2AccessTokenResponse.class, httpResponse);

		idToken = this.jwtDecoder
			.decode((String) accessTokenResponse.getAdditionalParameters().get(OidcParameterNames.ID_TOKEN));

		assertThat(idToken.<String>getClaim("sid")).isEqualTo(sidClaim);
	}

	@Test
	public void requestWhenLogoutRequestThenLogout() throws Exception {
		this.spring.register(AuthorizationServerConfiguration.class).autowire();

		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().scope(OidcScopes.OPENID).build();
		this.registeredClientRepository.save(registeredClient);

		String issuer = "https://example.com:8443/issuer1";

		// Login
		MultiValueMap<String, String> authorizationRequestParameters = getAuthorizationRequestParameters(
				registeredClient);
		MvcResult mvcResult = this.mvc
			.perform(get(issuer.concat(DEFAULT_AUTHORIZATION_ENDPOINT_URI)).queryParams(authorizationRequestParameters)
				.with(user("user")))
			.andExpect(status().is3xxRedirection())
			.andReturn();

		MockHttpSession session = (MockHttpSession) mvcResult.getRequest().getSession();
		assertThat(session.isNew()).isTrue();

		String redirectedUrl = mvcResult.getResponse().getRedirectedUrl();
		String authorizationCode = extractParameterFromRedirectUri(redirectedUrl, "code");
		OAuth2Authorization authorization = this.authorizationService.findByToken(authorizationCode,
				AUTHORIZATION_CODE_TOKEN_TYPE);

		// Get ID Token
		mvcResult = this.mvc
			.perform(post(issuer.concat(DEFAULT_TOKEN_ENDPOINT_URI))
				.params(getTokenRequestParameters(registeredClient, authorization))
				.header(HttpHeaders.AUTHORIZATION,
						"Basic " + encodeBasicAuth(registeredClient.getClientId(), registeredClient.getClientSecret())))
			.andExpect(status().isOk())
			.andReturn();

		MockHttpServletResponse servletResponse = mvcResult.getResponse();
		MockClientHttpResponse httpResponse = new MockClientHttpResponse(servletResponse.getContentAsByteArray(),
				HttpStatus.valueOf(servletResponse.getStatus()));
		OAuth2AccessTokenResponse accessTokenResponse = accessTokenHttpResponseConverter
			.read(OAuth2AccessTokenResponse.class, httpResponse);

		String idToken = (String) accessTokenResponse.getAdditionalParameters().get(OidcParameterNames.ID_TOKEN);

		// Logout
		mvcResult = this.mvc
			.perform(post(issuer.concat(DEFAULT_OIDC_LOGOUT_ENDPOINT_URI)).param("id_token_hint", idToken)
				.session(session))
			.andExpect(status().is3xxRedirection())
			.andReturn();
		redirectedUrl = mvcResult.getResponse().getRedirectedUrl();

		assertThat(redirectedUrl).matches("/");
		assertThat(session.isInvalid()).isTrue();
	}

	@Test
	public void requestWhenLogoutRequestWithOtherUsersIdTokenThenNotLogout() throws Exception {
		this.spring.register(AuthorizationServerConfiguration.class).autowire();

		// Login user1
		RegisteredClient registeredClient1 = TestRegisteredClients.registeredClient().scope(OidcScopes.OPENID).build();
		this.registeredClientRepository.save(registeredClient1);

		MultiValueMap<String, String> authorizationRequestParameters = getAuthorizationRequestParameters(
				registeredClient1);
		MvcResult mvcResult = this.mvc
			.perform(get(DEFAULT_AUTHORIZATION_ENDPOINT_URI).queryParams(authorizationRequestParameters)
				.with(user("user1")))
			.andExpect(status().is3xxRedirection())
			.andReturn();

		MockHttpSession user1Session = (MockHttpSession) mvcResult.getRequest().getSession();
		assertThat(user1Session.isNew()).isTrue();

		String redirectedUrl = mvcResult.getResponse().getRedirectedUrl();
		String authorizationCode = extractParameterFromRedirectUri(redirectedUrl, "code");
		OAuth2Authorization user1Authorization = this.authorizationService.findByToken(authorizationCode,
				AUTHORIZATION_CODE_TOKEN_TYPE);

		mvcResult = this.mvc
			.perform(post(DEFAULT_TOKEN_ENDPOINT_URI)
				.params(getTokenRequestParameters(registeredClient1, user1Authorization))
				.header(HttpHeaders.AUTHORIZATION,
						"Basic " + encodeBasicAuth(registeredClient1.getClientId(),
								registeredClient1.getClientSecret())))
			.andExpect(status().isOk())
			.andReturn();

		MockHttpServletResponse servletResponse = mvcResult.getResponse();
		MockClientHttpResponse httpResponse = new MockClientHttpResponse(servletResponse.getContentAsByteArray(),
				HttpStatus.valueOf(servletResponse.getStatus()));
		OAuth2AccessTokenResponse accessTokenResponse = accessTokenHttpResponseConverter
			.read(OAuth2AccessTokenResponse.class, httpResponse);

		String user1IdToken = (String) accessTokenResponse.getAdditionalParameters().get(OidcParameterNames.ID_TOKEN);

		// Login user2
		RegisteredClient registeredClient2 = TestRegisteredClients.registeredClient2().scope(OidcScopes.OPENID).build();
		this.registeredClientRepository.save(registeredClient2);

		authorizationRequestParameters = getAuthorizationRequestParameters(registeredClient2);
		mvcResult = this.mvc
			.perform(get(DEFAULT_AUTHORIZATION_ENDPOINT_URI).queryParams(authorizationRequestParameters)
				.with(user("user2")))
			.andExpect(status().is3xxRedirection())
			.andReturn();

		MockHttpSession user2Session = (MockHttpSession) mvcResult.getRequest().getSession();
		assertThat(user2Session.isNew()).isTrue();

		redirectedUrl = mvcResult.getResponse().getRedirectedUrl();
		authorizationCode = extractParameterFromRedirectUri(redirectedUrl, "code");
		OAuth2Authorization user2Authorization = this.authorizationService.findByToken(authorizationCode,
				AUTHORIZATION_CODE_TOKEN_TYPE);

		mvcResult = this.mvc
			.perform(post(DEFAULT_TOKEN_ENDPOINT_URI)
				.params(getTokenRequestParameters(registeredClient2, user2Authorization))
				.header(HttpHeaders.AUTHORIZATION,
						"Basic " + encodeBasicAuth(registeredClient2.getClientId(),
								registeredClient2.getClientSecret())))
			.andExpect(status().isOk())
			.andReturn();

		servletResponse = mvcResult.getResponse();
		httpResponse = new MockClientHttpResponse(servletResponse.getContentAsByteArray(),
				HttpStatus.valueOf(servletResponse.getStatus()));
		accessTokenResponse = accessTokenHttpResponseConverter.read(OAuth2AccessTokenResponse.class, httpResponse);

		String user2IdToken = (String) accessTokenResponse.getAdditionalParameters().get(OidcParameterNames.ID_TOKEN);

		// Attempt to log out user1 using user2's ID Token
		mvcResult = this.mvc
			.perform(post(DEFAULT_OIDC_LOGOUT_ENDPOINT_URI).param("id_token_hint", user2IdToken).session(user1Session))
			.andExpect(status().isBadRequest())
			.andExpect(status().reason("[invalid_token] OpenID Connect 1.0 Logout Request Parameter: sub"))
			.andReturn();

		assertThat(user1Session.isInvalid()).isFalse();
	}

	@Test
	public void requestWhenCustomTokenGeneratorThenUsed() throws Exception {
		this.spring.register(AuthorizationServerConfigurationWithTokenGenerator.class).autowire();

		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().scope(OidcScopes.OPENID).build();
		this.registeredClientRepository.save(registeredClient);

		OAuth2Authorization authorization = createAuthorization(registeredClient);
		this.authorizationService.save(authorization);

		this.mvc
			.perform(post(DEFAULT_TOKEN_ENDPOINT_URI).params(getTokenRequestParameters(registeredClient, authorization))
				.header(HttpHeaders.AUTHORIZATION,
						"Basic " + encodeBasicAuth(registeredClient.getClientId(), registeredClient.getClientSecret())))
			.andExpect(status().isOk());

		verify(this.tokenGenerator, times(3)).generate(any());
	}

	// gh-1422
	@Test
	public void requestWhenAuthenticationRequestWithOfflineAccessScopeThenTokenResponseIncludesRefreshToken()
			throws Exception {
		this.spring.register(AuthorizationServerConfigurationWithCustomRefreshTokenGenerator.class).autowire();

		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
			.scope(OidcScopes.OPENID)
			.scope("offline_access")
			.build();
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
		assertThat(redirectedUrl).matches(expectedRedirectUri + "\\?code=.{15,}&state=state");

		String authorizationCode = extractParameterFromRedirectUri(redirectedUrl, "code");
		OAuth2Authorization authorization = this.authorizationService.findByToken(authorizationCode,
				AUTHORIZATION_CODE_TOKEN_TYPE);

		this.mvc
			.perform(post(DEFAULT_TOKEN_ENDPOINT_URI).params(getTokenRequestParameters(registeredClient, authorization))
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
			.andExpect(jsonPath("$.id_token").isNotEmpty())
			.andReturn();
	}

	// gh-1422
	@Test
	public void requestWhenAuthenticationRequestWithoutOfflineAccessScopeThenTokenResponseDoesNotIncludeRefreshToken()
			throws Exception {
		this.spring.register(AuthorizationServerConfigurationWithCustomRefreshTokenGenerator.class).autowire();

		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().scope(OidcScopes.OPENID).build();
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
		assertThat(redirectedUrl).matches(expectedRedirectUri + "\\?code=.{15,}&state=state");

		String authorizationCode = extractParameterFromRedirectUri(redirectedUrl, "code");
		OAuth2Authorization authorization = this.authorizationService.findByToken(authorizationCode,
				AUTHORIZATION_CODE_TOKEN_TYPE);

		this.mvc
			.perform(post(DEFAULT_TOKEN_ENDPOINT_URI).params(getTokenRequestParameters(registeredClient, authorization))
				.header(HttpHeaders.AUTHORIZATION,
						"Basic " + encodeBasicAuth(registeredClient.getClientId(), registeredClient.getClientSecret())))
			.andExpect(status().isOk())
			.andExpect(header().string(HttpHeaders.CACHE_CONTROL, containsString("no-store")))
			.andExpect(header().string(HttpHeaders.PRAGMA, containsString("no-cache")))
			.andExpect(jsonPath("$.access_token").isNotEmpty())
			.andExpect(jsonPath("$.token_type").isNotEmpty())
			.andExpect(jsonPath("$.expires_in").isNotEmpty())
			.andExpect(jsonPath("$.refresh_token").doesNotExist())
			.andExpect(jsonPath("$.scope").isNotEmpty())
			.andExpect(jsonPath("$.id_token").isNotEmpty())
			.andReturn();
	}

	private static OAuth2Authorization createAuthorization(RegisteredClient registeredClient) {
		Map<String, Object> additionalParameters = new HashMap<>();
		additionalParameters.put(PkceParameterNames.CODE_CHALLENGE, S256_CODE_CHALLENGE);
		additionalParameters.put(PkceParameterNames.CODE_CHALLENGE_METHOD, "S256");
		return TestOAuth2Authorizations.authorization(registeredClient, additionalParameters).build();
	}

	private static MultiValueMap<String, String> getAuthorizationRequestParameters(RegisteredClient registeredClient) {
		MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
		parameters.set(OAuth2ParameterNames.RESPONSE_TYPE, OAuth2AuthorizationResponseType.CODE.getValue());
		parameters.set(OAuth2ParameterNames.CLIENT_ID, registeredClient.getClientId());
		parameters.set(OAuth2ParameterNames.REDIRECT_URI, registeredClient.getRedirectUris().iterator().next());
		parameters.set(OAuth2ParameterNames.SCOPE,
				StringUtils.collectionToDelimitedString(registeredClient.getScopes(), " "));
		parameters.set(OAuth2ParameterNames.STATE, "state");
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

	private static String encodeBasicAuth(String clientId, String secret) throws Exception {
		clientId = URLEncoder.encode(clientId, StandardCharsets.UTF_8.name());
		secret = URLEncoder.encode(secret, StandardCharsets.UTF_8.name());
		String credentialsString = clientId + ":" + secret;
		byte[] encodedBytes = Base64.getEncoder().encode(credentialsString.getBytes(StandardCharsets.UTF_8));
		return new String(encodedBytes, StandardCharsets.UTF_8);
	}

	private String extractParameterFromRedirectUri(String redirectUri, String param)
			throws UnsupportedEncodingException {
		String locationHeader = URLDecoder.decode(redirectUri, StandardCharsets.UTF_8.name());
		UriComponents uriComponents = UriComponentsBuilder.fromUriString(locationHeader).build();
		return uriComponents.getQueryParams().getFirst(param);
	}

	@EnableWebSecurity
	@Configuration(proxyBeanMethods = false)
	static class AuthorizationServerConfiguration {

		@Bean
		SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.oauth2AuthorizationServer((authorizationServer) ->
					authorizationServer
						.oidc(Customizer.withDefaults())	// Enable OpenID Connect 1.0
				);
			// @formatter:on
			return http.build();
		}

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
		JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
			return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
		}

		@Bean
		OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer() {
			return (context) -> {
				if (context.getTokenType().getValue().equals(OidcParameterNames.ID_TOKEN)) {
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
		AuthorizationServerSettings authorizationServerSettings() {
			return AuthorizationServerSettings.builder().multipleIssuersAllowed(true).build();
		}

		@Bean
		PasswordEncoder passwordEncoder() {
			return NoOpPasswordEncoder.getInstance();
		}

		@Bean
		SessionRegistry sessionRegistry() {
			return sessionRegistry;
		}

	}

	@EnableWebSecurity
	@Configuration
	static class AuthorizationServerConfigurationWithTokenGenerator extends AuthorizationServerConfiguration {

		// @formatter:off
		@Bean
		SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
			http
					.oauth2AuthorizationServer((authorizationServer) ->
							authorizationServer
									.tokenGenerator(tokenGenerator())
									.oidc(Customizer.withDefaults())
					)
					.authorizeHttpRequests((authorize) ->
							authorize.anyRequest().authenticated()
					);
			return http.build();
		}
		// @formatter:on

		@Bean
		OAuth2TokenGenerator<?> tokenGenerator() {
			JwtGenerator jwtGenerator = new JwtGenerator(new NimbusJwtEncoder(jwkSource()));
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
	@Configuration
	static class AuthorizationServerConfigurationWithCustomRefreshTokenGenerator
			extends AuthorizationServerConfiguration {

		// @formatter:off
		@Bean
		SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
			http
					.oauth2AuthorizationServer((authorizationServer) ->
							authorizationServer
									.tokenGenerator(tokenGenerator())
									.oidc(Customizer.withDefaults())
					)
					.authorizeHttpRequests((authorize) ->
							authorize.anyRequest().authenticated()
					);
			return http.build();
		}
		// @formatter:on

		@Bean
		OAuth2TokenGenerator<?> tokenGenerator() {
			JwtGenerator jwtGenerator = new JwtGenerator(new NimbusJwtEncoder(jwkSource()));
			jwtGenerator.setJwtCustomizer(jwtCustomizer());
			OAuth2TokenGenerator<OAuth2RefreshToken> refreshTokenGenerator = new CustomRefreshTokenGenerator();
			return new DelegatingOAuth2TokenGenerator(jwtGenerator, refreshTokenGenerator);
		}

		private static final class CustomRefreshTokenGenerator implements OAuth2TokenGenerator<OAuth2RefreshToken> {

			private final OAuth2RefreshTokenGenerator delegate = new OAuth2RefreshTokenGenerator();

			@Nullable
			@Override
			public OAuth2RefreshToken generate(OAuth2TokenContext context) {
				if (context.getAuthorizedScopes().contains(OidcScopes.OPENID)
						&& !context.getAuthorizedScopes().contains("offline_access")) {
					return null;
				}
				return this.delegate.generate(context);
			}

		}

	}

}
