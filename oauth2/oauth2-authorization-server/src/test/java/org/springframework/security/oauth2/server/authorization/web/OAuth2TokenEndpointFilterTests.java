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

package org.springframework.security.oauth2.server.authorization.web;

import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.assertj.core.api.InstanceOfAssertFactories;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.mock.http.client.MockClientHttpResponse;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.oauth2.core.http.converter.OAuth2ErrorHttpMessageConverter;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientCredentialsAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2RefreshTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenExchangeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.util.StringUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * Tests for {@link OAuth2TokenEndpointFilter}.
 *
 * @author Madhu Bhat
 * @author Joe Grandja
 * @author Daniel Garnier-Moiroux
 */
public class OAuth2TokenEndpointFilterTests {

	private static final String DEFAULT_TOKEN_ENDPOINT_URI = "/oauth2/token";

	private static final String REMOTE_ADDRESS = "remote-address";

	private static final String ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";

	private AuthenticationManager authenticationManager;

	private OAuth2TokenEndpointFilter filter;

	private final HttpMessageConverter<OAuth2Error> errorHttpResponseConverter = new OAuth2ErrorHttpMessageConverter();

	private final HttpMessageConverter<OAuth2AccessTokenResponse> accessTokenHttpResponseConverter = new OAuth2AccessTokenResponseHttpMessageConverter();

	@BeforeEach
	public void setUp() {
		this.authenticationManager = mock(AuthenticationManager.class);
		this.filter = new OAuth2TokenEndpointFilter(this.authenticationManager);
	}

	@AfterEach
	public void cleanup() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void constructorWhenAuthenticationManagerNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OAuth2TokenEndpointFilter(null, "tokenEndpointUri"))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessage("authenticationManager cannot be null");
	}

	@Test
	public void constructorWhenTokenEndpointUriNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OAuth2TokenEndpointFilter(this.authenticationManager, null))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessage("tokenEndpointUri cannot be empty");
	}

	@Test
	public void setAuthenticationDetailsSourceWhenNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> this.filter.setAuthenticationDetailsSource(null))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessage("authenticationDetailsSource cannot be null");
	}

	@Test
	public void setAuthenticationConverterWhenNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> this.filter.setAuthenticationConverter(null))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessage("authenticationConverter cannot be null");
	}

	@Test
	public void setAuthenticationSuccessHandlerWhenNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> this.filter.setAuthenticationSuccessHandler(null))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessage("authenticationSuccessHandler cannot be null");
	}

	@Test
	public void setAuthenticationFailureHandlerWhenNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> this.filter.setAuthenticationFailureHandler(null))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessage("authenticationFailureHandler cannot be null");
	}

	@Test
	public void doFilterWhenNotTokenRequestThenNotProcessed() throws Exception {
		String requestUri = "/path";
		MockHttpServletRequest request = new MockHttpServletRequest("POST", requestUri);
		request.setServletPath(requestUri);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verify(filterChain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
	}

	@Test
	public void doFilterWhenTokenRequestGetThenNotProcessed() throws Exception {
		String requestUri = DEFAULT_TOKEN_ENDPOINT_URI;
		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestUri);
		request.setServletPath(requestUri);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verify(filterChain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
	}

	@Test
	public void doFilterWhenTokenRequestMissingGrantTypeThenInvalidRequestError() throws Exception {
		MockHttpServletRequest request = createAuthorizationCodeTokenRequest(
				TestRegisteredClients.registeredClient().build());
		request.removeParameter(OAuth2ParameterNames.GRANT_TYPE);

		doFilterWhenTokenRequestInvalidParameterThenError(OAuth2ParameterNames.GRANT_TYPE,
				OAuth2ErrorCodes.INVALID_REQUEST, request);
	}

	@Test
	public void doFilterWhenTokenRequestMultipleGrantTypeThenInvalidRequestError() throws Exception {
		MockHttpServletRequest request = createAuthorizationCodeTokenRequest(
				TestRegisteredClients.registeredClient().build());
		request.addParameter(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.AUTHORIZATION_CODE.getValue());

		doFilterWhenTokenRequestInvalidParameterThenError(OAuth2ParameterNames.GRANT_TYPE,
				OAuth2ErrorCodes.INVALID_REQUEST, request);
	}

	@Test
	public void doFilterWhenTokenRequestInvalidGrantTypeThenUnsupportedGrantTypeError() throws Exception {
		MockHttpServletRequest request = createAuthorizationCodeTokenRequest(
				TestRegisteredClients.registeredClient().build());
		request.setParameter(OAuth2ParameterNames.GRANT_TYPE, "invalid-grant-type");

		doFilterWhenTokenRequestInvalidParameterThenError(OAuth2ParameterNames.GRANT_TYPE,
				OAuth2ErrorCodes.UNSUPPORTED_GRANT_TYPE, request);
	}

	@Test
	public void doFilterWhenTokenRequestMissingCodeThenInvalidRequestError() throws Exception {
		MockHttpServletRequest request = createAuthorizationCodeTokenRequest(
				TestRegisteredClients.registeredClient().build());
		request.removeParameter(OAuth2ParameterNames.CODE);

		doFilterWhenTokenRequestInvalidParameterThenError(OAuth2ParameterNames.CODE, OAuth2ErrorCodes.INVALID_REQUEST,
				request);
	}

	@Test
	public void doFilterWhenTokenRequestMultipleCodeThenInvalidRequestError() throws Exception {
		MockHttpServletRequest request = createAuthorizationCodeTokenRequest(
				TestRegisteredClients.registeredClient().build());
		request.addParameter(OAuth2ParameterNames.CODE, "code-2");

		doFilterWhenTokenRequestInvalidParameterThenError(OAuth2ParameterNames.CODE, OAuth2ErrorCodes.INVALID_REQUEST,
				request);
	}

	@Test
	public void doFilterWhenTokenRequestMultipleRedirectUriThenInvalidRequestError() throws Exception {
		MockHttpServletRequest request = createAuthorizationCodeTokenRequest(
				TestRegisteredClients.registeredClient().build());
		request.addParameter(OAuth2ParameterNames.REDIRECT_URI, "https://example2.com");

		doFilterWhenTokenRequestInvalidParameterThenError(OAuth2ParameterNames.REDIRECT_URI,
				OAuth2ErrorCodes.INVALID_REQUEST, request);
	}

	@Test
	public void doFilterWhenTokenRequestMultipleDPoPHeaderThenInvalidRequestError() throws Exception {
		MockHttpServletRequest request = createAuthorizationCodeTokenRequest(
				TestRegisteredClients.registeredClient().build());
		request.addHeader(OAuth2AccessToken.TokenType.DPOP.getValue(), "dpop-proof-jwt");
		request.addHeader(OAuth2AccessToken.TokenType.DPOP.getValue(), "dpop-proof-jwt-2");

		doFilterWhenTokenRequestInvalidParameterThenError(OAuth2AccessToken.TokenType.DPOP.getValue(),
				OAuth2ErrorCodes.INVALID_REQUEST, request);
	}

	@Test
	public void doFilterWhenAuthorizationCodeTokenRequestThenAccessTokenResponse() throws Exception {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		Authentication clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
				ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
		OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "token",
				Instant.now(), Instant.now().plus(Duration.ofHours(1)),
				new HashSet<>(Arrays.asList("scope1", "scope2")));
		OAuth2RefreshToken refreshToken = new OAuth2RefreshToken("refresh-token", Instant.now(),
				Instant.now().plus(Duration.ofDays(1)));
		OAuth2AccessTokenAuthenticationToken accessTokenAuthentication = new OAuth2AccessTokenAuthenticationToken(
				registeredClient, clientPrincipal, accessToken, refreshToken);

		given(this.authenticationManager.authenticate(any())).willReturn(accessTokenAuthentication);

		SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
		securityContext.setAuthentication(clientPrincipal);
		SecurityContextHolder.setContext(securityContext);

		MockHttpServletRequest request = createAuthorizationCodeTokenRequest(registeredClient);
		request.addHeader(OAuth2AccessToken.TokenType.DPOP.getValue(), "dpop-proof-jwt");
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verifyNoInteractions(filterChain);

		ArgumentCaptor<OAuth2AuthorizationCodeAuthenticationToken> authorizationCodeAuthenticationCaptor = ArgumentCaptor
			.forClass(OAuth2AuthorizationCodeAuthenticationToken.class);
		verify(this.authenticationManager).authenticate(authorizationCodeAuthenticationCaptor.capture());

		OAuth2AuthorizationCodeAuthenticationToken authorizationCodeAuthentication = authorizationCodeAuthenticationCaptor
			.getValue();
		assertThat(authorizationCodeAuthentication.getCode())
			.isEqualTo(request.getParameter(OAuth2ParameterNames.CODE));
		assertThat(authorizationCodeAuthentication.getPrincipal()).isEqualTo(clientPrincipal);
		assertThat(authorizationCodeAuthentication.getRedirectUri())
			.isEqualTo(request.getParameter(OAuth2ParameterNames.REDIRECT_URI));
		Map<String, Object> expectedAdditionalParameters = new HashMap<>();
		expectedAdditionalParameters.put("custom-param-1", "custom-value-1");
		expectedAdditionalParameters.put("custom-param-2", new String[] { "custom-value-1", "custom-value-2" });
		expectedAdditionalParameters.put("dpop_proof", "dpop-proof-jwt");
		expectedAdditionalParameters.put("dpop_method", "POST");
		expectedAdditionalParameters.put("dpop_target_uri", "http://localhost/oauth2/token");
		assertThat(authorizationCodeAuthentication.getAdditionalParameters())
			.containsExactlyInAnyOrderEntriesOf(expectedAdditionalParameters);
		assertThat(authorizationCodeAuthentication.getDetails())
			.asInstanceOf(InstanceOfAssertFactories.type(WebAuthenticationDetails.class))
			.extracting(WebAuthenticationDetails::getRemoteAddress)
			.isEqualTo(REMOTE_ADDRESS);

		assertThat(response.getStatus()).isEqualTo(HttpStatus.OK.value());
		OAuth2AccessTokenResponse accessTokenResponse = readAccessTokenResponse(response);

		OAuth2AccessToken accessTokenResult = accessTokenResponse.getAccessToken();
		assertThat(accessTokenResult.getTokenType()).isEqualTo(accessToken.getTokenType());
		assertThat(accessTokenResult.getTokenValue()).isEqualTo(accessToken.getTokenValue());
		assertThat(accessTokenResult.getIssuedAt()).isBetween(accessToken.getIssuedAt().minusSeconds(1),
				accessToken.getIssuedAt().plusSeconds(1));
		assertThat(accessTokenResult.getExpiresAt()).isBetween(accessToken.getExpiresAt().minusSeconds(1),
				accessToken.getExpiresAt().plusSeconds(1));
		assertThat(accessTokenResult.getScopes()).isEqualTo(accessToken.getScopes());
		assertThat(accessTokenResponse.getRefreshToken().getTokenValue()).isEqualTo(refreshToken.getTokenValue());
	}

	@Test
	public void doFilterWhenClientCredentialsTokenRequestMultipleScopeThenInvalidRequestError() throws Exception {
		MockHttpServletRequest request = createClientCredentialsTokenRequest(
				TestRegisteredClients.registeredClient2().build());
		request.addParameter(OAuth2ParameterNames.SCOPE, "profile");

		doFilterWhenTokenRequestInvalidParameterThenError(OAuth2ParameterNames.SCOPE, OAuth2ErrorCodes.INVALID_REQUEST,
				request);
	}

	@Test
	public void doFilterWhenClientCredentialsTokenRequestThenAccessTokenResponse() throws Exception {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient2().build();
		Authentication clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
				ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
		OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "token",
				Instant.now(), Instant.now().plus(Duration.ofHours(1)),
				new HashSet<>(Arrays.asList("scope1", "scope2")));
		OAuth2AccessTokenAuthenticationToken accessTokenAuthentication = new OAuth2AccessTokenAuthenticationToken(
				registeredClient, clientPrincipal, accessToken);

		given(this.authenticationManager.authenticate(any())).willReturn(accessTokenAuthentication);

		SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
		securityContext.setAuthentication(clientPrincipal);
		SecurityContextHolder.setContext(securityContext);

		MockHttpServletRequest request = createClientCredentialsTokenRequest(registeredClient);
		request.addHeader(OAuth2AccessToken.TokenType.DPOP.getValue(), "dpop-proof-jwt");
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verifyNoInteractions(filterChain);

		ArgumentCaptor<OAuth2ClientCredentialsAuthenticationToken> clientCredentialsAuthenticationCaptor = ArgumentCaptor
			.forClass(OAuth2ClientCredentialsAuthenticationToken.class);
		verify(this.authenticationManager).authenticate(clientCredentialsAuthenticationCaptor.capture());

		OAuth2ClientCredentialsAuthenticationToken clientCredentialsAuthentication = clientCredentialsAuthenticationCaptor
			.getValue();
		assertThat(clientCredentialsAuthentication.getPrincipal()).isEqualTo(clientPrincipal);
		assertThat(clientCredentialsAuthentication.getScopes()).isEqualTo(registeredClient.getScopes());
		Map<String, Object> expectedAdditionalParameters = new HashMap<>();
		expectedAdditionalParameters.put("custom-param-1", "custom-value-1");
		expectedAdditionalParameters.put("custom-param-2", new String[] { "custom-value-1", "custom-value-2" });
		expectedAdditionalParameters.put("dpop_proof", "dpop-proof-jwt");
		expectedAdditionalParameters.put("dpop_method", "POST");
		expectedAdditionalParameters.put("dpop_target_uri", "http://localhost/oauth2/token");
		assertThat(clientCredentialsAuthentication.getAdditionalParameters())
			.containsExactlyInAnyOrderEntriesOf(expectedAdditionalParameters);
		assertThat(clientCredentialsAuthentication.getDetails())
			.asInstanceOf(InstanceOfAssertFactories.type(WebAuthenticationDetails.class))
			.extracting(WebAuthenticationDetails::getRemoteAddress)
			.isEqualTo(REMOTE_ADDRESS);

		assertThat(response.getStatus()).isEqualTo(HttpStatus.OK.value());
		// For gh-281, check that expires_in is a number
		assertThat(new ObjectMapper().readValue(response.getContentAsByteArray(), Map.class)
			.get(OAuth2ParameterNames.EXPIRES_IN)).isInstanceOf(Number.class);
		OAuth2AccessTokenResponse accessTokenResponse = readAccessTokenResponse(response);

		OAuth2AccessToken accessTokenResult = accessTokenResponse.getAccessToken();
		assertThat(accessTokenResult.getTokenType()).isEqualTo(accessToken.getTokenType());
		assertThat(accessTokenResult.getTokenValue()).isEqualTo(accessToken.getTokenValue());
		assertThat(accessTokenResult.getIssuedAt()).isBetween(accessToken.getIssuedAt().minusSeconds(1),
				accessToken.getIssuedAt().plusSeconds(1));
		assertThat(accessTokenResult.getExpiresAt()).isBetween(accessToken.getExpiresAt().minusSeconds(1),
				accessToken.getExpiresAt().plusSeconds(1));
		assertThat(accessTokenResult.getScopes()).isEqualTo(accessToken.getScopes());
	}

	@Test
	public void doFilterWhenRefreshTokenRequestMissingRefreshTokenThenInvalidRequestError() throws Exception {
		MockHttpServletRequest request = createRefreshTokenTokenRequest(
				TestRegisteredClients.registeredClient().build());
		request.removeParameter(OAuth2ParameterNames.REFRESH_TOKEN);

		doFilterWhenTokenRequestInvalidParameterThenError(OAuth2ParameterNames.REFRESH_TOKEN,
				OAuth2ErrorCodes.INVALID_REQUEST, request);
	}

	@Test
	public void doFilterWhenRefreshTokenRequestMultipleRefreshTokenThenInvalidRequestError() throws Exception {
		MockHttpServletRequest request = createRefreshTokenTokenRequest(
				TestRegisteredClients.registeredClient().build());
		request.addParameter(OAuth2ParameterNames.REFRESH_TOKEN, "refresh-token-2");

		doFilterWhenTokenRequestInvalidParameterThenError(OAuth2ParameterNames.REFRESH_TOKEN,
				OAuth2ErrorCodes.INVALID_REQUEST, request);
	}

	@Test
	public void doFilterWhenRefreshTokenRequestMultipleScopeThenInvalidRequestError() throws Exception {
		MockHttpServletRequest request = createRefreshTokenTokenRequest(
				TestRegisteredClients.registeredClient().build());
		request.addParameter(OAuth2ParameterNames.SCOPE, "profile");

		doFilterWhenTokenRequestInvalidParameterThenError(OAuth2ParameterNames.SCOPE, OAuth2ErrorCodes.INVALID_REQUEST,
				request);
	}

	@Test
	public void doFilterWhenRefreshTokenRequestThenAccessTokenResponse() throws Exception {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		Authentication clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
				ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
		OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "token",
				Instant.now(), Instant.now().plus(Duration.ofHours(1)),
				new HashSet<>(Arrays.asList("scope1", "scope2")));
		OAuth2RefreshToken refreshToken = new OAuth2RefreshToken("refresh-token", Instant.now());
		OAuth2AccessTokenAuthenticationToken accessTokenAuthentication = new OAuth2AccessTokenAuthenticationToken(
				registeredClient, clientPrincipal, accessToken, refreshToken);

		given(this.authenticationManager.authenticate(any())).willReturn(accessTokenAuthentication);

		SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
		securityContext.setAuthentication(clientPrincipal);
		SecurityContextHolder.setContext(securityContext);

		MockHttpServletRequest request = createRefreshTokenTokenRequest(registeredClient);
		request.addHeader(OAuth2AccessToken.TokenType.DPOP.getValue(), "dpop-proof-jwt");
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verifyNoInteractions(filterChain);

		ArgumentCaptor<OAuth2RefreshTokenAuthenticationToken> refreshTokenAuthenticationCaptor = ArgumentCaptor
			.forClass(OAuth2RefreshTokenAuthenticationToken.class);
		verify(this.authenticationManager).authenticate(refreshTokenAuthenticationCaptor.capture());

		OAuth2RefreshTokenAuthenticationToken refreshTokenAuthenticationToken = refreshTokenAuthenticationCaptor
			.getValue();
		assertThat(refreshTokenAuthenticationToken.getRefreshToken()).isEqualTo(refreshToken.getTokenValue());
		assertThat(refreshTokenAuthenticationToken.getPrincipal()).isEqualTo(clientPrincipal);
		assertThat(refreshTokenAuthenticationToken.getScopes()).isEqualTo(registeredClient.getScopes());
		Map<String, Object> expectedAdditionalParameters = new HashMap<>();
		expectedAdditionalParameters.put("custom-param-1", "custom-value-1");
		expectedAdditionalParameters.put("custom-param-2", new String[] { "custom-value-1", "custom-value-2" });
		expectedAdditionalParameters.put("dpop_proof", "dpop-proof-jwt");
		expectedAdditionalParameters.put("dpop_method", "POST");
		expectedAdditionalParameters.put("dpop_target_uri", "http://localhost/oauth2/token");
		assertThat(refreshTokenAuthenticationToken.getAdditionalParameters())
			.containsExactlyInAnyOrderEntriesOf(expectedAdditionalParameters);
		assertThat(refreshTokenAuthenticationToken.getDetails())
			.asInstanceOf(InstanceOfAssertFactories.type(WebAuthenticationDetails.class))
			.extracting(WebAuthenticationDetails::getRemoteAddress)
			.isEqualTo(REMOTE_ADDRESS);

		assertThat(response.getStatus()).isEqualTo(HttpStatus.OK.value());
		OAuth2AccessTokenResponse accessTokenResponse = readAccessTokenResponse(response);

		OAuth2AccessToken accessTokenResult = accessTokenResponse.getAccessToken();
		assertThat(accessTokenResult.getTokenType()).isEqualTo(accessToken.getTokenType());
		assertThat(accessTokenResult.getTokenValue()).isEqualTo(accessToken.getTokenValue());
		assertThat(accessTokenResult.getIssuedAt()).isBetween(accessToken.getIssuedAt().minusSeconds(1),
				accessToken.getIssuedAt().plusSeconds(1));
		assertThat(accessTokenResult.getExpiresAt()).isBetween(accessToken.getExpiresAt().minusSeconds(1),
				accessToken.getExpiresAt().plusSeconds(1));
		assertThat(accessTokenResult.getScopes()).isEqualTo(accessToken.getScopes());

		OAuth2RefreshToken refreshTokenResult = accessTokenResponse.getRefreshToken();
		assertThat(refreshTokenResult.getTokenValue()).isEqualTo(refreshToken.getTokenValue());
	}

	@Test
	public void doFilterWhenTokenExchangeRequestThenAccessTokenResponse() throws Exception {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
			.authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
			.build();
		Authentication clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
				ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
		OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "token",
				Instant.now(), Instant.now().plus(Duration.ofHours(1)),
				new HashSet<>(Arrays.asList("scope1", "scope2")));
		OAuth2RefreshToken refreshToken = new OAuth2RefreshToken("refresh-token", Instant.now());
		OAuth2AccessTokenAuthenticationToken accessTokenAuthentication = new OAuth2AccessTokenAuthenticationToken(
				registeredClient, clientPrincipal, accessToken, refreshToken);

		given(this.authenticationManager.authenticate(any())).willReturn(accessTokenAuthentication);

		SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
		securityContext.setAuthentication(clientPrincipal);
		SecurityContextHolder.setContext(securityContext);

		MockHttpServletRequest request = createTokenExchangeTokenRequest(registeredClient);
		request.addHeader(OAuth2AccessToken.TokenType.DPOP.getValue(), "dpop-proof-jwt");
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verifyNoInteractions(filterChain);

		ArgumentCaptor<OAuth2TokenExchangeAuthenticationToken> tokenExchangeAuthenticationCaptor = ArgumentCaptor
			.forClass(OAuth2TokenExchangeAuthenticationToken.class);
		verify(this.authenticationManager).authenticate(tokenExchangeAuthenticationCaptor.capture());

		OAuth2TokenExchangeAuthenticationToken tokenExchangeAuthenticationToken = tokenExchangeAuthenticationCaptor
			.getValue();
		assertThat(tokenExchangeAuthenticationToken.getSubjectToken()).isEqualTo("subject-token");
		assertThat(tokenExchangeAuthenticationToken.getSubjectTokenType()).isEqualTo(ACCESS_TOKEN_TYPE);
		assertThat(tokenExchangeAuthenticationToken.getPrincipal()).isEqualTo(clientPrincipal);
		assertThat(tokenExchangeAuthenticationToken.getScopes()).isEqualTo(registeredClient.getScopes());
		Map<String, Object> expectedAdditionalParameters = new HashMap<>();
		expectedAdditionalParameters.put("custom-param-1", "custom-value-1");
		expectedAdditionalParameters.put("custom-param-2", new String[] { "custom-value-1", "custom-value-2" });
		expectedAdditionalParameters.put("dpop_proof", "dpop-proof-jwt");
		expectedAdditionalParameters.put("dpop_method", "POST");
		expectedAdditionalParameters.put("dpop_target_uri", "http://localhost/oauth2/token");
		assertThat(tokenExchangeAuthenticationToken.getAdditionalParameters())
			.containsExactlyInAnyOrderEntriesOf(expectedAdditionalParameters);
		assertThat(tokenExchangeAuthenticationToken.getDetails())
			.asInstanceOf(InstanceOfAssertFactories.type(WebAuthenticationDetails.class))
			.extracting(WebAuthenticationDetails::getRemoteAddress)
			.isEqualTo(REMOTE_ADDRESS);

		assertThat(response.getStatus()).isEqualTo(HttpStatus.OK.value());
		OAuth2AccessTokenResponse accessTokenResponse = readAccessTokenResponse(response);

		OAuth2AccessToken accessTokenResult = accessTokenResponse.getAccessToken();
		assertThat(accessTokenResult.getTokenType()).isEqualTo(accessToken.getTokenType());
		assertThat(accessTokenResult.getTokenValue()).isEqualTo(accessToken.getTokenValue());
		assertThat(accessTokenResult.getIssuedAt()).isBetween(accessToken.getIssuedAt().minusSeconds(1),
				accessToken.getIssuedAt().plusSeconds(1));
		assertThat(accessTokenResult.getExpiresAt()).isBetween(accessToken.getExpiresAt().minusSeconds(1),
				accessToken.getExpiresAt().plusSeconds(1));
		assertThat(accessTokenResult.getScopes()).isEqualTo(accessToken.getScopes());

		OAuth2RefreshToken refreshTokenResult = accessTokenResponse.getRefreshToken();
		assertThat(refreshTokenResult.getTokenValue()).isEqualTo(refreshToken.getTokenValue());
	}

	@Test
	public void doFilterWhenCustomAuthenticationDetailsSourceThenUsed() throws Exception {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		Authentication clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
				ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());

		MockHttpServletRequest request = createAuthorizationCodeTokenRequest(registeredClient);

		AuthenticationDetailsSource<HttpServletRequest, WebAuthenticationDetails> authenticationDetailsSource = mock(
				AuthenticationDetailsSource.class);
		WebAuthenticationDetails webAuthenticationDetails = new WebAuthenticationDetails(request);
		given(authenticationDetailsSource.buildDetails(any())).willReturn(webAuthenticationDetails);
		this.filter.setAuthenticationDetailsSource(authenticationDetailsSource);

		OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "token",
				Instant.now(), Instant.now().plus(Duration.ofHours(1)),
				new HashSet<>(Arrays.asList("scope1", "scope2")));
		OAuth2AccessTokenAuthenticationToken accessTokenAuthentication = new OAuth2AccessTokenAuthenticationToken(
				registeredClient, clientPrincipal, accessToken);

		given(this.authenticationManager.authenticate(any())).willReturn(accessTokenAuthentication);

		SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
		securityContext.setAuthentication(clientPrincipal);
		SecurityContextHolder.setContext(securityContext);

		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verify(authenticationDetailsSource).buildDetails(any());
	}

	@Test
	public void doFilterWhenCustomAuthenticationConverterThenUsed() throws Exception {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		Authentication clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
				ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());

		OAuth2AuthorizationCodeAuthenticationToken authorizationCodeAuthentication = new OAuth2AuthorizationCodeAuthenticationToken(
				"code", clientPrincipal, null, null);

		AuthenticationConverter authenticationConverter = mock(AuthenticationConverter.class);
		given(authenticationConverter.convert(any())).willReturn(authorizationCodeAuthentication);
		this.filter.setAuthenticationConverter(authenticationConverter);

		OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "token",
				Instant.now(), Instant.now().plus(Duration.ofHours(1)),
				new HashSet<>(Arrays.asList("scope1", "scope2")));
		OAuth2AccessTokenAuthenticationToken accessTokenAuthentication = new OAuth2AccessTokenAuthenticationToken(
				registeredClient, clientPrincipal, accessToken);

		given(this.authenticationManager.authenticate(any())).willReturn(accessTokenAuthentication);

		SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
		securityContext.setAuthentication(clientPrincipal);
		SecurityContextHolder.setContext(securityContext);

		MockHttpServletRequest request = createAuthorizationCodeTokenRequest(registeredClient);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verify(authenticationConverter).convert(any());
	}

	@Test
	public void doFilterWhenCustomAuthenticationSuccessHandlerThenUsed() throws Exception {
		AuthenticationSuccessHandler authenticationSuccessHandler = mock(AuthenticationSuccessHandler.class);
		this.filter.setAuthenticationSuccessHandler(authenticationSuccessHandler);

		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		Authentication clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
				ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
		OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "token",
				Instant.now(), Instant.now().plus(Duration.ofHours(1)),
				new HashSet<>(Arrays.asList("scope1", "scope2")));
		OAuth2AccessTokenAuthenticationToken accessTokenAuthentication = new OAuth2AccessTokenAuthenticationToken(
				registeredClient, clientPrincipal, accessToken);

		given(this.authenticationManager.authenticate(any())).willReturn(accessTokenAuthentication);

		SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
		securityContext.setAuthentication(clientPrincipal);
		SecurityContextHolder.setContext(securityContext);

		MockHttpServletRequest request = createAuthorizationCodeTokenRequest(registeredClient);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verify(authenticationSuccessHandler).onAuthenticationSuccess(any(), any(), any());
	}

	@Test
	public void doFilterWhenCustomAuthenticationFailureHandlerThenUsed() throws Exception {
		AuthenticationFailureHandler authenticationFailureHandler = mock(AuthenticationFailureHandler.class);
		this.filter.setAuthenticationFailureHandler(authenticationFailureHandler);

		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();

		MockHttpServletRequest request = createAuthorizationCodeTokenRequest(registeredClient);
		request.removeParameter(OAuth2ParameterNames.GRANT_TYPE);

		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verify(authenticationFailureHandler).onAuthenticationFailure(any(), any(), any());
	}

	private void doFilterWhenTokenRequestInvalidParameterThenError(String parameterName, String errorCode,
			MockHttpServletRequest request) throws Exception {

		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verifyNoInteractions(filterChain);

		assertThat(response.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST.value());
		OAuth2Error error = readError(response);
		assertThat(error.getErrorCode()).isEqualTo(errorCode);
		assertThat(error.getDescription()).isEqualTo("OAuth 2.0 Parameter: " + parameterName);
	}

	private OAuth2Error readError(MockHttpServletResponse response) throws Exception {
		MockClientHttpResponse httpResponse = new MockClientHttpResponse(response.getContentAsByteArray(),
				HttpStatus.valueOf(response.getStatus()));
		return this.errorHttpResponseConverter.read(OAuth2Error.class, httpResponse);
	}

	private OAuth2AccessTokenResponse readAccessTokenResponse(MockHttpServletResponse response) throws Exception {
		MockClientHttpResponse httpResponse = new MockClientHttpResponse(response.getContentAsByteArray(),
				HttpStatus.valueOf(response.getStatus()));
		return this.accessTokenHttpResponseConverter.read(OAuth2AccessTokenResponse.class, httpResponse);
	}

	private static MockHttpServletRequest createAuthorizationCodeTokenRequest(RegisteredClient registeredClient) {
		String[] redirectUris = registeredClient.getRedirectUris().toArray(new String[0]);

		String requestUri = DEFAULT_TOKEN_ENDPOINT_URI;
		MockHttpServletRequest request = new MockHttpServletRequest("POST", requestUri);
		request.setServletPath(requestUri);
		request.setRemoteAddr(REMOTE_ADDRESS);

		request.addParameter(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.AUTHORIZATION_CODE.getValue());
		request.addParameter(OAuth2ParameterNames.CODE, "code");
		request.addParameter(OAuth2ParameterNames.REDIRECT_URI, redirectUris[0]);
		// The client does not need to send the client ID param, but we are resilient in
		// case they do
		request.addParameter(OAuth2ParameterNames.CLIENT_ID, registeredClient.getClientId());
		request.addParameter("custom-param-1", "custom-value-1");
		request.addParameter("custom-param-2", "custom-value-1", "custom-value-2");

		return request;
	}

	private static MockHttpServletRequest createClientCredentialsTokenRequest(RegisteredClient registeredClient) {
		String requestUri = DEFAULT_TOKEN_ENDPOINT_URI;
		MockHttpServletRequest request = new MockHttpServletRequest("POST", requestUri);
		request.setServletPath(requestUri);
		request.setRemoteAddr(REMOTE_ADDRESS);

		request.addParameter(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.CLIENT_CREDENTIALS.getValue());
		request.addParameter(OAuth2ParameterNames.SCOPE,
				StringUtils.collectionToDelimitedString(registeredClient.getScopes(), " "));
		request.addParameter("custom-param-1", "custom-value-1");
		request.addParameter("custom-param-2", "custom-value-1", "custom-value-2");

		return request;
	}

	private static MockHttpServletRequest createRefreshTokenTokenRequest(RegisteredClient registeredClient) {
		String requestUri = DEFAULT_TOKEN_ENDPOINT_URI;
		MockHttpServletRequest request = new MockHttpServletRequest("POST", requestUri);
		request.setServletPath(requestUri);
		request.setRemoteAddr(REMOTE_ADDRESS);

		request.addParameter(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.REFRESH_TOKEN.getValue());
		request.addParameter(OAuth2ParameterNames.REFRESH_TOKEN, "refresh-token");
		request.addParameter(OAuth2ParameterNames.SCOPE,
				StringUtils.collectionToDelimitedString(registeredClient.getScopes(), " "));
		request.addParameter("custom-param-1", "custom-value-1");
		request.addParameter("custom-param-2", "custom-value-1", "custom-value-2");

		return request;
	}

	private static MockHttpServletRequest createTokenExchangeTokenRequest(RegisteredClient registeredClient) {
		String requestUri = DEFAULT_TOKEN_ENDPOINT_URI;
		MockHttpServletRequest request = new MockHttpServletRequest("POST", requestUri);
		request.setServletPath(requestUri);
		request.setRemoteAddr(REMOTE_ADDRESS);

		request.addParameter(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.TOKEN_EXCHANGE.getValue());
		request.addParameter(OAuth2ParameterNames.SUBJECT_TOKEN, "subject-token");
		request.addParameter(OAuth2ParameterNames.SUBJECT_TOKEN_TYPE, ACCESS_TOKEN_TYPE);
		request.addParameter(OAuth2ParameterNames.SCOPE,
				StringUtils.collectionToDelimitedString(registeredClient.getScopes(), " "));
		request.addParameter("custom-param-1", "custom-value-1");
		request.addParameter("custom-param-2", "custom-value-1", "custom-value-2");

		return request;
	}

}
