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

import java.time.Instant;
import java.util.Map;
import java.util.function.Consumer;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.assertj.core.api.InstanceOfAssertFactories;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import org.springframework.core.ParameterizedTypeReference;
import org.springframework.core.ResolvableType;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.SmartHttpMessageConverter;
import org.springframework.mock.http.client.MockClientHttpResponse;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.security.oauth2.core.http.converter.OAuth2ErrorHttpMessageConverter;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2PushedAuthorizationRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.context.TestAuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.util.StringUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * Tests for {@link OAuth2PushedAuthorizationRequestEndpointFilter}.
 *
 * @author Joe Grandja
 * @author Andrey Litvitski
 */
public class OAuth2PushedAuthorizationRequestEndpointFilterTests {

	private static final String AUTHORIZATION_URI = "https://provider.com/oauth2/par";

	private static final String STATE = "state";

	private static final String REMOTE_ADDRESS = "remote-address";

	private final HttpMessageConverter<OAuth2Error> errorHttpResponseConverter = new OAuth2ErrorHttpMessageConverter();

	private final SmartHttpMessageConverter<Object> jsonMessageConverter = HttpMessageConverters
		.getJsonMessageConverter();

	private AuthenticationManager authenticationManager;

	private OAuth2PushedAuthorizationRequestEndpointFilter filter;

	private TestingAuthenticationToken clientPrincipal;

	@BeforeEach
	public void setUp() {
		this.authenticationManager = mock(AuthenticationManager.class);
		this.filter = new OAuth2PushedAuthorizationRequestEndpointFilter(this.authenticationManager);
		this.clientPrincipal = new TestingAuthenticationToken("client-id", "client-secret");
		this.clientPrincipal.setAuthenticated(true);
		SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
		securityContext.setAuthentication(this.clientPrincipal);
		SecurityContextHolder.setContext(securityContext);
		AuthorizationServerContextHolder
			.setContext(new TestAuthorizationServerContext(AuthorizationServerSettings.builder().build(), null));
	}

	@AfterEach
	public void cleanup() {
		SecurityContextHolder.clearContext();
		AuthorizationServerContextHolder.resetContext();
	}

	@Test
	public void constructorWhenAuthenticationManagerNullThenThrowIllegalArgumentException() {
		assertThatExceptionOfType(IllegalArgumentException.class)
			.isThrownBy(() -> new OAuth2PushedAuthorizationRequestEndpointFilter(null))
			.withMessage("authenticationManager cannot be null");
	}

	@Test
	public void constructorWhenPushedAuthorizationRequestEndpointUriNullThenThrowIllegalArgumentException() {
		assertThatExceptionOfType(IllegalArgumentException.class)
			.isThrownBy(() -> new OAuth2PushedAuthorizationRequestEndpointFilter(this.authenticationManager, null))
			.withMessage("pushedAuthorizationRequestEndpointUri cannot be empty");
	}

	@Test
	public void setAuthenticationDetailsSourceWhenNullThenThrowIllegalArgumentException() {
		assertThatExceptionOfType(IllegalArgumentException.class)
			.isThrownBy(() -> this.filter.setAuthenticationDetailsSource(null))
			.withMessage("authenticationDetailsSource cannot be null");
	}

	@Test
	public void setAuthenticationConverterWhenNullThenThrowIllegalArgumentException() {
		assertThatExceptionOfType(IllegalArgumentException.class)
			.isThrownBy(() -> this.filter.setAuthenticationConverter(null))
			.withMessage("authenticationConverter cannot be null");
	}

	@Test
	public void setAuthenticationSuccessHandlerWhenNullThenThrowIllegalArgumentException() {
		assertThatExceptionOfType(IllegalArgumentException.class)
			.isThrownBy(() -> this.filter.setAuthenticationSuccessHandler(null))
			.withMessage("authenticationSuccessHandler cannot be null");
	}

	@Test
	public void setAuthenticationFailureHandlerWhenNullThenThrowIllegalArgumentException() {
		assertThatExceptionOfType(IllegalArgumentException.class)
			.isThrownBy(() -> this.filter.setAuthenticationFailureHandler(null))
			.withMessage("authenticationFailureHandler cannot be null");
	}

	@Test
	public void doFilterWhenNotPushedAuthorizationRequestThenNotProcessed() throws Exception {
		String requestUri = "/path";
		MockHttpServletRequest request = new MockHttpServletRequest("POST", requestUri);
		request.setServletPath(requestUri);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verify(filterChain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
	}

	@Test
	public void doFilterWhenPushedAuthorizationRequestIncludesRequestUriThenInvalidRequestError() throws Exception {
		doFilterWhenPushedAuthorizationRequestInvalidParameterThenError(
				TestRegisteredClients.registeredClient().build(), OAuth2ParameterNames.REQUEST_URI,
				OAuth2ErrorCodes.INVALID_REQUEST,
				(request) -> request.addParameter(OAuth2ParameterNames.REQUEST_URI, OAuth2ParameterNames.REQUEST_URI));
	}

	@Test
	public void doFilterWhenPushedAuthorizationRequestMultipleResponseTypeThenInvalidRequestError() throws Exception {
		doFilterWhenPushedAuthorizationRequestInvalidParameterThenError(
				TestRegisteredClients.registeredClient().build(), OAuth2ParameterNames.RESPONSE_TYPE,
				OAuth2ErrorCodes.INVALID_REQUEST,
				(request) -> request.addParameter(OAuth2ParameterNames.RESPONSE_TYPE, "id_token"));
	}

	@Test
	public void doFilterWhenPushedAuthorizationRequestInvalidResponseTypeThenUnsupportedResponseTypeError()
			throws Exception {
		doFilterWhenPushedAuthorizationRequestInvalidParameterThenError(
				TestRegisteredClients.registeredClient().build(), OAuth2ParameterNames.RESPONSE_TYPE,
				OAuth2ErrorCodes.UNSUPPORTED_RESPONSE_TYPE,
				(request) -> request.setParameter(OAuth2ParameterNames.RESPONSE_TYPE, "id_token"));
	}

	@Test
	public void doFilterWhenPushedAuthorizationRequestMissingClientIdThenInvalidRequestError() throws Exception {
		doFilterWhenPushedAuthorizationRequestInvalidParameterThenError(
				TestRegisteredClients.registeredClient().build(), OAuth2ParameterNames.CLIENT_ID,
				OAuth2ErrorCodes.INVALID_REQUEST, (request) -> request.removeParameter(OAuth2ParameterNames.CLIENT_ID));
	}

	@Test
	public void doFilterWhenPushedAuthorizationRequestMultipleClientIdThenInvalidRequestError() throws Exception {
		doFilterWhenPushedAuthorizationRequestInvalidParameterThenError(
				TestRegisteredClients.registeredClient().build(), OAuth2ParameterNames.CLIENT_ID,
				OAuth2ErrorCodes.INVALID_REQUEST,
				(request) -> request.addParameter(OAuth2ParameterNames.CLIENT_ID, "client-2"));
	}

	@Test
	public void doFilterWhenPushedAuthorizationRequestMultipleRedirectUriThenInvalidRequestError() throws Exception {
		doFilterWhenPushedAuthorizationRequestInvalidParameterThenError(
				TestRegisteredClients.registeredClient().build(), OAuth2ParameterNames.REDIRECT_URI,
				OAuth2ErrorCodes.INVALID_REQUEST,
				(request) -> request.addParameter(OAuth2ParameterNames.REDIRECT_URI, "https://example2.com"));
	}

	@Test
	public void doFilterWhenPushedAuthorizationRequestMultipleScopeThenInvalidRequestError() throws Exception {
		doFilterWhenPushedAuthorizationRequestInvalidParameterThenError(
				TestRegisteredClients.registeredClient().build(), OAuth2ParameterNames.SCOPE,
				OAuth2ErrorCodes.INVALID_REQUEST,
				(request) -> request.addParameter(OAuth2ParameterNames.SCOPE, "scope2"));
	}

	@Test
	public void doFilterWhenPushedAuthorizationRequestMultipleStateThenInvalidRequestError() throws Exception {
		doFilterWhenPushedAuthorizationRequestInvalidParameterThenError(
				TestRegisteredClients.registeredClient().build(), OAuth2ParameterNames.STATE,
				OAuth2ErrorCodes.INVALID_REQUEST,
				(request) -> request.addParameter(OAuth2ParameterNames.STATE, "state2"));
	}

	@Test
	public void doFilterWhenPushedAuthorizationRequestMultipleCodeChallengeThenInvalidRequestError() throws Exception {
		doFilterWhenPushedAuthorizationRequestInvalidParameterThenError(
				TestRegisteredClients.registeredClient().build(), PkceParameterNames.CODE_CHALLENGE,
				OAuth2ErrorCodes.INVALID_REQUEST, (request) -> {
					request.addParameter(PkceParameterNames.CODE_CHALLENGE, "code-challenge");
					request.addParameter(PkceParameterNames.CODE_CHALLENGE, "another-code-challenge");
				});
	}

	@Test
	public void doFilterWhenPushedAuthorizationRequestMultipleCodeChallengeMethodThenInvalidRequestError()
			throws Exception {
		doFilterWhenPushedAuthorizationRequestInvalidParameterThenError(
				TestRegisteredClients.registeredClient().build(), PkceParameterNames.CODE_CHALLENGE_METHOD,
				OAuth2ErrorCodes.INVALID_REQUEST, (request) -> {
					request.addParameter(PkceParameterNames.CODE_CHALLENGE_METHOD, "S256");
					request.addParameter(PkceParameterNames.CODE_CHALLENGE_METHOD, "S256");
				});
	}

	@Test
	public void doFilterWhenPushedAuthenticationRequestMultiplePromptThenInvalidRequestError() throws Exception {
		// Setup OpenID Connect request
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().scopes((scopes) -> {
			scopes.clear();
			scopes.add(OidcScopes.OPENID);
		}).build();
		doFilterWhenPushedAuthorizationRequestInvalidParameterThenError(registeredClient, "prompt",
				OAuth2ErrorCodes.INVALID_REQUEST, (request) -> {
					request.addParameter("prompt", "none");
					request.addParameter("prompt", "login");
				});
	}

	@Test
	public void doFilterWhenPushedAuthorizationRequestAuthenticationExceptionThenErrorResponse() throws Exception {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST, "error description", "error uri");
		given(this.authenticationManager.authenticate(any())).willThrow(new OAuth2AuthenticationException(error));

		MockHttpServletRequest request = createPushedAuthorizationRequest(registeredClient);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verify(this.authenticationManager).authenticate(any());
		verifyNoInteractions(filterChain);

		assertThat(response.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST.value());
		OAuth2Error errorResponse = readError(response);
		assertThat(errorResponse.getErrorCode()).isEqualTo(error.getErrorCode());
		assertThat(errorResponse.getDescription()).isEqualTo(error.getDescription());
		assertThat(errorResponse.getUri()).isEqualTo(error.getUri());
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isSameAs(this.clientPrincipal);
	}

	@Test
	public void doFilterWhenCustomAuthenticationConverterThenUsed() throws Exception {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2PushedAuthorizationRequestAuthenticationToken pushedAuthorizationRequestAuthenticationResult = new OAuth2PushedAuthorizationRequestAuthenticationToken(
				AUTHORIZATION_URI, registeredClient.getClientId(), this.clientPrincipal,
				OAuth2ParameterNames.REQUEST_URI, Instant.now().plusSeconds(30),
				registeredClient.getRedirectUris().iterator().next(), STATE, registeredClient.getScopes());

		AuthenticationConverter authenticationConverter = mock(AuthenticationConverter.class);
		given(authenticationConverter.convert(any())).willReturn(pushedAuthorizationRequestAuthenticationResult);
		this.filter.setAuthenticationConverter(authenticationConverter);

		given(this.authenticationManager.authenticate(any()))
			.willReturn(pushedAuthorizationRequestAuthenticationResult);

		MockHttpServletRequest request = createPushedAuthorizationRequest(registeredClient);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verify(authenticationConverter).convert(any());
		verify(this.authenticationManager).authenticate(any());
	}

	@Test
	public void doFilterWhenCustomAuthenticationSuccessHandlerThenUsed() throws Exception {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2PushedAuthorizationRequestAuthenticationToken pushedAuthorizationRequestAuthenticationResult = new OAuth2PushedAuthorizationRequestAuthenticationToken(
				AUTHORIZATION_URI, registeredClient.getClientId(), this.clientPrincipal,
				OAuth2ParameterNames.REQUEST_URI, Instant.now().plusSeconds(30),
				registeredClient.getRedirectUris().iterator().next(), STATE, registeredClient.getScopes());
		given(this.authenticationManager.authenticate(any()))
			.willReturn(pushedAuthorizationRequestAuthenticationResult);

		AuthenticationSuccessHandler authenticationSuccessHandler = mock(AuthenticationSuccessHandler.class);
		this.filter.setAuthenticationSuccessHandler(authenticationSuccessHandler);

		MockHttpServletRequest request = createPushedAuthorizationRequest(registeredClient);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verify(this.authenticationManager).authenticate(any());
		verifyNoInteractions(filterChain);
		verify(authenticationSuccessHandler).onAuthenticationSuccess(any(), any(),
				same(pushedAuthorizationRequestAuthenticationResult));
	}

	@Test
	public void doFilterWhenCustomAuthenticationFailureHandlerThenUsed() throws Exception {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2Error error = new OAuth2Error("errorCode", "errorDescription", "errorUri");
		OAuth2AuthenticationException authenticationException = new OAuth2AuthenticationException(error);
		given(this.authenticationManager.authenticate(any())).willThrow(authenticationException);

		AuthenticationFailureHandler authenticationFailureHandler = mock(AuthenticationFailureHandler.class);
		this.filter.setAuthenticationFailureHandler(authenticationFailureHandler);

		MockHttpServletRequest request = createPushedAuthorizationRequest(registeredClient);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verify(this.authenticationManager).authenticate(any());
		verifyNoInteractions(filterChain);
		verify(authenticationFailureHandler).onAuthenticationFailure(any(), any(), same(authenticationException));
	}

	@Test
	public void doFilterWhenCustomAuthenticationDetailsSourceThenUsed() throws Exception {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		MockHttpServletRequest request = createPushedAuthorizationRequest(registeredClient);

		AuthenticationDetailsSource<HttpServletRequest, WebAuthenticationDetails> authenticationDetailsSource = mock(
				AuthenticationDetailsSource.class);
		WebAuthenticationDetails webAuthenticationDetails = new WebAuthenticationDetails(request);
		given(authenticationDetailsSource.buildDetails(request)).willReturn(webAuthenticationDetails);
		this.filter.setAuthenticationDetailsSource(authenticationDetailsSource);

		OAuth2PushedAuthorizationRequestAuthenticationToken pushedAuthorizationRequestAuthenticationResult = new OAuth2PushedAuthorizationRequestAuthenticationToken(
				AUTHORIZATION_URI, registeredClient.getClientId(), this.clientPrincipal,
				OAuth2ParameterNames.REQUEST_URI, Instant.now().plusSeconds(30),
				registeredClient.getRedirectUris().iterator().next(), STATE, registeredClient.getScopes());

		given(this.authenticationManager.authenticate(any()))
			.willReturn(pushedAuthorizationRequestAuthenticationResult);

		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verify(authenticationDetailsSource).buildDetails(any());
		verify(this.authenticationManager).authenticate(any());
	}

	@Test
	public void doFilterWhenPushedAuthorizationRequestAuthenticatedThenPushedAuthorizationResponse() throws Exception {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		String requestUri = OAuth2ParameterNames.REQUEST_URI;
		Instant requestUriExpiresAt = Instant.now().plusSeconds(30);
		OAuth2PushedAuthorizationRequestAuthenticationToken pushedAuthorizationRequestAuthenticationResult = new OAuth2PushedAuthorizationRequestAuthenticationToken(
				AUTHORIZATION_URI, registeredClient.getClientId(), this.clientPrincipal, requestUri,
				requestUriExpiresAt, registeredClient.getRedirectUris().iterator().next(), STATE,
				registeredClient.getScopes());
		given(this.authenticationManager.authenticate(any()))
			.willReturn(pushedAuthorizationRequestAuthenticationResult);

		MockHttpServletRequest request = createPushedAuthorizationRequest(registeredClient);
		request.addParameter("custom-param", "custom-value-1", "custom-value-2");

		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		ArgumentCaptor<OAuth2PushedAuthorizationRequestAuthenticationToken> pushedAuthorizationRequestAuthenticationCaptor = ArgumentCaptor
			.forClass(OAuth2PushedAuthorizationRequestAuthenticationToken.class);
		verify(this.authenticationManager).authenticate(pushedAuthorizationRequestAuthenticationCaptor.capture());
		verifyNoInteractions(filterChain);

		assertThat(pushedAuthorizationRequestAuthenticationCaptor.getValue().getDetails())
			.asInstanceOf(InstanceOfAssertFactories.type(WebAuthenticationDetails.class))
			.extracting(WebAuthenticationDetails::getRemoteAddress)
			.isEqualTo(REMOTE_ADDRESS);

		// Assert that multi-valued request parameters are preserved
		assertThat(pushedAuthorizationRequestAuthenticationCaptor.getValue().getAdditionalParameters())
			.extracting((params) -> params.get("custom-param"))
			.asInstanceOf(InstanceOfAssertFactories.type(String[].class))
			.isEqualTo(new String[] { "custom-value-1", "custom-value-2" });
		assertThat(response.getStatus()).isEqualTo(HttpStatus.CREATED.value());
		Map<String, Object> responseParameters = readPushedAuthorizationResponse(response);
		assertThat(responseParameters.get(OAuth2ParameterNames.REQUEST_URI)).isEqualTo(requestUri);
		Instant requestUriExpiry = Instant.now()
			.plusSeconds(Long.parseLong(String.valueOf(responseParameters.get("expires_in"))));
		assertThat(requestUriExpiry).isBetween(requestUriExpiresAt.minusSeconds(1), requestUriExpiresAt.plusSeconds(1));
	}

	private void doFilterWhenPushedAuthorizationRequestInvalidParameterThenError(RegisteredClient registeredClient,
			String parameterName, String errorCode, Consumer<MockHttpServletRequest> requestConsumer) throws Exception {

		doFilterWhenRequestInvalidParameterThenError(createPushedAuthorizationRequest(registeredClient), parameterName,
				errorCode, requestConsumer);
	}

	private void doFilterWhenRequestInvalidParameterThenError(MockHttpServletRequest request, String parameterName,
			String errorCode, Consumer<MockHttpServletRequest> requestConsumer) throws Exception {

		requestConsumer.accept(request);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verifyNoInteractions(filterChain);

		assertThat(response.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST.value());
		OAuth2Error error = readError(response);
		assertThat(error.getErrorCode()).isEqualTo(errorCode);
		assertThat(error.getDescription()).isEqualTo("OAuth 2.0 Parameter: " + parameterName);
	}

	private static MockHttpServletRequest createPushedAuthorizationRequest(RegisteredClient registeredClient) {
		String requestUri = AuthorizationServerContextHolder.getContext()
			.getAuthorizationServerSettings()
			.getPushedAuthorizationRequestEndpoint();
		MockHttpServletRequest request = new MockHttpServletRequest("POST", requestUri);
		request.setServletPath(requestUri);
		request.setRemoteAddr(REMOTE_ADDRESS);

		request.addParameter(OAuth2ParameterNames.RESPONSE_TYPE, OAuth2AuthorizationResponseType.CODE.getValue());
		request.addParameter(OAuth2ParameterNames.CLIENT_ID, registeredClient.getClientId());
		request.addParameter(OAuth2ParameterNames.REDIRECT_URI, registeredClient.getRedirectUris().iterator().next());
		request.addParameter(OAuth2ParameterNames.SCOPE,
				StringUtils.collectionToDelimitedString(registeredClient.getScopes(), " "));
		request.addParameter(OAuth2ParameterNames.STATE, "state");

		return request;
	}

	private OAuth2Error readError(MockHttpServletResponse response) throws Exception {
		MockClientHttpResponse httpResponse = new MockClientHttpResponse(response.getContentAsByteArray(),
				HttpStatus.valueOf(response.getStatus()));
		return this.errorHttpResponseConverter.read(OAuth2Error.class, httpResponse);
	}

	@SuppressWarnings("unchecked")
	private Map<String, Object> readPushedAuthorizationResponse(MockHttpServletResponse response) throws Exception {
		final ParameterizedTypeReference<Map<String, Object>> STRING_OBJECT_MAP = new ParameterizedTypeReference<>() {
		};
		MockClientHttpResponse httpResponse = new MockClientHttpResponse(response.getContentAsByteArray(),
				HttpStatus.valueOf(response.getStatus()));
		return (Map<String, Object>) this.jsonMessageConverter.read(ResolvableType.forType(STRING_OBJECT_MAP.getType()),
				httpResponse, null);
	}

}
