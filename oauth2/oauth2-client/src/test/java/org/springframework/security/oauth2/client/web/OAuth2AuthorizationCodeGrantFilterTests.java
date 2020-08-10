/*
 * Copyright 2002-2020 the original author or authors.
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
package org.springframework.security.oauth2.client.web;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthorizationCodeAuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.util.CollectionUtils;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.security.oauth2.core.TestOAuth2AccessTokens.noScopes;
import static org.springframework.security.oauth2.core.TestOAuth2RefreshTokens.refreshToken;
import static org.springframework.security.oauth2.core.endpoint.TestOAuth2AuthorizationExchanges.success;
import static org.springframework.security.oauth2.core.endpoint.TestOAuth2AuthorizationRequests.request;

/**
 * Tests for {@link OAuth2AuthorizationCodeGrantFilter}.
 *
 * @author Joe Grandja
 * @author Parikshit Dutta
 */
public class OAuth2AuthorizationCodeGrantFilterTests {

	private ClientRegistration registration1;

	private String principalName1 = "principal-1";

	private ClientRegistrationRepository clientRegistrationRepository;

	private OAuth2AuthorizedClientService authorizedClientService;

	private OAuth2AuthorizedClientRepository authorizedClientRepository;

	private AuthenticationManager authenticationManager;

	private AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository;

	private OAuth2AuthorizationCodeGrantFilter filter;

	@Before
	public void setup() {
		this.registration1 = TestClientRegistrations.clientRegistration().build();
		this.clientRegistrationRepository = new InMemoryClientRegistrationRepository(this.registration1);
		this.authorizedClientService = new InMemoryOAuth2AuthorizedClientService(this.clientRegistrationRepository);
		this.authorizedClientRepository = new AuthenticatedPrincipalOAuth2AuthorizedClientRepository(
				this.authorizedClientService);
		this.authorizationRequestRepository = new HttpSessionOAuth2AuthorizationRequestRepository();
		this.authenticationManager = mock(AuthenticationManager.class);
		this.filter = spy(new OAuth2AuthorizationCodeGrantFilter(this.clientRegistrationRepository,
				this.authorizedClientRepository, this.authenticationManager));
		this.filter.setAuthorizationRequestRepository(this.authorizationRequestRepository);
		TestingAuthenticationToken authentication = new TestingAuthenticationToken(this.principalName1, "password");
		authentication.setAuthenticated(true);
		SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
		securityContext.setAuthentication(authentication);
		SecurityContextHolder.setContext(securityContext);
	}

	@After
	public void cleanup() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void constructorWhenClientRegistrationRepositoryIsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OAuth2AuthorizationCodeGrantFilter(null, this.authorizedClientRepository,
				this.authenticationManager)).isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void constructorWhenAuthorizedClientRepositoryIsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OAuth2AuthorizationCodeGrantFilter(this.clientRegistrationRepository, null,
				this.authenticationManager)).isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void constructorWhenAuthenticationManagerIsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OAuth2AuthorizationCodeGrantFilter(this.clientRegistrationRepository,
				this.authorizedClientRepository, null)).isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void setAuthorizationRequestRepositoryWhenAuthorizationRequestRepositoryIsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> this.filter.setAuthorizationRequestRepository(null))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void setRequestCacheWhenRequestCacheIsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> this.filter.setRequestCache(null)).isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void doFilterWhenNotAuthorizationResponseThenNotProcessed() throws Exception {
		String requestUri = "/path";
		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestUri);
		request.setServletPath(requestUri);
		// NOTE: A valid Authorization Response contains either a 'code' or 'error'
		// parameter.
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verify(filterChain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
	}

	@Test
	public void doFilterWhenAuthorizationRequestNotFoundThenNotProcessed() throws Exception {
		MockHttpServletRequest authorizationRequest = createAuthorizationRequest("/path");
		MockHttpServletRequest authorizationResponse = createAuthorizationResponse(authorizationRequest);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(authorizationResponse, response, filterChain);

		verify(filterChain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
	}

	@Test
	public void doFilterWhenAuthorizationRequestRedirectUriDoesNotMatchThenNotProcessed() throws Exception {
		String requestUri = "/callback/client-1";
		MockHttpServletRequest authorizationRequest = createAuthorizationRequest(requestUri);
		MockHttpServletRequest authorizationResponse = createAuthorizationResponse(authorizationRequest);
		MockHttpServletResponse response = new MockHttpServletResponse();
		this.setUpAuthorizationRequest(authorizationRequest, response, this.registration1);
		authorizationResponse.setRequestURI(requestUri + "-no-match");
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(authorizationResponse, response, filterChain);

		verify(filterChain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
	}

	// gh-7963
	@Test
	public void doFilterWhenAuthorizationRequestRedirectUriParametersMatchThenProcessed() throws Exception {
		// 1) redirect_uri with query parameters
		String requestUri = "/callback/client-1";
		Map<String, String> parameters = new LinkedHashMap<>();
		parameters.put("param1", "value1");
		parameters.put("param2", "value2");
		MockHttpServletRequest authorizationRequest = createAuthorizationRequest(requestUri, parameters);
		MockHttpServletResponse response = new MockHttpServletResponse();
		this.setUpAuthorizationRequest(authorizationRequest, response, this.registration1);
		this.setUpAuthenticationResult(this.registration1);
		FilterChain filterChain = mock(FilterChain.class);
		MockHttpServletRequest authorizationResponse = createAuthorizationResponse(authorizationRequest);
		this.filter.doFilter(authorizationResponse, response, filterChain);
		verifyNoInteractions(filterChain);

		// 2) redirect_uri with query parameters AND authorization response additional
		// parameters
		Map<String, String> additionalParameters = new LinkedHashMap<>();
		additionalParameters.put("auth-param1", "value1");
		additionalParameters.put("auth-param2", "value2");
		response = new MockHttpServletResponse();
		this.setUpAuthorizationRequest(authorizationRequest, response, this.registration1);
		authorizationResponse = createAuthorizationResponse(authorizationRequest, additionalParameters);
		this.filter.doFilter(authorizationResponse, response, filterChain);
		verifyNoInteractions(filterChain);
	}

	// gh-7963
	@Test
	public void doFilterWhenAuthorizationRequestRedirectUriParametersDoesNotMatchThenNotProcessed() throws Exception {
		String requestUri = "/callback/client-1";
		Map<String, String> parameters = new LinkedHashMap<>();
		parameters.put("param1", "value1");
		parameters.put("param2", "value2");
		MockHttpServletRequest authorizationRequest = createAuthorizationRequest(requestUri, parameters);
		MockHttpServletResponse response = new MockHttpServletResponse();
		this.setUpAuthorizationRequest(authorizationRequest, response, this.registration1);
		this.setUpAuthenticationResult(this.registration1);
		FilterChain filterChain = mock(FilterChain.class);

		// 1) Parameter value
		Map<String, String> parametersNotMatch = new LinkedHashMap<>(parameters);
		parametersNotMatch.put("param2", "value8");
		MockHttpServletRequest authorizationResponse = createAuthorizationResponse(
				createAuthorizationRequest(requestUri, parametersNotMatch));
		authorizationResponse.setSession(authorizationRequest.getSession());
		this.filter.doFilter(authorizationResponse, response, filterChain);
		verify(filterChain, times(1)).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));

		// 2) Parameter order
		parametersNotMatch = new LinkedHashMap<>();
		parametersNotMatch.put("param2", "value2");
		parametersNotMatch.put("param1", "value1");
		authorizationResponse = createAuthorizationResponse(createAuthorizationRequest(requestUri, parametersNotMatch));
		authorizationResponse.setSession(authorizationRequest.getSession());
		this.filter.doFilter(authorizationResponse, response, filterChain);
		verify(filterChain, times(2)).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));

		// 3) Parameter missing
		parametersNotMatch = new LinkedHashMap<>(parameters);
		parametersNotMatch.remove("param2");
		authorizationResponse = createAuthorizationResponse(createAuthorizationRequest(requestUri, parametersNotMatch));
		authorizationResponse.setSession(authorizationRequest.getSession());
		this.filter.doFilter(authorizationResponse, response, filterChain);
		verify(filterChain, times(3)).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
	}

	@Test
	public void doFilterWhenAuthorizationRequestMatchThenAuthorizationRequestRemoved() throws Exception {
		MockHttpServletRequest authorizationRequest = createAuthorizationRequest("/callback/client-1");
		MockHttpServletRequest authorizationResponse = createAuthorizationResponse(authorizationRequest);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);
		this.setUpAuthorizationRequest(authorizationRequest, response, this.registration1);
		this.setUpAuthenticationResult(this.registration1);

		this.filter.doFilter(authorizationResponse, response, filterChain);

		assertThat(this.authorizationRequestRepository.loadAuthorizationRequest(authorizationResponse)).isNull();
	}

	@Test
	public void doFilterWhenAuthorizationFailsThenHandleOAuth2AuthorizationException() throws Exception {
		MockHttpServletRequest authorizationRequest = createAuthorizationRequest("/callback/client-1");
		MockHttpServletRequest authorizationResponse = createAuthorizationResponse(authorizationRequest);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);
		this.setUpAuthorizationRequest(authorizationRequest, response, this.registration1);

		OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT);
		when(this.authenticationManager.authenticate(any(Authentication.class)))
				.thenThrow(new OAuth2AuthorizationException(error));

		this.filter.doFilter(authorizationResponse, response, filterChain);

		assertThat(response.getRedirectedUrl()).isEqualTo("http://localhost/callback/client-1?error=invalid_grant");
	}

	@Test
	public void doFilterWhenAuthorizationSucceedsThenAuthorizedClientSavedToService() throws Exception {
		MockHttpServletRequest authorizationRequest = createAuthorizationRequest("/callback/client-1");
		MockHttpServletRequest authorizationResponse = createAuthorizationResponse(authorizationRequest);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);
		this.setUpAuthorizationRequest(authorizationRequest, response, this.registration1);
		this.setUpAuthenticationResult(this.registration1);

		this.filter.doFilter(authorizationResponse, response, filterChain);

		OAuth2AuthorizedClient authorizedClient = this.authorizedClientService
				.loadAuthorizedClient(this.registration1.getRegistrationId(), this.principalName1);
		assertThat(authorizedClient).isNotNull();
		assertThat(authorizedClient.getClientRegistration()).isEqualTo(this.registration1);
		assertThat(authorizedClient.getPrincipalName()).isEqualTo(this.principalName1);
		assertThat(authorizedClient.getAccessToken()).isNotNull();
		assertThat(authorizedClient.getRefreshToken()).isNotNull();
	}

	@Test
	public void doFilterWhenAuthorizationSucceedsThenRedirected() throws Exception {
		MockHttpServletRequest authorizationRequest = createAuthorizationRequest("/callback/client-1");
		MockHttpServletRequest authorizationResponse = createAuthorizationResponse(authorizationRequest);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);
		this.setUpAuthorizationRequest(authorizationRequest, response, this.registration1);
		this.setUpAuthenticationResult(this.registration1);

		this.filter.doFilter(authorizationResponse, response, filterChain);

		assertThat(response.getRedirectedUrl()).isEqualTo("http://localhost/callback/client-1");
	}

	@Test
	public void doFilterWhenAuthorizationSucceedsAndHasSavedRequestThenRedirectToSavedRequest() throws Exception {
		String requestUri = "/saved-request";
		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestUri);
		request.setServletPath(requestUri);
		MockHttpServletResponse response = new MockHttpServletResponse();
		RequestCache requestCache = new HttpSessionRequestCache();
		requestCache.saveRequest(request, response);
		request.setRequestURI("/callback/client-1");
		request.addParameter(OAuth2ParameterNames.CODE, "code");
		request.addParameter(OAuth2ParameterNames.STATE, "state");
		FilterChain filterChain = mock(FilterChain.class);
		this.setUpAuthorizationRequest(request, response, this.registration1);
		this.setUpAuthenticationResult(this.registration1);

		this.filter.doFilter(request, response, filterChain);

		assertThat(response.getRedirectedUrl()).isEqualTo("http://localhost/saved-request");
	}

	@Test
	public void doFilterWhenAuthorizationSucceedsAndRequestCacheConfiguredThenRequestCacheUsed() throws Exception {
		MockHttpServletRequest authorizationRequest = createAuthorizationRequest("/callback/client-1");
		MockHttpServletRequest authorizationResponse = createAuthorizationResponse(authorizationRequest);
		MockHttpServletResponse response = new MockHttpServletResponse();

		FilterChain filterChain = mock(FilterChain.class);
		this.setUpAuthorizationRequest(authorizationRequest, response, this.registration1);
		this.setUpAuthenticationResult(this.registration1);

		RequestCache requestCache = spy(HttpSessionRequestCache.class);
		this.filter.setRequestCache(requestCache);

		authorizationRequest.setRequestURI("/saved-request");
		requestCache.saveRequest(authorizationRequest, response);

		this.filter.doFilter(authorizationResponse, response, filterChain);

		verify(requestCache).getRequest(any(HttpServletRequest.class), any(HttpServletResponse.class));
		assertThat(response.getRedirectedUrl()).isEqualTo("http://localhost/saved-request");
	}

	@Test
	public void doFilterWhenAuthorizationSucceedsAndAnonymousAccessThenAuthorizedClientSavedToHttpSession()
			throws Exception {
		AnonymousAuthenticationToken anonymousPrincipal = new AnonymousAuthenticationToken("key-1234", "anonymousUser",
				AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));
		SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
		securityContext.setAuthentication(anonymousPrincipal);
		SecurityContextHolder.setContext(securityContext);

		MockHttpServletRequest authorizationRequest = createAuthorizationRequest("/callback/client-1");
		MockHttpServletRequest authorizationResponse = createAuthorizationResponse(authorizationRequest);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);
		this.setUpAuthorizationRequest(authorizationRequest, response, this.registration1);
		this.setUpAuthenticationResult(this.registration1);

		this.filter.doFilter(authorizationResponse, response, filterChain);

		OAuth2AuthorizedClient authorizedClient = this.authorizedClientRepository.loadAuthorizedClient(
				this.registration1.getRegistrationId(), anonymousPrincipal, authorizationResponse);
		assertThat(authorizedClient).isNotNull();
		assertThat(authorizedClient.getClientRegistration()).isEqualTo(this.registration1);
		assertThat(authorizedClient.getPrincipalName()).isEqualTo(anonymousPrincipal.getName());
		assertThat(authorizedClient.getAccessToken()).isNotNull();

		HttpSession session = authorizationResponse.getSession(false);
		assertThat(session).isNotNull();

		@SuppressWarnings("unchecked")
		Map<String, OAuth2AuthorizedClient> authorizedClients = (Map<String, OAuth2AuthorizedClient>) session
				.getAttribute(HttpSessionOAuth2AuthorizedClientRepository.class.getName() + ".AUTHORIZED_CLIENTS");
		assertThat(authorizedClients).isNotEmpty();
		assertThat(authorizedClients).hasSize(1);
		assertThat(authorizedClients.values().iterator().next()).isSameAs(authorizedClient);
	}

	@Test
	public void doFilterWhenAuthorizationSucceedsAndAnonymousAccessNullAuthenticationThenAuthorizedClientSavedToHttpSession()
			throws Exception {
		SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
		SecurityContextHolder.setContext(securityContext); // null Authentication

		MockHttpServletRequest authorizationRequest = createAuthorizationRequest("/callback/client-1");
		MockHttpServletRequest authorizationResponse = createAuthorizationResponse(authorizationRequest);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);
		this.setUpAuthorizationRequest(authorizationRequest, response, this.registration1);
		this.setUpAuthenticationResult(this.registration1);

		this.filter.doFilter(authorizationResponse, response, filterChain);

		OAuth2AuthorizedClient authorizedClient = this.authorizedClientRepository
				.loadAuthorizedClient(this.registration1.getRegistrationId(), null, authorizationResponse);
		assertThat(authorizedClient).isNotNull();
		assertThat(authorizedClient.getClientRegistration()).isEqualTo(this.registration1);
		assertThat(authorizedClient.getPrincipalName()).isEqualTo("anonymousUser");
		assertThat(authorizedClient.getAccessToken()).isNotNull();

		HttpSession session = authorizationResponse.getSession(false);
		assertThat(session).isNotNull();

		@SuppressWarnings("unchecked")
		Map<String, OAuth2AuthorizedClient> authorizedClients = (Map<String, OAuth2AuthorizedClient>) session
				.getAttribute(HttpSessionOAuth2AuthorizedClientRepository.class.getName() + ".AUTHORIZED_CLIENTS");
		assertThat(authorizedClients).isNotEmpty();
		assertThat(authorizedClients).hasSize(1);
		assertThat(authorizedClients.values().iterator().next()).isSameAs(authorizedClient);
	}

	private static MockHttpServletRequest createAuthorizationRequest(String requestUri) {
		return createAuthorizationRequest(requestUri, new LinkedHashMap<>());
	}

	private static MockHttpServletRequest createAuthorizationRequest(String requestUri,
			Map<String, String> parameters) {
		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestUri);
		request.setServletPath(requestUri);
		if (!CollectionUtils.isEmpty(parameters)) {
			parameters.forEach(request::addParameter);
			request.setQueryString(parameters.entrySet().stream().map(e -> e.getKey() + "=" + e.getValue())
					.collect(Collectors.joining("&")));
		}
		return request;
	}

	private static MockHttpServletRequest createAuthorizationResponse(MockHttpServletRequest authorizationRequest) {
		return createAuthorizationResponse(authorizationRequest, new LinkedHashMap<>());
	}

	private static MockHttpServletRequest createAuthorizationResponse(MockHttpServletRequest authorizationRequest,
			Map<String, String> additionalParameters) {
		MockHttpServletRequest authorizationResponse = new MockHttpServletRequest(authorizationRequest.getMethod(),
				authorizationRequest.getRequestURI());
		authorizationResponse.setServletPath(authorizationRequest.getRequestURI());
		authorizationRequest.getParameterMap().forEach(authorizationResponse::addParameter);
		authorizationResponse.addParameter(OAuth2ParameterNames.CODE, "code");
		authorizationResponse.addParameter(OAuth2ParameterNames.STATE, "state");
		additionalParameters.forEach(authorizationResponse::addParameter);
		authorizationResponse.setQueryString(authorizationResponse.getParameterMap().entrySet().stream()
				.map(e -> e.getKey() + "=" + e.getValue()[0]).collect(Collectors.joining("&")));
		authorizationResponse.setSession(authorizationRequest.getSession());
		return authorizationResponse;
	}

	private void setUpAuthorizationRequest(HttpServletRequest request, HttpServletResponse response,
			ClientRegistration registration) {
		Map<String, Object> attributes = new HashMap<>();
		attributes.put(OAuth2ParameterNames.REGISTRATION_ID, registration.getRegistrationId());
		OAuth2AuthorizationRequest authorizationRequest = request().attributes(attributes)
				.redirectUri(UrlUtils.buildFullRequestUrl(request)).build();
		this.authorizationRequestRepository.saveAuthorizationRequest(authorizationRequest, request, response);
	}

	private void setUpAuthenticationResult(ClientRegistration registration) {
		OAuth2AuthorizationCodeAuthenticationToken authentication = new OAuth2AuthorizationCodeAuthenticationToken(
				registration, success(), noScopes(), refreshToken());
		when(this.authenticationManager.authenticate(any(Authentication.class))).thenReturn(authentication);
	}

}
