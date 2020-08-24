/*
 * Copyright 2002-2019 the original author or authors.
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

import java.util.HashMap;
import java.util.Map;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.TestOAuth2AuthorizationExchanges;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.web.util.UriComponentsBuilder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyZeroInteractions;

/**
 * Tests for {@link OAuth2LoginAuthenticationFilter}.
 *
 * @author Joe Grandja
 */
public class OAuth2LoginAuthenticationFilterTests {

	private ClientRegistration registration1;

	private ClientRegistration registration2;

	private String principalName1 = "principal-1";

	private ClientRegistrationRepository clientRegistrationRepository;

	private OAuth2AuthorizedClientRepository authorizedClientRepository;

	private OAuth2AuthorizedClientService authorizedClientService;

	private AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository;

	private AuthenticationFailureHandler failureHandler;

	private AuthenticationManager authenticationManager;

	private AuthenticationDetailsSource authenticationDetailsSource;

	private OAuth2LoginAuthenticationToken loginAuthentication;

	private OAuth2LoginAuthenticationFilter filter;

	@Before
	public void setUp() {
		this.registration1 = TestClientRegistrations.clientRegistration().build();
		this.registration2 = TestClientRegistrations.clientRegistration2().build();
		this.clientRegistrationRepository = new InMemoryClientRegistrationRepository(this.registration1,
				this.registration2);
		this.authorizedClientService = new InMemoryOAuth2AuthorizedClientService(this.clientRegistrationRepository);
		this.authorizedClientRepository = new AuthenticatedPrincipalOAuth2AuthorizedClientRepository(
				this.authorizedClientService);
		this.authorizationRequestRepository = new HttpSessionOAuth2AuthorizationRequestRepository();
		this.failureHandler = mock(AuthenticationFailureHandler.class);
		this.authenticationManager = mock(AuthenticationManager.class);
		this.authenticationDetailsSource = mock(AuthenticationDetailsSource.class);
		this.filter = spy(new OAuth2LoginAuthenticationFilter(this.clientRegistrationRepository,
				this.authorizedClientRepository, OAuth2LoginAuthenticationFilter.DEFAULT_FILTER_PROCESSES_URI));
		this.filter.setAuthorizationRequestRepository(this.authorizationRequestRepository);
		this.filter.setAuthenticationFailureHandler(this.failureHandler);
		this.filter.setAuthenticationManager(this.authenticationManager);
		this.filter.setAuthenticationDetailsSource(this.authenticationDetailsSource);
	}

	@Test
	public void constructorWhenClientRegistrationRepositoryIsNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new OAuth2LoginAuthenticationFilter(null, this.authorizedClientService));
	}

	@Test
	public void constructorWhenAuthorizedClientServiceIsNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new OAuth2LoginAuthenticationFilter(this.clientRegistrationRepository, null));
	}

	@Test
	public void constructorWhenAuthorizedClientRepositoryIsNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new OAuth2LoginAuthenticationFilter(this.clientRegistrationRepository,
						(OAuth2AuthorizedClientRepository) null,
						OAuth2LoginAuthenticationFilter.DEFAULT_FILTER_PROCESSES_URI));
	}

	@Test
	public void constructorWhenFilterProcessesUrlIsNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new OAuth2LoginAuthenticationFilter(this.clientRegistrationRepository,
						this.authorizedClientRepository, null));
	}

	@Test
	public void setAuthorizationRequestRepositoryWhenAuthorizationRequestRepositoryIsNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.filter.setAuthorizationRequestRepository(null));
	}

	@Test
	public void doFilterWhenNotAuthorizationResponseThenNextFilter() throws Exception {
		String requestUri = "/path";
		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestUri);
		request.setServletPath(requestUri);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);
		this.filter.doFilter(request, response, filterChain);
		verify(filterChain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
		verify(this.filter, never()).attemptAuthentication(any(HttpServletRequest.class),
				any(HttpServletResponse.class));
	}

	@Test
	public void doFilterWhenAuthorizationResponseInvalidThenInvalidRequestError() throws Exception {
		String requestUri = "/login/oauth2/code/" + this.registration1.getRegistrationId();
		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestUri);
		request.setServletPath(requestUri);
		// NOTE:
		// A valid Authorization Response contains either a 'code' or 'error' parameter.
		// Don't set it to force an invalid Authorization Response.
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);
		this.filter.doFilter(request, response, filterChain);
		ArgumentCaptor<AuthenticationException> authenticationExceptionArgCaptor = ArgumentCaptor
				.forClass(AuthenticationException.class);
		verify(this.failureHandler).onAuthenticationFailure(any(HttpServletRequest.class),
				any(HttpServletResponse.class), authenticationExceptionArgCaptor.capture());
		assertThat(authenticationExceptionArgCaptor.getValue()).isInstanceOf(OAuth2AuthenticationException.class);
		OAuth2AuthenticationException authenticationException = (OAuth2AuthenticationException) authenticationExceptionArgCaptor
				.getValue();
		assertThat(authenticationException.getError().getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_REQUEST);
	}

	@Test
	public void doFilterWhenAuthorizationResponseAuthorizationRequestNotFoundThenAuthorizationRequestNotFoundError()
			throws Exception {
		String requestUri = "/login/oauth2/code/" + this.registration2.getRegistrationId();
		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestUri);
		request.setServletPath(requestUri);
		request.addParameter(OAuth2ParameterNames.CODE, "code");
		request.addParameter(OAuth2ParameterNames.STATE, "state");
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);
		this.filter.doFilter(request, response, filterChain);
		ArgumentCaptor<AuthenticationException> authenticationExceptionArgCaptor = ArgumentCaptor
				.forClass(AuthenticationException.class);
		verify(this.failureHandler).onAuthenticationFailure(any(HttpServletRequest.class),
				any(HttpServletResponse.class), authenticationExceptionArgCaptor.capture());
		assertThat(authenticationExceptionArgCaptor.getValue()).isInstanceOf(OAuth2AuthenticationException.class);
		OAuth2AuthenticationException authenticationException = (OAuth2AuthenticationException) authenticationExceptionArgCaptor
				.getValue();
		assertThat(authenticationException.getError().getErrorCode()).isEqualTo("authorization_request_not_found");
	}

	// gh-5251
	@Test
	public void doFilterWhenAuthorizationResponseClientRegistrationNotFoundThenClientRegistrationNotFoundError()
			throws Exception {
		String requestUri = "/login/oauth2/code/" + this.registration2.getRegistrationId();
		String state = "state";
		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestUri);
		request.setServletPath(requestUri);
		request.addParameter(OAuth2ParameterNames.CODE, "code");
		request.addParameter(OAuth2ParameterNames.STATE, "state");
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);
		// @formatter:off
		ClientRegistration registrationNotFound = ClientRegistration.withRegistrationId("registration-not-found")
				.clientId("client-1")
				.clientSecret("secret")
				.clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
				.scope("user")
				.authorizationUri("https://provider.com/oauth2/authorize")
				.tokenUri("https://provider.com/oauth2/token")
				.userInfoUri("https://provider.com/oauth2/user")
				.userNameAttributeName("id")
				.clientName("client-1")
				.build();
		// @formatter:on
		this.setUpAuthorizationRequest(request, response, registrationNotFound, state);
		this.filter.doFilter(request, response, filterChain);
		ArgumentCaptor<AuthenticationException> authenticationExceptionArgCaptor = ArgumentCaptor
				.forClass(AuthenticationException.class);
		verify(this.failureHandler).onAuthenticationFailure(any(HttpServletRequest.class),
				any(HttpServletResponse.class), authenticationExceptionArgCaptor.capture());
		assertThat(authenticationExceptionArgCaptor.getValue()).isInstanceOf(OAuth2AuthenticationException.class);
		OAuth2AuthenticationException authenticationException = (OAuth2AuthenticationException) authenticationExceptionArgCaptor
				.getValue();
		assertThat(authenticationException.getError().getErrorCode()).isEqualTo("client_registration_not_found");
	}

	@Test
	public void doFilterWhenAuthorizationResponseValidThenAuthorizationRequestRemoved() throws Exception {
		String requestUri = "/login/oauth2/code/" + this.registration2.getRegistrationId();
		String state = "state";
		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestUri);
		request.setServletPath(requestUri);
		request.addParameter(OAuth2ParameterNames.CODE, "code");
		request.addParameter(OAuth2ParameterNames.STATE, state);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);
		this.setUpAuthorizationRequest(request, response, this.registration2, state);
		this.setUpAuthenticationResult(this.registration2);
		this.filter.doFilter(request, response, filterChain);
		assertThat(this.authorizationRequestRepository.loadAuthorizationRequest(request)).isNull();
	}

	@Test
	public void doFilterWhenAuthorizationResponseValidThenAuthorizedClientSaved() throws Exception {
		String requestUri = "/login/oauth2/code/" + this.registration1.getRegistrationId();
		String state = "state";
		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestUri);
		request.setServletPath(requestUri);
		request.addParameter(OAuth2ParameterNames.CODE, "code");
		request.addParameter(OAuth2ParameterNames.STATE, state);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);
		this.setUpAuthorizationRequest(request, response, this.registration1, state);
		this.setUpAuthenticationResult(this.registration1);
		this.filter.doFilter(request, response, filterChain);
		OAuth2AuthorizedClient authorizedClient = this.authorizedClientRepository
				.loadAuthorizedClient(this.registration1.getRegistrationId(), this.loginAuthentication, request);
		assertThat(authorizedClient).isNotNull();
		assertThat(authorizedClient.getClientRegistration()).isEqualTo(this.registration1);
		assertThat(authorizedClient.getPrincipalName()).isEqualTo(this.principalName1);
		assertThat(authorizedClient.getAccessToken()).isNotNull();
		assertThat(authorizedClient.getRefreshToken()).isNotNull();
	}

	@Test
	public void doFilterWhenCustomFilterProcessesUrlThenFilterProcesses() throws Exception {
		String filterProcessesUrl = "/login/oauth2/custom/*";
		this.filter = spy(new OAuth2LoginAuthenticationFilter(this.clientRegistrationRepository,
				this.authorizedClientRepository, filterProcessesUrl));
		this.filter.setAuthenticationManager(this.authenticationManager);
		String requestUri = "/login/oauth2/custom/" + this.registration2.getRegistrationId();
		String state = "state";
		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestUri);
		request.setServletPath(requestUri);
		request.addParameter(OAuth2ParameterNames.CODE, "code");
		request.addParameter(OAuth2ParameterNames.STATE, state);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);
		this.setUpAuthorizationRequest(request, response, this.registration2, state);
		this.setUpAuthenticationResult(this.registration2);
		this.filter.doFilter(request, response, filterChain);
		verifyZeroInteractions(filterChain);
		verify(this.filter).attemptAuthentication(any(HttpServletRequest.class), any(HttpServletResponse.class));
	}

	// gh-5890
	@Test
	public void doFilterWhenAuthorizationResponseHasDefaultPort80ThenRedirectUriMatchingExcludesPort()
			throws Exception {
		String requestUri = "/login/oauth2/code/" + this.registration2.getRegistrationId();
		String state = "state";
		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestUri);
		request.setScheme("http");
		request.setServerName("localhost");
		request.setServerPort(80);
		request.setServletPath(requestUri);
		request.addParameter(OAuth2ParameterNames.CODE, "code");
		request.addParameter(OAuth2ParameterNames.STATE, "state");
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);
		this.setUpAuthorizationRequest(request, response, this.registration2, state);
		this.setUpAuthenticationResult(this.registration2);
		this.filter.doFilter(request, response, filterChain);
		ArgumentCaptor<Authentication> authenticationArgCaptor = ArgumentCaptor.forClass(Authentication.class);
		verify(this.authenticationManager).authenticate(authenticationArgCaptor.capture());
		OAuth2LoginAuthenticationToken authentication = (OAuth2LoginAuthenticationToken) authenticationArgCaptor
				.getValue();
		OAuth2AuthorizationRequest authorizationRequest = authentication.getAuthorizationExchange()
				.getAuthorizationRequest();
		OAuth2AuthorizationResponse authorizationResponse = authentication.getAuthorizationExchange()
				.getAuthorizationResponse();
		String expectedRedirectUri = "http://localhost/login/oauth2/code/registration-id-2";
		assertThat(authorizationRequest.getRedirectUri()).isEqualTo(expectedRedirectUri);
		assertThat(authorizationResponse.getRedirectUri()).isEqualTo(expectedRedirectUri);
	}

	// gh-5890
	@Test
	public void doFilterWhenAuthorizationResponseHasDefaultPort443ThenRedirectUriMatchingExcludesPort()
			throws Exception {
		String requestUri = "/login/oauth2/code/" + this.registration2.getRegistrationId();
		String state = "state";
		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestUri);
		request.setScheme("https");
		request.setServerName("example.com");
		request.setServerPort(443);
		request.setServletPath(requestUri);
		request.addParameter(OAuth2ParameterNames.CODE, "code");
		request.addParameter(OAuth2ParameterNames.STATE, "state");
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);
		this.setUpAuthorizationRequest(request, response, this.registration2, state);
		this.setUpAuthenticationResult(this.registration2);
		this.filter.doFilter(request, response, filterChain);
		ArgumentCaptor<Authentication> authenticationArgCaptor = ArgumentCaptor.forClass(Authentication.class);
		verify(this.authenticationManager).authenticate(authenticationArgCaptor.capture());
		OAuth2LoginAuthenticationToken authentication = (OAuth2LoginAuthenticationToken) authenticationArgCaptor
				.getValue();
		OAuth2AuthorizationRequest authorizationRequest = authentication.getAuthorizationExchange()
				.getAuthorizationRequest();
		OAuth2AuthorizationResponse authorizationResponse = authentication.getAuthorizationExchange()
				.getAuthorizationResponse();
		String expectedRedirectUri = "https://example.com/login/oauth2/code/registration-id-2";
		assertThat(authorizationRequest.getRedirectUri()).isEqualTo(expectedRedirectUri);
		assertThat(authorizationResponse.getRedirectUri()).isEqualTo(expectedRedirectUri);
	}

	// gh-5890
	@Test
	public void doFilterWhenAuthorizationResponseHasNonDefaultPortThenRedirectUriMatchingIncludesPort()
			throws Exception {
		String requestUri = "/login/oauth2/code/" + this.registration2.getRegistrationId();
		String state = "state";
		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestUri);
		request.setScheme("https");
		request.setServerName("example.com");
		request.setServerPort(9090);
		request.setServletPath(requestUri);
		request.addParameter(OAuth2ParameterNames.CODE, "code");
		request.addParameter(OAuth2ParameterNames.STATE, "state");
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);
		this.setUpAuthorizationRequest(request, response, this.registration2, state);
		this.setUpAuthenticationResult(this.registration2);
		this.filter.doFilter(request, response, filterChain);
		ArgumentCaptor<Authentication> authenticationArgCaptor = ArgumentCaptor.forClass(Authentication.class);
		verify(this.authenticationManager).authenticate(authenticationArgCaptor.capture());
		OAuth2LoginAuthenticationToken authentication = (OAuth2LoginAuthenticationToken) authenticationArgCaptor
				.getValue();
		OAuth2AuthorizationRequest authorizationRequest = authentication.getAuthorizationExchange()
				.getAuthorizationRequest();
		OAuth2AuthorizationResponse authorizationResponse = authentication.getAuthorizationExchange()
				.getAuthorizationResponse();
		String expectedRedirectUri = "https://example.com:9090/login/oauth2/code/registration-id-2";
		assertThat(authorizationRequest.getRedirectUri()).isEqualTo(expectedRedirectUri);
		assertThat(authorizationResponse.getRedirectUri()).isEqualTo(expectedRedirectUri);
	}

	// gh-6866
	@Test
	public void attemptAuthenticationShouldSetAuthenticationDetailsOnAuthenticationResult() throws Exception {
		String requestUri = "/login/oauth2/code/" + this.registration1.getRegistrationId();
		String state = "state";
		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestUri);
		request.setServletPath(requestUri);
		request.addParameter(OAuth2ParameterNames.CODE, "code");
		request.addParameter(OAuth2ParameterNames.STATE, state);
		WebAuthenticationDetails webAuthenticationDetails = mock(WebAuthenticationDetails.class);
		given(this.authenticationDetailsSource.buildDetails(any())).willReturn(webAuthenticationDetails);
		MockHttpServletResponse response = new MockHttpServletResponse();
		this.setUpAuthorizationRequest(request, response, this.registration2, state);
		this.setUpAuthenticationResult(this.registration2);
		Authentication result = this.filter.attemptAuthentication(request, response);
		assertThat(result.getDetails()).isEqualTo(webAuthenticationDetails);
	}

	private void setUpAuthorizationRequest(HttpServletRequest request, HttpServletResponse response,
			ClientRegistration registration, String state) {
		Map<String, Object> attributes = new HashMap<>();
		attributes.put(OAuth2ParameterNames.REGISTRATION_ID, registration.getRegistrationId());
		OAuth2AuthorizationRequest authorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
				.authorizationUri(registration.getProviderDetails().getAuthorizationUri())
				.clientId(registration.getClientId()).redirectUri(expandRedirectUri(request, registration))
				.scopes(registration.getScopes()).state(state).attributes(attributes).build();
		this.authorizationRequestRepository.saveAuthorizationRequest(authorizationRequest, request, response);
	}

	private String expandRedirectUri(HttpServletRequest request, ClientRegistration clientRegistration) {
		String baseUrl = UriComponentsBuilder.fromHttpUrl(UrlUtils.buildFullRequestUrl(request)).replaceQuery(null)
				.replacePath(request.getContextPath()).build().toUriString();
		Map<String, String> uriVariables = new HashMap<>();
		uriVariables.put("baseUrl", baseUrl);
		uriVariables.put("action", "login");
		uriVariables.put("registrationId", clientRegistration.getRegistrationId());
		return UriComponentsBuilder.fromUriString(clientRegistration.getRedirectUri()).buildAndExpand(uriVariables)
				.toUriString();
	}

	private void setUpAuthenticationResult(ClientRegistration registration) {
		OAuth2User user = mock(OAuth2User.class);
		given(user.getName()).willReturn(this.principalName1);
		this.loginAuthentication = mock(OAuth2LoginAuthenticationToken.class);
		given(this.loginAuthentication.getPrincipal()).willReturn(user);
		given(this.loginAuthentication.getName()).willReturn(this.principalName1);
		given(this.loginAuthentication.getAuthorities()).willReturn(AuthorityUtils.createAuthorityList("ROLE_USER"));
		given(this.loginAuthentication.getClientRegistration()).willReturn(registration);
		given(this.loginAuthentication.getAuthorizationExchange())
				.willReturn(TestOAuth2AuthorizationExchanges.success());
		given(this.loginAuthentication.getAccessToken()).willReturn(mock(OAuth2AccessToken.class));
		given(this.loginAuthentication.getRefreshToken()).willReturn(mock(OAuth2RefreshToken.class));
		given(this.loginAuthentication.isAuthenticated()).willReturn(true);
		given(this.authenticationManager.authenticate(any(Authentication.class))).willReturn(this.loginAuthentication);
	}

}
