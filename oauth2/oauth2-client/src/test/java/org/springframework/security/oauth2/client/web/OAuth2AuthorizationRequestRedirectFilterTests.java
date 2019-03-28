/*
 * Copyright 2002-2017 the original author or authors.
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

import org.junit.Before;
import org.junit.Test;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

/**
 * Tests for {@link OAuth2AuthorizationRequestRedirectFilter}.
 *
 * @author Joe Grandja
 */
public class OAuth2AuthorizationRequestRedirectFilterTests {
	private ClientRegistration registration1;
	private ClientRegistration registration2;
	private ClientRegistration registration3;
	private ClientRegistrationRepository clientRegistrationRepository;
	private OAuth2AuthorizationRequestRedirectFilter filter;

	@Before
	public void setUp() {
		this.registration1 = ClientRegistration.withRegistrationId("registration-1")
			.clientId("client-1")
			.clientSecret("secret")
			.clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
			.redirectUriTemplate("{baseUrl}/login/oauth2/code/{registrationId}")
			.scope("user")
			.authorizationUri("https://provider.com/oauth2/authorize")
			.tokenUri("https://provider.com/oauth2/token")
			.userInfoUri("https://provider.com/oauth2/user")
			.userNameAttributeName("id")
			.clientName("client-1")
			.build();
		this.registration2 = ClientRegistration.withRegistrationId("registration-2")
			.clientId("client-2")
			.clientSecret("secret")
			.clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
			.redirectUriTemplate("{baseUrl}/login/oauth2/code/{registrationId}")
			.scope("openid", "profile", "email")
			.authorizationUri("https://provider.com/oauth2/authorize")
			.tokenUri("https://provider.com/oauth2/token")
			.userInfoUri("https://provider.com/oauth2/userinfo")
			.jwkSetUri("https://provider.com/oauth2/keys")
			.clientName("client-2")
			.build();
		this.registration3 = ClientRegistration.withRegistrationId("registration-3")
			.clientId("client-3")
			.authorizationGrantType(AuthorizationGrantType.IMPLICIT)
			.redirectUriTemplate("{baseUrl}/login/oauth2/implicit/{registrationId}")
			.scope("openid", "profile", "email")
			.authorizationUri("https://provider.com/oauth2/authorize")
			.tokenUri("https://provider.com/oauth2/token")
			.userInfoUri("https://provider.com/oauth2/userinfo")
			.clientName("client-3")
			.build();
		this.clientRegistrationRepository = new InMemoryClientRegistrationRepository(
			this.registration1, this.registration2, this.registration3);
		this.filter = new OAuth2AuthorizationRequestRedirectFilter(this.clientRegistrationRepository);
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorWhenClientRegistrationRepositoryIsNullThenThrowIllegalArgumentException() {
		new OAuth2AuthorizationRequestRedirectFilter(null);
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorWhenAuthorizationRequestBaseUriIsNullThenThrowIllegalArgumentException() {
		new OAuth2AuthorizationRequestRedirectFilter(this.clientRegistrationRepository, null);
	}

	@Test(expected = IllegalArgumentException.class)
	public void setAuthorizationRequestRepositoryWhenAuthorizationRequestRepositoryIsNullThenThrowIllegalArgumentException() {
		this.filter.setAuthorizationRequestRepository(null);
	}

	@Test
	public void doFilterWhenNotAuthorizationRequestThenNextFilter() throws Exception {
		String requestUri = "/path";
		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestUri);
		request.setServletPath(requestUri);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verify(filterChain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
	}

	@Test
	public void doFilterWhenAuthorizationRequestWithInvalidClientThenStatusBadRequest() throws Exception {
		String requestUri = OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI +
			"/" + this.registration1.getRegistrationId() + "-invalid";
		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestUri);
		request.setServletPath(requestUri);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verifyZeroInteractions(filterChain);

		assertThat(response.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST.value());
		assertThat(response.getErrorMessage()).isEqualTo(HttpStatus.BAD_REQUEST.getReasonPhrase());
	}

	@Test
	public void doFilterWhenAuthorizationRequestAuthorizationCodeGrantThenRedirectForAuthorization() throws Exception {
		String requestUri = OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI +
			"/" + this.registration1.getRegistrationId();
		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestUri);
		request.setServletPath(requestUri);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verifyZeroInteractions(filterChain);

		assertThat(response.getRedirectedUrl()).matches("https://provider.com/oauth2/authorize\\?response_type=code&client_id=client-1&scope=user&state=.{15,}&redirect_uri=http://localhost/login/oauth2/code/registration-1");
	}

	@Test
	public void doFilterWhenAuthorizationRequestAuthorizationCodeGrantThenAuthorizationRequestSavedInSession() throws Exception {
		String requestUri = OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI +
			"/" + this.registration2.getRegistrationId();
		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestUri);
		request.setServletPath(requestUri);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository =
			new HttpSessionOAuth2AuthorizationRequestRepository();
		this.filter.setAuthorizationRequestRepository(authorizationRequestRepository);

		this.filter.doFilter(request, response, filterChain);

		verifyZeroInteractions(filterChain);

		OAuth2AuthorizationRequest authorizationRequest = authorizationRequestRepository.loadAuthorizationRequest(request);

		assertThat(authorizationRequest).isNotNull();
		assertThat(authorizationRequest.getAuthorizationUri()).isEqualTo(
			this.registration2.getProviderDetails().getAuthorizationUri());
		assertThat(authorizationRequest.getGrantType()).isEqualTo(
			this.registration2.getAuthorizationGrantType());
		assertThat(authorizationRequest.getResponseType()).isEqualTo(
			OAuth2AuthorizationResponseType.CODE);
		assertThat(authorizationRequest.getClientId()).isEqualTo(
			this.registration2.getClientId());
		assertThat(authorizationRequest.getRedirectUri()).isEqualTo(
			"http://localhost/login/oauth2/code/registration-2");
		assertThat(authorizationRequest.getScopes()).isEqualTo(
			this.registration2.getScopes());
		assertThat(authorizationRequest.getState()).isNotNull();
		assertThat(authorizationRequest.getAdditionalParameters()
			.get(OAuth2ParameterNames.REGISTRATION_ID)).isEqualTo(this.registration2.getRegistrationId());
	}

	@Test
	public void doFilterWhenAuthorizationRequestImplicitGrantThenRedirectForAuthorization() throws Exception {
		String requestUri = OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI +
			"/" + this.registration3.getRegistrationId();
		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestUri);
		request.setServletPath(requestUri);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verifyZeroInteractions(filterChain);

		assertThat(response.getRedirectedUrl()).matches("https://provider.com/oauth2/authorize\\?response_type=token&client_id=client-3&scope=openid%20profile%20email&state=.{15,}&redirect_uri=http://localhost/login/oauth2/implicit/registration-3");
	}

	@Test
	public void doFilterWhenAuthorizationRequestImplicitGrantThenAuthorizationRequestNotSavedInSession() throws Exception {
		String requestUri = OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI +
			"/" + this.registration3.getRegistrationId();
		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestUri);
		request.setServletPath(requestUri);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository =
			new HttpSessionOAuth2AuthorizationRequestRepository();
		this.filter.setAuthorizationRequestRepository(authorizationRequestRepository);

		this.filter.doFilter(request, response, filterChain);

		verifyZeroInteractions(filterChain);

		OAuth2AuthorizationRequest authorizationRequest = authorizationRequestRepository.loadAuthorizationRequest(request);

		assertThat(authorizationRequest).isNull();
	}

	@Test
	public void doFilterWhenCustomAuthorizationRequestBaseUriThenRedirectForAuthorization() throws Exception {
		String authorizationRequestBaseUri = "/custom/authorization";
		this.filter = new OAuth2AuthorizationRequestRedirectFilter(this.clientRegistrationRepository, authorizationRequestBaseUri);

		String requestUri = authorizationRequestBaseUri + "/" + this.registration1.getRegistrationId();
		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestUri);
		request.setServletPath(requestUri);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verifyZeroInteractions(filterChain);

		assertThat(response.getRedirectedUrl()).matches("https://provider.com/oauth2/authorize\\?response_type=code&client_id=client-1&scope=user&state=.{15,}&redirect_uri=http://localhost/login/oauth2/code/registration-1");
	}

	@Test
	public void doFilterWhenAuthorizationRequestRedirectUriTemplatedThenRedirectUriExpanded() throws Exception {
		String requestUri = OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI +
			"/" + this.registration2.getRegistrationId();
		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestUri);
		request.setServletPath(requestUri);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository =
			new HttpSessionOAuth2AuthorizationRequestRepository();
		this.filter.setAuthorizationRequestRepository(authorizationRequestRepository);

		this.filter.doFilter(request, response, filterChain);

		verifyZeroInteractions(filterChain);

		OAuth2AuthorizationRequest authorizationRequest = authorizationRequestRepository.loadAuthorizationRequest(request);

		assertThat(authorizationRequest.getRedirectUri()).isNotEqualTo(
			this.registration2.getRedirectUriTemplate());
		assertThat(authorizationRequest.getRedirectUri()).isEqualTo(
			"http://localhost/login/oauth2/code/registration-2");
	}

	@Test
	public void doFilterWhenAuthorizationRequestIncludesPort80ThenExpandedRedirectUriExcludesPort() throws Exception {
		String requestUri = OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI +
			"/" + this.registration1.getRegistrationId();
		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestUri);
		request.setScheme("http");
		request.setServerName("localhost");
		request.setServerPort(80);
		request.setServletPath(requestUri);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verifyZeroInteractions(filterChain);

		assertThat(response.getRedirectedUrl()).matches("https://provider.com/oauth2/authorize\\?response_type=code&client_id=client-1&scope=user&state=.{15,}&redirect_uri=http://localhost/login/oauth2/code/registration-1");
	}

	@Test
	public void doFilterWhenAuthorizationRequestIncludesPort443ThenExpandedRedirectUriExcludesPort() throws Exception {
		String requestUri = OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI +
			"/" + this.registration1.getRegistrationId();
		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestUri);
		request.setScheme("https");
		request.setServerName("example.com");
		request.setServerPort(443);
		request.setServletPath(requestUri);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verifyZeroInteractions(filterChain);

		assertThat(response.getRedirectedUrl()).matches("https://provider.com/oauth2/authorize\\?response_type=code&client_id=client-1&scope=user&state=.{15,}&redirect_uri=https://example.com/login/oauth2/code/registration-1");
	}
}
