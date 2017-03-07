/*
 * Copyright 2012-2017 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.oauth2.client.authorization;

import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.client.authorization.AuthorizationRequestRedirectFilter;
import org.springframework.security.oauth2.client.authorization.AuthorizationRequestRepository;
import org.springframework.security.oauth2.client.authorization.AuthorizationRequestUriBuilder;
import org.springframework.security.oauth2.client.authorization.HttpSessionAuthorizationRequestRepository;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.protocol.AuthorizationRequestAttributes;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.net.URI;
import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;
import static org.springframework.security.oauth2.client.ClientRegistrationTestUtil.*;

/**
 * Tests {@link AuthorizationRequestRedirectFilter}.
 *
 * @author Joe Grandja
 */
public class AuthorizationRequestRedirectFilterTests {

	@Test(expected = IllegalArgumentException.class)
	public void constructorWhenFilterProcessingBaseUriIsNullThenThrowIllegalArgumentException() {
		new AuthorizationRequestRedirectFilter(null, mock(ClientRegistrationRepository.class), mock(AuthorizationRequestUriBuilder.class));
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorWhenClientRegistrationRepositoryIsNullThenThrowIllegalArgumentException() {
		new AuthorizationRequestRedirectFilter(null, mock(AuthorizationRequestUriBuilder.class));
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorWhenAuthorizationRequestUriBuilderIsNullThenThrowIllegalArgumentException() {
		new AuthorizationRequestRedirectFilter(mock(ClientRegistrationRepository.class), null);
	}

	@Test(expected = IllegalArgumentException.class)
	public void afterPropertiesSetWhenClientRegistrationsIsEmptyThenThrowIllegalArgumentException() {
		ClientRegistrationRepository clientRegistrationRepository = mock(ClientRegistrationRepository.class);
		when(clientRegistrationRepository.getRegistrations()).thenReturn(Collections.emptyList());
		AuthorizationRequestRedirectFilter filter = new AuthorizationRequestRedirectFilter(
				clientRegistrationRepository, mock(AuthorizationRequestUriBuilder.class));
		filter.afterPropertiesSet();
	}

	@Test
	public void doFilterWhenRequestDoesNotMatchClientThenContinueChain() throws Exception {
		ClientRegistration clientRegistration = googleClientRegistration();
		String authorizationUri = clientRegistration.getProviderDetails().getAuthorizationUri().toString();
		AuthorizationRequestRedirectFilter filter =
				setupFilter(authorizationUri, clientRegistration);

		String requestURI = "/path";
		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestURI);
		request.setServletPath(requestURI);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		filter.doFilter(request, response, filterChain);

		verify(filterChain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
	}

	@Test
	public void doFilterWhenRequestMatchesClientThenRedirectForAuthorization() throws Exception {
		ClientRegistration clientRegistration = googleClientRegistration();
		String authorizationUri = clientRegistration.getProviderDetails().getAuthorizationUri().toString();
		AuthorizationRequestRedirectFilter filter =
				setupFilter(authorizationUri, clientRegistration);

		String requestUri = AuthorizationRequestRedirectFilter.DEFAULT_FILTER_PROCESSING_URI +
				"/" + clientRegistration.getClientAlias();
		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestUri);
		request.setServletPath(requestUri);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		filter.doFilter(request, response, filterChain);

		verifyZeroInteractions(filterChain);        // Request should not proceed up the chain

		assertThat(response.getRedirectedUrl()).isEqualTo(authorizationUri);
	}

	@Test
	public void doFilterWhenRequestMatchesClientThenAuthorizationRequestSavedInSession() throws Exception {
		ClientRegistration clientRegistration = githubClientRegistration();
		String authorizationUri = clientRegistration.getProviderDetails().getAuthorizationUri().toString();
		AuthorizationRequestRedirectFilter filter =
				setupFilter(authorizationUri, clientRegistration);
		AuthorizationRequestRepository authorizationRequestRepository = new HttpSessionAuthorizationRequestRepository();
		filter.setAuthorizationRequestRepository(authorizationRequestRepository);

		String requestUri = AuthorizationRequestRedirectFilter.DEFAULT_FILTER_PROCESSING_URI +
				"/" + clientRegistration.getClientAlias();
		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestUri);
		request.setServletPath(requestUri);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		filter.doFilter(request, response, filterChain);

		verifyZeroInteractions(filterChain);        // Request should not proceed up the chain

		// The authorization request attributes are saved in the session before the redirect happens
		AuthorizationRequestAttributes authorizationRequestAttributes =
				authorizationRequestRepository.loadAuthorizationRequest(request);
		assertThat(authorizationRequestAttributes).isNotNull();

		assertThat(authorizationRequestAttributes.getAuthorizeUri()).isNotNull();
		assertThat(authorizationRequestAttributes.getGrantType()).isNotNull();
		assertThat(authorizationRequestAttributes.getResponseType()).isNotNull();
		assertThat(authorizationRequestAttributes.getClientId()).isNotNull();
		assertThat(authorizationRequestAttributes.getRedirectUri()).isNotNull();
		assertThat(authorizationRequestAttributes.getScopes()).isNotNull();
		assertThat(authorizationRequestAttributes.getState()).isNotNull();
	}

	@Test
	public void doFilterWhenCustomFilterProcessingBaseUriThenRequestStillMatchesClient() throws Exception {
		String filterProcessingBaseUri = "/oauth2-login";
		ClientRegistration clientRegistration = githubClientRegistration();

		verifyRequestMatchesClientWithCustomFilterProcessingBaseUri(filterProcessingBaseUri, clientRegistration);
	}

	@Test
	public void doFilterWhenCustomFilterProcessingBaseUriWithTrailingSlashThenRequestStillMatchesClient() throws Exception {
		String filterProcessingBaseUri = "/oauth2-login/";
		ClientRegistration clientRegistration = googleClientRegistration();

		verifyRequestMatchesClientWithCustomFilterProcessingBaseUri(filterProcessingBaseUri, clientRegistration);
	}

	@Test
	public void doFilterWhenCustomFilterProcessingBaseUriWithoutLeadingSlashThenRequestStillMatchesClient() throws Exception {
		String filterProcessingBaseUri = "oauth2-login";
		ClientRegistration clientRegistration = githubClientRegistration();

		verifyRequestMatchesClientWithCustomFilterProcessingBaseUri(filterProcessingBaseUri, clientRegistration);
	}

	@Test(expected = IllegalArgumentException.class)
	public void doFilterWhenAuthorizationRequestUriBuilderReturnsNullThenThrowIllegalArgumentException() throws Exception {
		ClientRegistration clientRegistration = githubClientRegistration();

		AuthorizationRequestUriBuilder authorizationUriBuilder = mock(AuthorizationRequestUriBuilder.class);
		when(authorizationUriBuilder.build(any(AuthorizationRequestAttributes.class))).thenReturn(null);

		AuthorizationRequestRedirectFilter filter = setupFilter(authorizationUriBuilder, clientRegistration);

		String requestUri = AuthorizationRequestRedirectFilter.DEFAULT_FILTER_PROCESSING_URI +
				"/" + clientRegistration.getClientAlias();
		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestUri);
		request.setServletPath(requestUri);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		filter.doFilter(request, response, filterChain);
	}

	private void verifyRequestMatchesClientWithCustomFilterProcessingBaseUri(
			String filterProcessingBaseUri, ClientRegistration clientRegistration) throws Exception {

		String authorizationUri = clientRegistration.getProviderDetails().getAuthorizationUri().toString();
		AuthorizationRequestRedirectFilter filter =
				setupFilter(filterProcessingBaseUri, authorizationUri, clientRegistration);

		String requestUri = filterProcessingBaseUri + "/" + clientRegistration.getClientAlias();
		if (!requestUri.startsWith("/")) {
			requestUri = "/" + requestUri;
		}
		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestUri);
		request.setServletPath(requestUri);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		filter.doFilter(request, response, filterChain);

		verifyZeroInteractions(filterChain);        // Request should not proceed up the chain if matched
	}

	private AuthorizationRequestRedirectFilter setupFilter(String authorizationUri,
															ClientRegistration... clientRegistrations) throws Exception {

		return setupFilter(AuthorizationRequestRedirectFilter.DEFAULT_FILTER_PROCESSING_URI,
				authorizationUri, clientRegistrations);
	}

	private AuthorizationRequestRedirectFilter setupFilter(String filterProcessingBaseUri, String authorizationUri,
															ClientRegistration... clientRegistrations) throws Exception {

		AuthorizationRequestUriBuilder authorizationUriBuilder = mock(AuthorizationRequestUriBuilder.class);
		URI authorizationURI = new URI(authorizationUri);
		when(authorizationUriBuilder.build(any(AuthorizationRequestAttributes.class))).thenReturn(authorizationURI);

		return setupFilter(filterProcessingBaseUri, authorizationUriBuilder, clientRegistrations);
	}

	private AuthorizationRequestRedirectFilter setupFilter(AuthorizationRequestUriBuilder authorizationUriBuilder,
															ClientRegistration... clientRegistrations) throws Exception {

		return setupFilter(AuthorizationRequestRedirectFilter.DEFAULT_FILTER_PROCESSING_URI,
				authorizationUriBuilder, clientRegistrations);
	}

	private AuthorizationRequestRedirectFilter setupFilter(String filterProcessingBaseUri,
															AuthorizationRequestUriBuilder authorizationUriBuilder,
															ClientRegistration... clientRegistrations) throws Exception {

		ClientRegistrationRepository clientRegistrationRepository = clientRegistrationRepository(clientRegistrations);

		AuthorizationRequestRedirectFilter filter = new AuthorizationRequestRedirectFilter(
				filterProcessingBaseUri, clientRegistrationRepository, authorizationUriBuilder);
		filter.afterPropertiesSet();

		return filter;
	}
}
