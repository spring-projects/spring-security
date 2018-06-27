/*
 * Copyright 2002-2018 the original author or authors.
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
package org.springframework.security.oauth2.client.web;

import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * Tests for {@link AuthenticatedPrincipalOAuth2AuthorizedClientRepository}.
 *
 * @author Joe Grandja
 */
public class AuthenticatedPrincipalOAuth2AuthorizedClientRepositoryTests {
	private String registrationId = "registrationId";
	private String principalName = "principalName";
	private OAuth2AuthorizedClientService authorizedClientService;
	private OAuth2AuthorizedClientRepository httpSessionAuthorizedClientRepository;
	private AuthenticatedPrincipalOAuth2AuthorizedClientRepository authorizedClientRepository;
	private MockHttpServletRequest request;
	private MockHttpServletResponse response;

	@Before
	public void setup() {
		this.authorizedClientService = mock(OAuth2AuthorizedClientService.class);
		this.httpSessionAuthorizedClientRepository = mock(OAuth2AuthorizedClientRepository.class);
		this.authorizedClientRepository = new AuthenticatedPrincipalOAuth2AuthorizedClientRepository(this.authorizedClientService);
		this.authorizedClientRepository.httpSessionAuthorizedClientRepository = this.httpSessionAuthorizedClientRepository;
		this.request = new MockHttpServletRequest();
		this.response = new MockHttpServletResponse();
	}

	@Test
	public void constructorWhenAuthorizedClientServiceIsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new AuthenticatedPrincipalOAuth2AuthorizedClientRepository(null))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void loadAuthorizedClientWhenAuthenticatedPrincipalThenLoadFromService() {
		this.setupAuthenticatedPrincipal();
		this.authorizedClientRepository.loadAuthorizedClient(this.registrationId, this.principalName, this.request);
		verify(this.authorizedClientService).loadAuthorizedClient(this.registrationId, this.principalName);
	}

	@Test
	public void loadAuthorizedClientWhenAnonymousPrincipalThenLoadFromSession() {
		this.setupAnonymousPrincipal();
		this.authorizedClientRepository.loadAuthorizedClient(this.registrationId, this.principalName, this.request);
		verify(this.httpSessionAuthorizedClientRepository).loadAuthorizedClient(this.registrationId, this.principalName, this.request);
	}

	@Test
	public void saveAuthorizedClientWhenAuthenticatedPrincipalThenSaveToService() {
		this.setupAuthenticatedPrincipal();
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		OAuth2AuthorizedClient authorizedClient = mock(OAuth2AuthorizedClient.class);
		this.authorizedClientRepository.saveAuthorizedClient(authorizedClient, authentication, this.request, this.response);
		verify(this.authorizedClientService).saveAuthorizedClient(authorizedClient, authentication);
	}

	@Test
	public void saveAuthorizedClientWhenAnonymousPrincipalThenSaveToSession() {
		this.setupAnonymousPrincipal();
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		OAuth2AuthorizedClient authorizedClient = mock(OAuth2AuthorizedClient.class);
		this.authorizedClientRepository.saveAuthorizedClient(authorizedClient, authentication, this.request, this.response);
		verify(this.httpSessionAuthorizedClientRepository).saveAuthorizedClient(authorizedClient, authentication, this.request, this.response);
	}

	@Test
	public void removeAuthorizedClientWhenAuthenticatedPrincipalThenRemoveFromService() {
		this.setupAuthenticatedPrincipal();
		this.authorizedClientRepository.removeAuthorizedClient(this.registrationId, this.principalName, this.request, this.response);
		verify(this.authorizedClientService).removeAuthorizedClient(this.registrationId, this.principalName);
	}

	@Test
	public void removeAuthorizedClientWhenAnonymousPrincipalThenRemoveFromSession() {
		this.setupAnonymousPrincipal();
		this.authorizedClientRepository.removeAuthorizedClient(this.registrationId, this.principalName, this.request, this.response);
		verify(this.httpSessionAuthorizedClientRepository).removeAuthorizedClient(this.registrationId, this.principalName, this.request, this.response);
	}

	private void setupAuthenticatedPrincipal() {
		TestingAuthenticationToken authentication = new TestingAuthenticationToken(this.principalName, "password");
		authentication.setAuthenticated(true);
		SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
		securityContext.setAuthentication(authentication);
		SecurityContextHolder.setContext(securityContext);
	}

	private void setupAnonymousPrincipal() {
		AnonymousAuthenticationToken anonymousPrincipal =
				new AnonymousAuthenticationToken("key-1234", "anonymousUser", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));
		SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
		securityContext.setAuthentication(anonymousPrincipal);
		SecurityContextHolder.setContext(securityContext);
	}
}
