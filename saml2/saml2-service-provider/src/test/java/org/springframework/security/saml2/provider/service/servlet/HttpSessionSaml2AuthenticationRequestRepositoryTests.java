/*
 * Copyright 2002-2021 the original author or authors.
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

package org.springframework.security.saml2.provider.service.servlet;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.saml2.provider.service.authentication.AbstractSaml2AuthenticationRequest;
import org.springframework.security.saml2.provider.service.web.HttpSessionSaml2AuthenticationRequestRepository;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * @author Marcus Da Coregio
 */
public class HttpSessionSaml2AuthenticationRequestRepositoryTests {

	private static final String IDP_SSO_URL = "https://sso-url.example.com/IDP/SSO";

	private MockHttpServletRequest request;

	private MockHttpServletResponse response;

	private HttpSessionSaml2AuthenticationRequestRepository authenticationRequestRepository;

	@BeforeEach
	public void setup() {
		this.request = new MockHttpServletRequest();
		this.response = new MockHttpServletResponse();
		this.authenticationRequestRepository = new HttpSessionSaml2AuthenticationRequestRepository();
	}

	@Test
	public void loadAuthenticationRequestWhenInvalidSessionThenNull() {
		AbstractSaml2AuthenticationRequest authenticationRequest = this.authenticationRequestRepository
				.loadAuthenticationRequest(this.request);
		assertThat(authenticationRequest).isNull();
	}

	@Test
	public void loadAuthenticationRequestWhenNoAttributeInSessionThenNull() {
		this.request.getSession();
		AbstractSaml2AuthenticationRequest authenticationRequest = this.authenticationRequestRepository
				.loadAuthenticationRequest(this.request);
		assertThat(authenticationRequest).isNull();
	}

	@Test
	public void loadAuthenticationRequestWhenAttributeInSessionThenReturnsAuthenticationRequest() {
		AbstractSaml2AuthenticationRequest mockAuthenticationRequest = mock(AbstractSaml2AuthenticationRequest.class);
		given(mockAuthenticationRequest.getAuthenticationRequestUri()).willReturn(IDP_SSO_URL);
		this.request.getSession();
		this.authenticationRequestRepository.saveAuthenticationRequest(mockAuthenticationRequest, this.request,
				this.response);
		AbstractSaml2AuthenticationRequest authenticationRequest = this.authenticationRequestRepository
				.loadAuthenticationRequest(this.request);
		assertThat(authenticationRequest.getAuthenticationRequestUri()).isEqualTo(IDP_SSO_URL);
	}

	@Test
	public void saveAuthenticationRequestWhenSessionDontExistsThenCreateAndSave() {
		AbstractSaml2AuthenticationRequest mockAuthenticationRequest = mock(AbstractSaml2AuthenticationRequest.class);
		this.authenticationRequestRepository.saveAuthenticationRequest(mockAuthenticationRequest, this.request,
				this.response);
		AbstractSaml2AuthenticationRequest authenticationRequest = this.authenticationRequestRepository
				.loadAuthenticationRequest(this.request);
		assertThat(authenticationRequest).isNotNull();
	}

	@Test
	public void saveAuthenticationRequestWhenSessionExistsThenSave() {
		AbstractSaml2AuthenticationRequest mockAuthenticationRequest = mock(AbstractSaml2AuthenticationRequest.class);
		this.request.getSession();
		this.authenticationRequestRepository.saveAuthenticationRequest(mockAuthenticationRequest, this.request,
				this.response);
		AbstractSaml2AuthenticationRequest authenticationRequest = this.authenticationRequestRepository
				.loadAuthenticationRequest(this.request);
		assertThat(authenticationRequest).isNotNull();
	}

	@Test
	public void saveAuthenticationRequestWhenNullAuthenticationRequestThenDontSave() {
		this.request.getSession();
		this.authenticationRequestRepository.saveAuthenticationRequest(null, this.request, this.response);
		AbstractSaml2AuthenticationRequest authenticationRequest = this.authenticationRequestRepository
				.loadAuthenticationRequest(this.request);
		assertThat(authenticationRequest).isNull();
	}

	@Test
	public void removeAuthenticationRequestWhenInvalidSessionThenReturnNull() {
		AbstractSaml2AuthenticationRequest authenticationRequest = this.authenticationRequestRepository
				.removeAuthenticationRequest(this.request, this.response);
		assertThat(authenticationRequest).isNull();
	}

	@Test
	public void removeAuthenticationRequestWhenAttributeInSessionThenRemoveAuthenticationRequest() {
		AbstractSaml2AuthenticationRequest mockAuthenticationRequest = mock(AbstractSaml2AuthenticationRequest.class);
		given(mockAuthenticationRequest.getAuthenticationRequestUri()).willReturn(IDP_SSO_URL);
		this.request.getSession();
		this.authenticationRequestRepository.saveAuthenticationRequest(mockAuthenticationRequest, this.request,
				this.response);
		AbstractSaml2AuthenticationRequest authenticationRequest = this.authenticationRequestRepository
				.removeAuthenticationRequest(this.request, this.response);
		AbstractSaml2AuthenticationRequest authenticationRequestAfterRemove = this.authenticationRequestRepository
				.loadAuthenticationRequest(this.request);
		assertThat(authenticationRequest.getAuthenticationRequestUri()).isEqualTo(IDP_SSO_URL);
		assertThat(authenticationRequestAfterRemove).isNull();
	}

	@Test
	public void removeAuthenticationRequestWhenValidSessionNoAttributeThenReturnsNull() {
		MockHttpSession session = mock(MockHttpSession.class);
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setSession(session);
		AbstractSaml2AuthenticationRequest authenticationRequest = this.authenticationRequestRepository
				.removeAuthenticationRequest(request, this.response);
		verify(session).getAttribute(anyString());
		assertThat(authenticationRequest).isNull();
	}

}
