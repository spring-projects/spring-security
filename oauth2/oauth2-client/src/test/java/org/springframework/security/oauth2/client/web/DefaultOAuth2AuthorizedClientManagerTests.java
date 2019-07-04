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

import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizationContext;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.core.TestOAuth2AccessTokens;
import org.springframework.security.oauth2.core.TestOAuth2RefreshTokens;

import java.util.function.BiFunction;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

/**
 * Tests for {@link DefaultOAuth2AuthorizedClientManager}.
 *
 * @author Joe Grandja
 */
public class DefaultOAuth2AuthorizedClientManagerTests {
	private ClientRegistrationRepository clientRegistrationRepository;
	private OAuth2AuthorizedClientRepository authorizedClientRepository;
	private OAuth2AuthorizedClientProvider authorizedClientProvider;
	private BiFunction contextAttributesMapper;
	private DefaultOAuth2AuthorizedClientManager authorizedClientManager;
	private ClientRegistration clientRegistration;
	private Authentication principal;
	private OAuth2AuthorizedClient authorizedClient;
	private MockHttpServletRequest request;
	private MockHttpServletResponse response;
	private ArgumentCaptor<OAuth2AuthorizationContext> authorizationContextCaptor;

	@SuppressWarnings("unchecked")
	@Before
	public void setup() {
		this.clientRegistrationRepository = mock(ClientRegistrationRepository.class);
		this.authorizedClientRepository = mock(OAuth2AuthorizedClientRepository.class);
		this.authorizedClientProvider = mock(OAuth2AuthorizedClientProvider.class);
		this.contextAttributesMapper = mock(BiFunction.class);
		this.authorizedClientManager = new DefaultOAuth2AuthorizedClientManager(
				this.clientRegistrationRepository, this.authorizedClientRepository);
		this.authorizedClientManager.setAuthorizedClientProvider(this.authorizedClientProvider);
		this.authorizedClientManager.setContextAttributesMapper(this.contextAttributesMapper);
		this.clientRegistration = TestClientRegistrations.clientRegistration().build();
		this.principal = new TestingAuthenticationToken("principal", "password");
		this.authorizedClient = new OAuth2AuthorizedClient(this.clientRegistration, this.principal.getName(),
				TestOAuth2AccessTokens.scopes("read", "write"), TestOAuth2RefreshTokens.refreshToken());
		this.request = new MockHttpServletRequest();
		this.response = new MockHttpServletResponse();
		this.authorizationContextCaptor = ArgumentCaptor.forClass(OAuth2AuthorizationContext.class);
	}

	@Test
	public void constructorWhenClientRegistrationRepositoryIsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new DefaultOAuth2AuthorizedClientManager(null, this.authorizedClientRepository))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("clientRegistrationRepository cannot be null");
	}

	@Test
	public void constructorWhenOAuth2AuthorizedClientRepositoryIsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new DefaultOAuth2AuthorizedClientManager(this.clientRegistrationRepository, null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("authorizedClientRepository cannot be null");
	}

	@Test
	public void setAuthorizedClientProviderWhenNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> this.authorizedClientManager.setAuthorizedClientProvider(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("authorizedClientProvider cannot be null");
	}

	@Test
	public void setContextAttributesMapperWhenNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> this.authorizedClientManager.setContextAttributesMapper(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("contextAttributesMapper cannot be null");
	}

	@Test
	public void authorizeWhenArgumentsInvalidThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> this.authorizedClientManager.authorize(null, this.principal, this.request, this.response))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("clientRegistrationId cannot be empty");
		assertThatThrownBy(() -> this.authorizedClientManager.authorize(this.clientRegistration.getRegistrationId(), null, this.request, this.response))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("principal cannot be null");
		assertThatThrownBy(() -> this.authorizedClientManager.authorize(this.clientRegistration.getRegistrationId(), this.principal, null, this.response))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("request cannot be null");
		assertThatThrownBy(() -> this.authorizedClientManager.authorize(this.clientRegistration.getRegistrationId(), this.principal, this.request, null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("response cannot be null");
	}

	@Test
	public void authorizeWhenClientRegistrationNotFoundThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> this.authorizedClientManager.authorize("invalid-registration-id", this.principal, this.request, this.response))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("Could not find ClientRegistration with id 'invalid-registration-id'");
	}

	@SuppressWarnings("unchecked")
	@Test
	public void authorizeWhenNotAuthorizedAndUnsupportedProviderThenNotAuthorized() {
		when(this.clientRegistrationRepository.findByRegistrationId(
				eq(this.clientRegistration.getRegistrationId()))).thenReturn(this.clientRegistration);

		OAuth2AuthorizedClient authorizedClient = this.authorizedClientManager.authorize(
				this.clientRegistration.getRegistrationId(), this.principal, this.request, this.response);

		verify(this.authorizedClientProvider).authorize(this.authorizationContextCaptor.capture());
		verify(this.contextAttributesMapper).apply(eq(this.clientRegistration), eq(this.request));

		OAuth2AuthorizationContext authorizationContext = this.authorizationContextCaptor.getValue();
		assertThat(authorizationContext.getClientRegistration()).isEqualTo(this.clientRegistration);
		assertThat(authorizationContext.getAuthorizedClient()).isNull();
		assertThat(authorizationContext.getPrincipal()).isEqualTo(this.principal);

		assertThat(authorizedClient).isNull();
		verify(this.authorizedClientRepository, never()).saveAuthorizedClient(
				any(OAuth2AuthorizedClient.class), eq(this.principal), eq(this.request), eq(this.response));
	}

	@SuppressWarnings("unchecked")
	@Test
	public void authorizeWhenNotAuthorizedAndSupportedProviderThenAuthorized() {
		when(this.clientRegistrationRepository.findByRegistrationId(
				eq(this.clientRegistration.getRegistrationId()))).thenReturn(this.clientRegistration);

		when(this.authorizedClientProvider.authorize(any(OAuth2AuthorizationContext.class))).thenReturn(this.authorizedClient);

		OAuth2AuthorizedClient authorizedClient = this.authorizedClientManager.authorize(
				this.clientRegistration.getRegistrationId(), this.principal, this.request, this.response);

		verify(this.authorizedClientProvider).authorize(this.authorizationContextCaptor.capture());
		verify(this.contextAttributesMapper).apply(eq(this.clientRegistration), eq(this.request));

		OAuth2AuthorizationContext authorizationContext = this.authorizationContextCaptor.getValue();
		assertThat(authorizationContext.getClientRegistration()).isEqualTo(this.clientRegistration);
		assertThat(authorizationContext.getAuthorizedClient()).isNull();
		assertThat(authorizationContext.getPrincipal()).isEqualTo(this.principal);

		assertThat(authorizedClient).isSameAs(this.authorizedClient);
		verify(this.authorizedClientRepository).saveAuthorizedClient(
				eq(this.authorizedClient), eq(this.principal), eq(this.request), eq(this.response));
	}

	@SuppressWarnings("unchecked")
	@Test
	public void authorizeWhenAuthorizedAndSupportedProviderThenReauthorized() {
		when(this.clientRegistrationRepository.findByRegistrationId(
				eq(this.clientRegistration.getRegistrationId()))).thenReturn(this.clientRegistration);
		when(this.authorizedClientRepository.loadAuthorizedClient(
				eq(this.clientRegistration.getRegistrationId()), eq(this.principal), eq(this.request))).thenReturn(this.authorizedClient);

		OAuth2AuthorizedClient reauthorizedClient = new OAuth2AuthorizedClient(
				this.clientRegistration, this.principal.getName(),
				TestOAuth2AccessTokens.noScopes(), TestOAuth2RefreshTokens.refreshToken());

		when(this.authorizedClientProvider.authorize(any(OAuth2AuthorizationContext.class))).thenReturn(reauthorizedClient);

		OAuth2AuthorizedClient authorizedClient = this.authorizedClientManager.authorize(
				this.clientRegistration.getRegistrationId(), this.principal, this.request, this.response);

		verify(this.authorizedClientProvider).authorize(this.authorizationContextCaptor.capture());
		verify(this.contextAttributesMapper).apply(eq(this.clientRegistration), eq(this.request));

		OAuth2AuthorizationContext authorizationContext = this.authorizationContextCaptor.getValue();
		assertThat(authorizationContext.getClientRegistration()).isEqualTo(this.clientRegistration);
		assertThat(authorizationContext.getAuthorizedClient()).isSameAs(this.authorizedClient);
		assertThat(authorizationContext.getPrincipal()).isEqualTo(this.principal);

		assertThat(authorizedClient).isSameAs(reauthorizedClient);
		verify(this.authorizedClientRepository).saveAuthorizedClient(
				eq(reauthorizedClient), eq(this.principal), eq(this.request), eq(this.response));
	}

	@Test
	public void reauthorizeWhenArgumentsInvalidThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> this.authorizedClientManager.reauthorize(null, this.principal, this.request, this.response))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("authorizedClient cannot be null");
		assertThatThrownBy(() -> this.authorizedClientManager.reauthorize(this.authorizedClient, null, this.request, this.response))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("principal cannot be null");
		assertThatThrownBy(() -> this.authorizedClientManager.reauthorize(this.authorizedClient, this.principal, null, this.response))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("request cannot be null");
		assertThatThrownBy(() -> this.authorizedClientManager.reauthorize(this.authorizedClient, this.principal, this.request, null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("response cannot be null");
	}

	@SuppressWarnings("unchecked")
	@Test
	public void reauthorizeWhenUnsupportedProviderThenNotReauthorized() {
		OAuth2AuthorizedClient authorizedClient = this.authorizedClientManager.reauthorize(
				this.authorizedClient, this.principal, this.request, this.response);

		verify(this.authorizedClientProvider).authorize(this.authorizationContextCaptor.capture());
		verify(this.contextAttributesMapper).apply(eq(this.clientRegistration), eq(this.request));

		OAuth2AuthorizationContext authorizationContext = this.authorizationContextCaptor.getValue();
		assertThat(authorizationContext.getClientRegistration()).isEqualTo(this.clientRegistration);
		assertThat(authorizationContext.getAuthorizedClient()).isSameAs(this.authorizedClient);
		assertThat(authorizationContext.getPrincipal()).isEqualTo(this.principal);

		assertThat(authorizedClient).isSameAs(this.authorizedClient);
		verify(this.authorizedClientRepository, never()).saveAuthorizedClient(
				any(OAuth2AuthorizedClient.class), eq(this.principal), eq(this.request), eq(this.response));
	}

	@SuppressWarnings("unchecked")
	@Test
	public void reauthorizeWhenSupportedProviderThenReauthorized() {
		OAuth2AuthorizedClient reauthorizedClient = new OAuth2AuthorizedClient(
				this.clientRegistration, this.principal.getName(),
				TestOAuth2AccessTokens.noScopes(), TestOAuth2RefreshTokens.refreshToken());

		when(this.authorizedClientProvider.authorize(any(OAuth2AuthorizationContext.class))).thenReturn(reauthorizedClient);

		OAuth2AuthorizedClient authorizedClient = this.authorizedClientManager.reauthorize(
				this.authorizedClient, this.principal, this.request, this.response);

		verify(this.authorizedClientProvider).authorize(this.authorizationContextCaptor.capture());
		verify(this.contextAttributesMapper).apply(eq(this.clientRegistration), eq(this.request));

		OAuth2AuthorizationContext authorizationContext = this.authorizationContextCaptor.getValue();
		assertThat(authorizationContext.getClientRegistration()).isEqualTo(this.clientRegistration);
		assertThat(authorizationContext.getAuthorizedClient()).isSameAs(this.authorizedClient);
		assertThat(authorizationContext.getPrincipal()).isEqualTo(this.principal);

		assertThat(authorizedClient).isSameAs(reauthorizedClient);
		verify(this.authorizedClientRepository).saveAuthorizedClient(
				eq(reauthorizedClient), eq(this.principal), eq(this.request), eq(this.response));
	}
}
