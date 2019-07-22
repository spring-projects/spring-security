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
package org.springframework.security.oauth2.client;

import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.core.TestOAuth2AccessTokens;
import org.springframework.security.oauth2.core.TestOAuth2RefreshTokens;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;

import java.util.function.Function;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

/**
 * Tests for {@link OAuth2AuthorizedClientManagerService}.
 *
 * @author Joe Grandja
 */
public class OAuth2AuthorizedClientManagerServiceTests {
	private ClientRegistrationRepository clientRegistrationRepository;
	private OAuth2AuthorizedClientService authorizedClientService;
	private OAuth2AuthorizedClientProvider authorizedClientProvider;
	private Function contextAttributesMapper;
	private OAuth2AuthorizedClientManagerService authorizedClientManager;
	private ClientRegistration clientRegistration;
	private Authentication principal;
	private OAuth2AuthorizedClient authorizedClient;
	private ArgumentCaptor<OAuth2AuthorizationContext> authorizationContextCaptor;

	@SuppressWarnings("unchecked")
	@Before
	public void setup() {
		this.clientRegistrationRepository = mock(ClientRegistrationRepository.class);
		this.authorizedClientService = mock(OAuth2AuthorizedClientService.class);
		this.authorizedClientProvider = mock(OAuth2AuthorizedClientProvider.class);
		this.contextAttributesMapper = mock(Function.class);
		this.authorizedClientManager = new OAuth2AuthorizedClientManagerService(
				this.clientRegistrationRepository, this.authorizedClientService);
		this.authorizedClientManager.setAuthorizedClientProvider(this.authorizedClientProvider);
		this.authorizedClientManager.setContextAttributesMapper(this.contextAttributesMapper);
		this.clientRegistration = TestClientRegistrations.clientRegistration().build();
		this.principal = new TestingAuthenticationToken("principal", "password");
		this.authorizedClient = new OAuth2AuthorizedClient(this.clientRegistration, this.principal.getName(),
				TestOAuth2AccessTokens.scopes("read", "write"), TestOAuth2RefreshTokens.refreshToken());
		this.authorizationContextCaptor = ArgumentCaptor.forClass(OAuth2AuthorizationContext.class);
	}

	@Test
	public void constructorWhenClientRegistrationRepositoryIsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OAuth2AuthorizedClientManagerService(null, this.authorizedClientService))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("clientRegistrationRepository cannot be null");
	}

	@Test
	public void constructorWhenOAuth2AuthorizedClientServiceIsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OAuth2AuthorizedClientManagerService(this.clientRegistrationRepository, null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("authorizedClientService cannot be null");
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
	public void authorizeWhenRequestIsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> this.authorizedClientManager.authorize(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("authorizeRequest cannot be null");
	}

	@Test
	public void authorizeWhenClientRegistrationNotFoundThenThrowIllegalArgumentException() {
		OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest.withClientRegistrationId("invalid-registration-id")
				.principal(this.principal)
				.build();
		assertThatThrownBy(() -> this.authorizedClientManager.authorize(authorizeRequest))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("Could not find ClientRegistration with id 'invalid-registration-id'");
	}

	@SuppressWarnings("unchecked")
	@Test
	public void authorizeWhenNotAuthorizedAndUnsupportedProviderThenNotAuthorized() {
		when(this.clientRegistrationRepository.findByRegistrationId(
				eq(this.clientRegistration.getRegistrationId()))).thenReturn(this.clientRegistration);

		OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest.withClientRegistrationId(this.clientRegistration.getRegistrationId())
				.principal(this.principal)
				.build();
		OAuth2AuthorizedClient authorizedClient = this.authorizedClientManager.authorize(authorizeRequest);

		verify(this.authorizedClientProvider).authorize(this.authorizationContextCaptor.capture());
		verify(this.contextAttributesMapper).apply(eq(authorizeRequest));

		OAuth2AuthorizationContext authorizationContext = this.authorizationContextCaptor.getValue();
		assertThat(authorizationContext.getClientRegistration()).isEqualTo(this.clientRegistration);
		assertThat(authorizationContext.getAuthorizedClient()).isNull();
		assertThat(authorizationContext.getPrincipal()).isEqualTo(this.principal);

		assertThat(authorizedClient).isNull();
		verify(this.authorizedClientService, never()).saveAuthorizedClient(
				any(OAuth2AuthorizedClient.class), eq(this.principal));
	}

	@SuppressWarnings("unchecked")
	@Test
	public void authorizeWhenNotAuthorizedAndSupportedProviderThenAuthorized() {
		when(this.clientRegistrationRepository.findByRegistrationId(
				eq(this.clientRegistration.getRegistrationId()))).thenReturn(this.clientRegistration);

		when(this.authorizedClientProvider.authorize(any(OAuth2AuthorizationContext.class))).thenReturn(this.authorizedClient);

		OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest.withClientRegistrationId(this.clientRegistration.getRegistrationId())
				.principal(this.principal)
				.build();
		OAuth2AuthorizedClient authorizedClient = this.authorizedClientManager.authorize(authorizeRequest);

		verify(this.authorizedClientProvider).authorize(this.authorizationContextCaptor.capture());
		verify(this.contextAttributesMapper).apply(eq(authorizeRequest));

		OAuth2AuthorizationContext authorizationContext = this.authorizationContextCaptor.getValue();
		assertThat(authorizationContext.getClientRegistration()).isEqualTo(this.clientRegistration);
		assertThat(authorizationContext.getAuthorizedClient()).isNull();
		assertThat(authorizationContext.getPrincipal()).isEqualTo(this.principal);

		assertThat(authorizedClient).isSameAs(this.authorizedClient);
		verify(this.authorizedClientService).saveAuthorizedClient(
				eq(this.authorizedClient), eq(this.principal));
	}

	@SuppressWarnings("unchecked")
	@Test
	public void authorizeWhenAuthorizedAndSupportedProviderThenReauthorized() {
		when(this.clientRegistrationRepository.findByRegistrationId(
				eq(this.clientRegistration.getRegistrationId()))).thenReturn(this.clientRegistration);
		when(this.authorizedClientService.loadAuthorizedClient(
				eq(this.clientRegistration.getRegistrationId()), eq(this.principal.getName()))).thenReturn(this.authorizedClient);

		OAuth2AuthorizedClient reauthorizedClient = new OAuth2AuthorizedClient(
				this.clientRegistration, this.principal.getName(),
				TestOAuth2AccessTokens.noScopes(), TestOAuth2RefreshTokens.refreshToken());

		when(this.authorizedClientProvider.authorize(any(OAuth2AuthorizationContext.class))).thenReturn(reauthorizedClient);

		OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest.withClientRegistrationId(this.clientRegistration.getRegistrationId())
				.principal(this.principal)
				.build();
		OAuth2AuthorizedClient authorizedClient = this.authorizedClientManager.authorize(authorizeRequest);

		verify(this.authorizedClientProvider).authorize(this.authorizationContextCaptor.capture());
		verify(this.contextAttributesMapper).apply(eq(authorizeRequest));

		OAuth2AuthorizationContext authorizationContext = this.authorizationContextCaptor.getValue();
		assertThat(authorizationContext.getClientRegistration()).isEqualTo(this.clientRegistration);
		assertThat(authorizationContext.getAuthorizedClient()).isSameAs(this.authorizedClient);
		assertThat(authorizationContext.getPrincipal()).isEqualTo(this.principal);

		assertThat(authorizedClient).isSameAs(reauthorizedClient);
		verify(this.authorizedClientService).saveAuthorizedClient(
				eq(reauthorizedClient), eq(this.principal));
	}

	@SuppressWarnings("unchecked")
	@Test
	public void reauthorizeWhenUnsupportedProviderThenNotReauthorized() {
		OAuth2AuthorizeRequest reauthorizeRequest = OAuth2AuthorizeRequest.withAuthorizedClient(this.authorizedClient)
				.principal(this.principal)
				.build();
		OAuth2AuthorizedClient authorizedClient = this.authorizedClientManager.authorize(reauthorizeRequest);

		verify(this.authorizedClientProvider).authorize(this.authorizationContextCaptor.capture());
		verify(this.contextAttributesMapper).apply(eq(reauthorizeRequest));

		OAuth2AuthorizationContext authorizationContext = this.authorizationContextCaptor.getValue();
		assertThat(authorizationContext.getClientRegistration()).isEqualTo(this.clientRegistration);
		assertThat(authorizationContext.getAuthorizedClient()).isSameAs(this.authorizedClient);
		assertThat(authorizationContext.getPrincipal()).isEqualTo(this.principal);

		assertThat(authorizedClient).isSameAs(this.authorizedClient);
		verify(this.authorizedClientService, never()).saveAuthorizedClient(
				any(OAuth2AuthorizedClient.class), eq(this.principal));
	}

	@SuppressWarnings("unchecked")
	@Test
	public void reauthorizeWhenSupportedProviderThenReauthorized() {
		OAuth2AuthorizedClient reauthorizedClient = new OAuth2AuthorizedClient(
				this.clientRegistration, this.principal.getName(),
				TestOAuth2AccessTokens.noScopes(), TestOAuth2RefreshTokens.refreshToken());

		when(this.authorizedClientProvider.authorize(any(OAuth2AuthorizationContext.class))).thenReturn(reauthorizedClient);

		OAuth2AuthorizeRequest reauthorizeRequest = OAuth2AuthorizeRequest.withAuthorizedClient(this.authorizedClient)
				.principal(this.principal)
				.build();
		OAuth2AuthorizedClient authorizedClient = this.authorizedClientManager.authorize(reauthorizeRequest);

		verify(this.authorizedClientProvider).authorize(this.authorizationContextCaptor.capture());
		verify(this.contextAttributesMapper).apply(eq(reauthorizeRequest));

		OAuth2AuthorizationContext authorizationContext = this.authorizationContextCaptor.getValue();
		assertThat(authorizationContext.getClientRegistration()).isEqualTo(this.clientRegistration);
		assertThat(authorizationContext.getAuthorizedClient()).isSameAs(this.authorizedClient);
		assertThat(authorizationContext.getPrincipal()).isEqualTo(this.principal);

		assertThat(authorizedClient).isSameAs(reauthorizedClient);
		verify(this.authorizedClientService).saveAuthorizedClient(
				eq(reauthorizedClient), eq(this.principal));
	}

	@SuppressWarnings("unchecked")
	@Test
	public void reauthorizeWhenRequestAttributeScopeThenMappedToContext() {
		OAuth2AuthorizedClient reauthorizedClient = new OAuth2AuthorizedClient(
				this.clientRegistration, this.principal.getName(),
				TestOAuth2AccessTokens.noScopes(), TestOAuth2RefreshTokens.refreshToken());

		when(this.authorizedClientProvider.authorize(any(OAuth2AuthorizationContext.class))).thenReturn(reauthorizedClient);

		// Override the mock with the default
		this.authorizedClientManager.setContextAttributesMapper(
				new OAuth2AuthorizedClientManagerService.DefaultContextAttributesMapper());

		OAuth2AuthorizeRequest reauthorizeRequest = OAuth2AuthorizeRequest.withAuthorizedClient(this.authorizedClient)
				.principal(this.principal)
				.attribute(OAuth2ParameterNames.SCOPE, "read write")
				.build();
		OAuth2AuthorizedClient authorizedClient = this.authorizedClientManager.authorize(reauthorizeRequest);

		verify(this.authorizedClientProvider).authorize(this.authorizationContextCaptor.capture());

		OAuth2AuthorizationContext authorizationContext = this.authorizationContextCaptor.getValue();
		assertThat(authorizationContext.getClientRegistration()).isEqualTo(this.clientRegistration);
		assertThat(authorizationContext.getAuthorizedClient()).isSameAs(this.authorizedClient);
		assertThat(authorizationContext.getPrincipal()).isEqualTo(this.principal);
		assertThat(authorizationContext.getAttributes()).containsKey(OAuth2AuthorizationContext.REQUEST_SCOPE_ATTRIBUTE_NAME);
		String[] requestScopeAttribute = authorizationContext.getAttribute(OAuth2AuthorizationContext.REQUEST_SCOPE_ATTRIBUTE_NAME);
		assertThat(requestScopeAttribute).contains("read", "write");

		assertThat(authorizedClient).isSameAs(reauthorizedClient);
		verify(this.authorizedClientService).saveAuthorizedClient(
				eq(reauthorizedClient), eq(this.principal));
	}
}
