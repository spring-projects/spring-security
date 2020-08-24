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

package org.springframework.security.oauth2.client;

import java.util.Map;
import java.util.function.Function;

import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;

import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.TestOAuth2AccessTokens;
import org.springframework.security.oauth2.core.TestOAuth2RefreshTokens;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * Tests for {@link AuthorizedClientServiceOAuth2AuthorizedClientManager}.
 *
 * @author Joe Grandja
 */
public class AuthorizedClientServiceOAuth2AuthorizedClientManagerTests {

	private ClientRegistrationRepository clientRegistrationRepository;

	private OAuth2AuthorizedClientService authorizedClientService;

	private OAuth2AuthorizedClientProvider authorizedClientProvider;

	private Function contextAttributesMapper;

	private OAuth2AuthorizationSuccessHandler authorizationSuccessHandler;

	private OAuth2AuthorizationFailureHandler authorizationFailureHandler;

	private AuthorizedClientServiceOAuth2AuthorizedClientManager authorizedClientManager;

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
		this.authorizationSuccessHandler = spy(new OAuth2AuthorizationSuccessHandler() {
			@Override
			public void onAuthorizationSuccess(OAuth2AuthorizedClient authorizedClient, Authentication principal,
					Map<String, Object> attributes) {
				AuthorizedClientServiceOAuth2AuthorizedClientManagerTests.this.authorizedClientService
						.saveAuthorizedClient(authorizedClient, principal);
			}
		});
		this.authorizationFailureHandler = spy(new RemoveAuthorizedClientOAuth2AuthorizationFailureHandler(
				(clientRegistrationId, principal, attributes) -> this.authorizedClientService
						.removeAuthorizedClient(clientRegistrationId, principal.getName())));
		this.authorizedClientManager = new AuthorizedClientServiceOAuth2AuthorizedClientManager(
				this.clientRegistrationRepository, this.authorizedClientService);
		this.authorizedClientManager.setAuthorizedClientProvider(this.authorizedClientProvider);
		this.authorizedClientManager.setContextAttributesMapper(this.contextAttributesMapper);
		this.authorizedClientManager.setAuthorizationSuccessHandler(this.authorizationSuccessHandler);
		this.authorizedClientManager.setAuthorizationFailureHandler(this.authorizationFailureHandler);
		this.clientRegistration = TestClientRegistrations.clientRegistration().build();
		this.principal = new TestingAuthenticationToken("principal", "password");
		this.authorizedClient = new OAuth2AuthorizedClient(this.clientRegistration, this.principal.getName(),
				TestOAuth2AccessTokens.scopes("read", "write"), TestOAuth2RefreshTokens.refreshToken());
		this.authorizationContextCaptor = ArgumentCaptor.forClass(OAuth2AuthorizationContext.class);
	}

	@Test
	public void constructorWhenClientRegistrationRepositoryIsNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new AuthorizedClientServiceOAuth2AuthorizedClientManager(null, this.authorizedClientService))
				.withMessage("clientRegistrationRepository cannot be null");
		// @formatter:on
	}

	@Test
	public void constructorWhenOAuth2AuthorizedClientServiceIsNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new AuthorizedClientServiceOAuth2AuthorizedClientManager(this.clientRegistrationRepository, null))
				.withMessage("authorizedClientService cannot be null");
		// @formatter:on
	}

	@Test
	public void setAuthorizedClientProviderWhenNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.authorizedClientManager.setAuthorizedClientProvider(null))
				.withMessage("authorizedClientProvider cannot be null");
		// @formatter:on
	}

	@Test
	public void setContextAttributesMapperWhenNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.authorizedClientManager.setContextAttributesMapper(null))
				.withMessage("contextAttributesMapper cannot be null");
		// @formatter:on
	}

	@Test
	public void setAuthorizationSuccessHandlerWhenNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.authorizedClientManager.setAuthorizationSuccessHandler(null))
				.withMessage("authorizationSuccessHandler cannot be null");
		// @formatter:on
	}

	@Test
	public void setAuthorizationFailureHandlerWhenNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.authorizedClientManager.setAuthorizationFailureHandler(null))
				.withMessage("authorizationFailureHandler cannot be null");
		// @formatter:on
	}

	@Test
	public void authorizeWhenRequestIsNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.authorizedClientManager.authorize(null))
				.withMessage("authorizeRequest cannot be null");
		// @formatter:on
	}

	@Test
	public void authorizeWhenClientRegistrationNotFoundThenThrowIllegalArgumentException() {
		// @formatter:off
		OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest
				.withClientRegistrationId("invalid-registration-id")

				.principal(this.principal).build();
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.authorizedClientManager.authorize(authorizeRequest))
				.withMessage("Could not find ClientRegistration with id 'invalid-registration-id'");
		// @formatter:on
	}

	@SuppressWarnings("unchecked")
	@Test
	public void authorizeWhenNotAuthorizedAndUnsupportedProviderThenNotAuthorized() {
		given(this.clientRegistrationRepository.findByRegistrationId(eq(this.clientRegistration.getRegistrationId())))
				.willReturn(this.clientRegistration);
		OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest
				.withClientRegistrationId(this.clientRegistration.getRegistrationId()).principal(this.principal)
				.build();
		OAuth2AuthorizedClient authorizedClient = this.authorizedClientManager.authorize(authorizeRequest);
		verify(this.authorizedClientProvider).authorize(this.authorizationContextCaptor.capture());
		verify(this.contextAttributesMapper).apply(eq(authorizeRequest));
		OAuth2AuthorizationContext authorizationContext = this.authorizationContextCaptor.getValue();
		assertThat(authorizationContext.getClientRegistration()).isEqualTo(this.clientRegistration);
		assertThat(authorizationContext.getAuthorizedClient()).isNull();
		assertThat(authorizationContext.getPrincipal()).isEqualTo(this.principal);
		assertThat(authorizedClient).isNull();
		verifyNoInteractions(this.authorizationSuccessHandler);
		verify(this.authorizedClientService, never()).saveAuthorizedClient(any(), any());
	}

	@SuppressWarnings("unchecked")
	@Test
	public void authorizeWhenNotAuthorizedAndSupportedProviderThenAuthorized() {
		given(this.clientRegistrationRepository.findByRegistrationId(eq(this.clientRegistration.getRegistrationId())))
				.willReturn(this.clientRegistration);
		given(this.authorizedClientProvider.authorize(any(OAuth2AuthorizationContext.class)))
				.willReturn(this.authorizedClient);
		// @formatter:off
		OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest
				.withClientRegistrationId(this.clientRegistration.getRegistrationId())
				.principal(this.principal)
				.build();
		// @formatter:on
		OAuth2AuthorizedClient authorizedClient = this.authorizedClientManager.authorize(authorizeRequest);
		verify(this.authorizedClientProvider).authorize(this.authorizationContextCaptor.capture());
		verify(this.contextAttributesMapper).apply(eq(authorizeRequest));
		OAuth2AuthorizationContext authorizationContext = this.authorizationContextCaptor.getValue();
		assertThat(authorizationContext.getClientRegistration()).isEqualTo(this.clientRegistration);
		assertThat(authorizationContext.getAuthorizedClient()).isNull();
		assertThat(authorizationContext.getPrincipal()).isEqualTo(this.principal);
		assertThat(authorizedClient).isSameAs(this.authorizedClient);
		verify(this.authorizationSuccessHandler).onAuthorizationSuccess(eq(this.authorizedClient), eq(this.principal),
				any());
		verify(this.authorizedClientService).saveAuthorizedClient(eq(this.authorizedClient), eq(this.principal));
	}

	@SuppressWarnings("unchecked")
	@Test
	public void authorizeWhenAuthorizedAndSupportedProviderThenReauthorized() {
		given(this.clientRegistrationRepository.findByRegistrationId(eq(this.clientRegistration.getRegistrationId())))
				.willReturn(this.clientRegistration);
		given(this.authorizedClientService.loadAuthorizedClient(eq(this.clientRegistration.getRegistrationId()),
				eq(this.principal.getName()))).willReturn(this.authorizedClient);
		OAuth2AuthorizedClient reauthorizedClient = new OAuth2AuthorizedClient(this.clientRegistration,
				this.principal.getName(), TestOAuth2AccessTokens.noScopes(), TestOAuth2RefreshTokens.refreshToken());
		given(this.authorizedClientProvider.authorize(any(OAuth2AuthorizationContext.class)))
				.willReturn(reauthorizedClient);
		// @formatter:off
		OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest
				.withClientRegistrationId(this.clientRegistration.getRegistrationId())
				.principal(this.principal)
				.build();
		// @formatter:on
		OAuth2AuthorizedClient authorizedClient = this.authorizedClientManager.authorize(authorizeRequest);
		verify(this.authorizedClientProvider).authorize(this.authorizationContextCaptor.capture());
		verify(this.contextAttributesMapper).apply(eq(authorizeRequest));
		OAuth2AuthorizationContext authorizationContext = this.authorizationContextCaptor.getValue();
		assertThat(authorizationContext.getClientRegistration()).isEqualTo(this.clientRegistration);
		assertThat(authorizationContext.getAuthorizedClient()).isSameAs(this.authorizedClient);
		assertThat(authorizationContext.getPrincipal()).isEqualTo(this.principal);
		assertThat(authorizedClient).isSameAs(reauthorizedClient);
		verify(this.authorizationSuccessHandler).onAuthorizationSuccess(eq(reauthorizedClient), eq(this.principal),
				any());
		verify(this.authorizedClientService).saveAuthorizedClient(eq(reauthorizedClient), eq(this.principal));
	}

	@SuppressWarnings("unchecked")
	@Test
	public void reauthorizeWhenUnsupportedProviderThenNotReauthorized() {
		OAuth2AuthorizeRequest reauthorizeRequest = OAuth2AuthorizeRequest.withAuthorizedClient(this.authorizedClient)
				.principal(this.principal).build();
		OAuth2AuthorizedClient authorizedClient = this.authorizedClientManager.authorize(reauthorizeRequest);
		verify(this.authorizedClientProvider).authorize(this.authorizationContextCaptor.capture());
		verify(this.contextAttributesMapper).apply(eq(reauthorizeRequest));
		OAuth2AuthorizationContext authorizationContext = this.authorizationContextCaptor.getValue();
		assertThat(authorizationContext.getClientRegistration()).isEqualTo(this.clientRegistration);
		assertThat(authorizationContext.getAuthorizedClient()).isSameAs(this.authorizedClient);
		assertThat(authorizationContext.getPrincipal()).isEqualTo(this.principal);
		assertThat(authorizedClient).isSameAs(this.authorizedClient);
		verifyNoInteractions(this.authorizationSuccessHandler);
		verify(this.authorizedClientService, never()).saveAuthorizedClient(any(), any());
	}

	@SuppressWarnings("unchecked")
	@Test
	public void reauthorizeWhenSupportedProviderThenReauthorized() {
		OAuth2AuthorizedClient reauthorizedClient = new OAuth2AuthorizedClient(this.clientRegistration,
				this.principal.getName(), TestOAuth2AccessTokens.noScopes(), TestOAuth2RefreshTokens.refreshToken());
		given(this.authorizedClientProvider.authorize(any(OAuth2AuthorizationContext.class)))
				.willReturn(reauthorizedClient);
		OAuth2AuthorizeRequest reauthorizeRequest = OAuth2AuthorizeRequest.withAuthorizedClient(this.authorizedClient)
				.principal(this.principal).build();
		OAuth2AuthorizedClient authorizedClient = this.authorizedClientManager.authorize(reauthorizeRequest);
		verify(this.authorizedClientProvider).authorize(this.authorizationContextCaptor.capture());
		verify(this.contextAttributesMapper).apply(eq(reauthorizeRequest));
		OAuth2AuthorizationContext authorizationContext = this.authorizationContextCaptor.getValue();
		assertThat(authorizationContext.getClientRegistration()).isEqualTo(this.clientRegistration);
		assertThat(authorizationContext.getAuthorizedClient()).isSameAs(this.authorizedClient);
		assertThat(authorizationContext.getPrincipal()).isEqualTo(this.principal);
		assertThat(authorizedClient).isSameAs(reauthorizedClient);
		verify(this.authorizationSuccessHandler).onAuthorizationSuccess(eq(reauthorizedClient), eq(this.principal),
				any());
		verify(this.authorizedClientService).saveAuthorizedClient(eq(reauthorizedClient), eq(this.principal));
	}

	@SuppressWarnings("unchecked")
	@Test
	public void reauthorizeWhenRequestAttributeScopeThenMappedToContext() {
		OAuth2AuthorizedClient reauthorizedClient = new OAuth2AuthorizedClient(this.clientRegistration,
				this.principal.getName(), TestOAuth2AccessTokens.noScopes(), TestOAuth2RefreshTokens.refreshToken());
		given(this.authorizedClientProvider.authorize(any(OAuth2AuthorizationContext.class)))
				.willReturn(reauthorizedClient);
		// Override the mock with the default
		this.authorizedClientManager.setContextAttributesMapper(
				new AuthorizedClientServiceOAuth2AuthorizedClientManager.DefaultContextAttributesMapper());
		OAuth2AuthorizeRequest reauthorizeRequest = OAuth2AuthorizeRequest.withAuthorizedClient(this.authorizedClient)
				.principal(this.principal).attribute(OAuth2ParameterNames.SCOPE, "read write").build();
		OAuth2AuthorizedClient authorizedClient = this.authorizedClientManager.authorize(reauthorizeRequest);
		verify(this.authorizedClientProvider).authorize(this.authorizationContextCaptor.capture());
		OAuth2AuthorizationContext authorizationContext = this.authorizationContextCaptor.getValue();
		assertThat(authorizationContext.getClientRegistration()).isEqualTo(this.clientRegistration);
		assertThat(authorizationContext.getAuthorizedClient()).isSameAs(this.authorizedClient);
		assertThat(authorizationContext.getPrincipal()).isEqualTo(this.principal);
		assertThat(authorizationContext.getAttributes())
				.containsKey(OAuth2AuthorizationContext.REQUEST_SCOPE_ATTRIBUTE_NAME);
		String[] requestScopeAttribute = authorizationContext
				.getAttribute(OAuth2AuthorizationContext.REQUEST_SCOPE_ATTRIBUTE_NAME);
		assertThat(requestScopeAttribute).contains("read", "write");
		assertThat(authorizedClient).isSameAs(reauthorizedClient);
		verify(this.authorizationSuccessHandler).onAuthorizationSuccess(eq(reauthorizedClient), eq(this.principal),
				any());
		verify(this.authorizedClientService).saveAuthorizedClient(eq(reauthorizedClient), eq(this.principal));
	}

	@Test
	public void reauthorizeWhenErrorCodeMatchThenRemoveAuthorizedClient() {
		ClientAuthorizationException authorizationException = new ClientAuthorizationException(
				new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT, null, null),
				this.clientRegistration.getRegistrationId());
		given(this.authorizedClientProvider.authorize(any(OAuth2AuthorizationContext.class)))
				.willThrow(authorizationException);
		OAuth2AuthorizeRequest reauthorizeRequest = OAuth2AuthorizeRequest.withAuthorizedClient(this.authorizedClient)
				.principal(this.principal).build();
		assertThatExceptionOfType(ClientAuthorizationException.class)
				.isThrownBy(() -> this.authorizedClientManager.authorize(reauthorizeRequest))
				.isEqualTo(authorizationException);
		verify(this.authorizationFailureHandler).onAuthorizationFailure(eq(authorizationException), eq(this.principal),
				any());
		verify(this.authorizedClientService).removeAuthorizedClient(eq(this.clientRegistration.getRegistrationId()),
				eq(this.principal.getName()));
	}

	@Test
	public void reauthorizeWhenErrorCodeDoesNotMatchThenDoNotRemoveAuthorizedClient() {
		ClientAuthorizationException authorizationException = new ClientAuthorizationException(
				new OAuth2Error("non-matching-error-code", null, null), this.clientRegistration.getRegistrationId());
		given(this.authorizedClientProvider.authorize(any(OAuth2AuthorizationContext.class)))
				.willThrow(authorizationException);
		// @formatter:off
		OAuth2AuthorizeRequest reauthorizeRequest = OAuth2AuthorizeRequest
				.withAuthorizedClient(this.authorizedClient)
				.principal(this.principal)
				.build();
		assertThatExceptionOfType(ClientAuthorizationException.class)
				.isThrownBy(() -> this.authorizedClientManager.authorize(reauthorizeRequest))
				.isEqualTo(authorizationException);
		// @formatter:on
		verify(this.authorizationFailureHandler).onAuthorizationFailure(eq(authorizationException), eq(this.principal),
				any());
		verifyNoInteractions(this.authorizedClientService);
	}

}
