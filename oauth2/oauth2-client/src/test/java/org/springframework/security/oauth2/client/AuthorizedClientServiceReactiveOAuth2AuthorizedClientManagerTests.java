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
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import reactor.test.publisher.PublisherProbe;

import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.TestOAuth2AccessTokens;
import org.springframework.security.oauth2.core.TestOAuth2RefreshTokens;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link AuthorizedClientServiceReactiveOAuth2AuthorizedClientManager}.
 *
 * @author Ankur Pathak
 * @author Phil Clay
 */
public class AuthorizedClientServiceReactiveOAuth2AuthorizedClientManagerTests {

	private ReactiveClientRegistrationRepository clientRegistrationRepository;

	private ReactiveOAuth2AuthorizedClientService authorizedClientService;

	private ReactiveOAuth2AuthorizedClientProvider authorizedClientProvider;

	private Function<OAuth2AuthorizeRequest, Mono<Map<String, Object>>> contextAttributesMapper;

	private AuthorizedClientServiceReactiveOAuth2AuthorizedClientManager authorizedClientManager;

	private ClientRegistration clientRegistration;

	private Authentication principal;

	private OAuth2AuthorizedClient authorizedClient;

	private ArgumentCaptor<OAuth2AuthorizationContext> authorizationContextCaptor;

	private PublisherProbe<Void> saveAuthorizedClientProbe;

	private PublisherProbe<Void> removeAuthorizedClientProbe;

	@SuppressWarnings("unchecked")
	@Before
	public void setup() {
		this.clientRegistrationRepository = mock(ReactiveClientRegistrationRepository.class);
		this.authorizedClientService = mock(ReactiveOAuth2AuthorizedClientService.class);
		this.saveAuthorizedClientProbe = PublisherProbe.empty();
		when(this.authorizedClientService.saveAuthorizedClient(any(), any()))
				.thenReturn(this.saveAuthorizedClientProbe.mono());
		this.removeAuthorizedClientProbe = PublisherProbe.empty();
		when(this.authorizedClientService.removeAuthorizedClient(any(), any()))
				.thenReturn(this.removeAuthorizedClientProbe.mono());
		this.authorizedClientProvider = mock(ReactiveOAuth2AuthorizedClientProvider.class);
		this.contextAttributesMapper = mock(Function.class);
		when(this.contextAttributesMapper.apply(any())).thenReturn(Mono.empty());
		this.authorizedClientManager = new AuthorizedClientServiceReactiveOAuth2AuthorizedClientManager(
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
		assertThatThrownBy(() -> new AuthorizedClientServiceReactiveOAuth2AuthorizedClientManager(null,
				this.authorizedClientService)).isInstanceOf(IllegalArgumentException.class)
						.hasMessage("clientRegistrationRepository cannot be null");
	}

	@Test
	public void constructorWhenOAuth2AuthorizedClientServiceIsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new AuthorizedClientServiceReactiveOAuth2AuthorizedClientManager(
				this.clientRegistrationRepository, null)).isInstanceOf(IllegalArgumentException.class)
						.hasMessage("authorizedClientService cannot be null");
	}

	@Test
	public void setAuthorizedClientProviderWhenNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> this.authorizedClientManager.setAuthorizedClientProvider(null))
				.isInstanceOf(IllegalArgumentException.class).hasMessage("authorizedClientProvider cannot be null");
	}

	@Test
	public void setContextAttributesMapperWhenNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> this.authorizedClientManager.setContextAttributesMapper(null))
				.isInstanceOf(IllegalArgumentException.class).hasMessage("contextAttributesMapper cannot be null");
	}

	@Test
	public void setAuthorizationSuccessHandlerWhenNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> this.authorizedClientManager.setAuthorizationSuccessHandler(null))
				.isInstanceOf(IllegalArgumentException.class).hasMessage("authorizationSuccessHandler cannot be null");
	}

	@Test
	public void setAuthorizationFailureHandlerWhenNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> this.authorizedClientManager.setAuthorizationFailureHandler(null))
				.isInstanceOf(IllegalArgumentException.class).hasMessage("authorizationFailureHandler cannot be null");
	}

	@Test
	public void authorizeWhenRequestIsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> this.authorizedClientManager.authorize(null))
				.isInstanceOf(IllegalArgumentException.class).hasMessage("authorizeRequest cannot be null");
	}

	@Test
	public void authorizeWhenClientRegistrationNotFoundThenThrowIllegalArgumentException() {
		String clientRegistrationId = "invalid-registration-id";
		OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest.withClientRegistrationId(clientRegistrationId)
				.principal(this.principal).build();
		when(this.clientRegistrationRepository.findByRegistrationId(clientRegistrationId)).thenReturn(Mono.empty());
		StepVerifier.create(this.authorizedClientManager.authorize(authorizeRequest))
				.verifyError(IllegalArgumentException.class);

	}

	@SuppressWarnings("unchecked")
	@Test
	public void authorizeWhenNotAuthorizedAndUnsupportedProviderThenNotAuthorized() {
		when(this.clientRegistrationRepository.findByRegistrationId(eq(this.clientRegistration.getRegistrationId())))
				.thenReturn(Mono.just(this.clientRegistration));
		when(this.authorizedClientService.loadAuthorizedClient(any(), any())).thenReturn(Mono.empty());

		when(authorizedClientProvider.authorize(any())).thenReturn(Mono.empty());
		OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest
				.withClientRegistrationId(this.clientRegistration.getRegistrationId()).principal(this.principal)
				.build();
		Mono<OAuth2AuthorizedClient> authorizedClient = this.authorizedClientManager.authorize(authorizeRequest);

		StepVerifier.create(authorizedClient).verifyComplete();

		verify(this.authorizedClientProvider).authorize(this.authorizationContextCaptor.capture());
		verify(this.contextAttributesMapper).apply(eq(authorizeRequest));

		OAuth2AuthorizationContext authorizationContext = this.authorizationContextCaptor.getValue();
		assertThat(authorizationContext.getClientRegistration()).isEqualTo(this.clientRegistration);
		assertThat(authorizationContext.getAuthorizedClient()).isNull();
		assertThat(authorizationContext.getPrincipal()).isEqualTo(this.principal);

		verify(this.authorizedClientService, never()).saveAuthorizedClient(any(OAuth2AuthorizedClient.class),
				eq(this.principal));
	}

	@SuppressWarnings("unchecked")
	@Test
	public void authorizeWhenNotAuthorizedAndSupportedProviderThenAuthorized() {
		when(this.clientRegistrationRepository.findByRegistrationId(eq(this.clientRegistration.getRegistrationId())))
				.thenReturn(Mono.just(this.clientRegistration));

		when(this.authorizedClientService.loadAuthorizedClient(any(), any())).thenReturn(Mono.empty());

		when(this.authorizedClientProvider.authorize(any(OAuth2AuthorizationContext.class)))
				.thenReturn(Mono.just(this.authorizedClient));

		OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest
				.withClientRegistrationId(this.clientRegistration.getRegistrationId()).principal(this.principal)
				.build();
		Mono<OAuth2AuthorizedClient> authorizedClient = this.authorizedClientManager.authorize(authorizeRequest);

		StepVerifier.create(authorizedClient).expectNext(this.authorizedClient).verifyComplete();

		verify(this.authorizedClientProvider).authorize(this.authorizationContextCaptor.capture());
		verify(this.contextAttributesMapper).apply(eq(authorizeRequest));

		OAuth2AuthorizationContext authorizationContext = this.authorizationContextCaptor.getValue();
		assertThat(authorizationContext.getClientRegistration()).isEqualTo(this.clientRegistration);
		assertThat(authorizationContext.getAuthorizedClient()).isNull();
		assertThat(authorizationContext.getPrincipal()).isEqualTo(this.principal);

		verify(this.authorizedClientService).saveAuthorizedClient(eq(this.authorizedClient), eq(this.principal));
		this.saveAuthorizedClientProbe.assertWasSubscribed();
		verify(this.authorizedClientService, never()).removeAuthorizedClient(any(), any());
	}

	@SuppressWarnings("unchecked")
	@Test
	public void authorizeWhenNotAuthorizedAndSupportedProviderAndCustomSuccessHandlerThenInvokeCustomSuccessHandler() {
		when(this.clientRegistrationRepository.findByRegistrationId(eq(this.clientRegistration.getRegistrationId())))
				.thenReturn(Mono.just(this.clientRegistration));

		when(this.authorizedClientService.loadAuthorizedClient(any(), any())).thenReturn(Mono.empty());

		when(this.authorizedClientProvider.authorize(any(OAuth2AuthorizationContext.class)))
				.thenReturn(Mono.just(this.authorizedClient));

		OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest
				.withClientRegistrationId(this.clientRegistration.getRegistrationId()).principal(this.principal)
				.build();
		PublisherProbe<Void> authorizationSuccessHandlerProbe = PublisherProbe.empty();
		this.authorizedClientManager.setAuthorizationSuccessHandler(
				(client, principal, attributes) -> authorizationSuccessHandlerProbe.mono());

		Mono<OAuth2AuthorizedClient> authorizedClient = this.authorizedClientManager.authorize(authorizeRequest);

		StepVerifier.create(authorizedClient).expectNext(this.authorizedClient).verifyComplete();

		verify(this.authorizedClientProvider).authorize(this.authorizationContextCaptor.capture());
		verify(this.contextAttributesMapper).apply(eq(authorizeRequest));

		OAuth2AuthorizationContext authorizationContext = this.authorizationContextCaptor.getValue();
		assertThat(authorizationContext.getClientRegistration()).isEqualTo(this.clientRegistration);
		assertThat(authorizationContext.getAuthorizedClient()).isNull();
		assertThat(authorizationContext.getPrincipal()).isEqualTo(this.principal);

		authorizationSuccessHandlerProbe.assertWasSubscribed();
		verify(this.authorizedClientService, never()).saveAuthorizedClient(any(), any());
		verify(this.authorizedClientService, never()).removeAuthorizedClient(any(), any());
	}

	@Test
	public void authorizeWhenInvalidTokenThenRemoveAuthorizedClient() {
		when(this.clientRegistrationRepository.findByRegistrationId(eq(this.clientRegistration.getRegistrationId())))
				.thenReturn(Mono.just(this.clientRegistration));

		when(this.authorizedClientService.loadAuthorizedClient(any(), any())).thenReturn(Mono.empty());

		OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest
				.withClientRegistrationId(this.clientRegistration.getRegistrationId()).principal(this.principal)
				.build();

		ClientAuthorizationException exception = new ClientAuthorizationException(
				new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN, null, null),
				this.clientRegistration.getRegistrationId());

		when(this.authorizedClientProvider.authorize(any(OAuth2AuthorizationContext.class)))
				.thenReturn(Mono.error(exception));

		assertThatCode(() -> this.authorizedClientManager.authorize(authorizeRequest).block()).isEqualTo(exception);

		verify(this.authorizedClientProvider).authorize(this.authorizationContextCaptor.capture());
		verify(this.contextAttributesMapper).apply(eq(authorizeRequest));

		OAuth2AuthorizationContext authorizationContext = this.authorizationContextCaptor.getValue();
		assertThat(authorizationContext.getClientRegistration()).isEqualTo(this.clientRegistration);
		assertThat(authorizationContext.getAuthorizedClient()).isNull();
		assertThat(authorizationContext.getPrincipal()).isEqualTo(this.principal);

		verify(this.authorizedClientService).removeAuthorizedClient(eq(this.clientRegistration.getRegistrationId()),
				eq(this.principal.getName()));
		this.removeAuthorizedClientProbe.assertWasSubscribed();
		verify(this.authorizedClientService, never()).saveAuthorizedClient(any(), any());
	}

	@Test
	public void authorizeWhenInvalidGrantThenRemoveAuthorizedClient() {
		when(this.clientRegistrationRepository.findByRegistrationId(eq(this.clientRegistration.getRegistrationId())))
				.thenReturn(Mono.just(this.clientRegistration));

		when(this.authorizedClientService.loadAuthorizedClient(any(), any())).thenReturn(Mono.empty());

		OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest
				.withClientRegistrationId(this.clientRegistration.getRegistrationId()).principal(this.principal)
				.build();

		ClientAuthorizationException exception = new ClientAuthorizationException(
				new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT, null, null),
				this.clientRegistration.getRegistrationId());

		when(this.authorizedClientProvider.authorize(any(OAuth2AuthorizationContext.class)))
				.thenReturn(Mono.error(exception));

		assertThatCode(() -> this.authorizedClientManager.authorize(authorizeRequest).block()).isEqualTo(exception);

		verify(this.authorizedClientProvider).authorize(this.authorizationContextCaptor.capture());
		verify(this.contextAttributesMapper).apply(eq(authorizeRequest));

		OAuth2AuthorizationContext authorizationContext = this.authorizationContextCaptor.getValue();
		assertThat(authorizationContext.getClientRegistration()).isEqualTo(this.clientRegistration);
		assertThat(authorizationContext.getAuthorizedClient()).isNull();
		assertThat(authorizationContext.getPrincipal()).isEqualTo(this.principal);

		verify(this.authorizedClientService).removeAuthorizedClient(eq(this.clientRegistration.getRegistrationId()),
				eq(this.principal.getName()));
		this.removeAuthorizedClientProbe.assertWasSubscribed();
		verify(this.authorizedClientService, never()).saveAuthorizedClient(any(), any());
	}

	@Test
	public void authorizeWhenServerErrorThenDoNotRemoveAuthorizedClient() {
		when(this.clientRegistrationRepository.findByRegistrationId(eq(this.clientRegistration.getRegistrationId())))
				.thenReturn(Mono.just(this.clientRegistration));

		when(this.authorizedClientService.loadAuthorizedClient(any(), any())).thenReturn(Mono.empty());

		OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest
				.withClientRegistrationId(this.clientRegistration.getRegistrationId()).principal(this.principal)
				.build();

		ClientAuthorizationException exception = new ClientAuthorizationException(
				new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR, null, null),
				this.clientRegistration.getRegistrationId());

		when(this.authorizedClientProvider.authorize(any(OAuth2AuthorizationContext.class)))
				.thenReturn(Mono.error(exception));

		assertThatCode(() -> this.authorizedClientManager.authorize(authorizeRequest).block()).isEqualTo(exception);

		verify(this.authorizedClientProvider).authorize(this.authorizationContextCaptor.capture());
		verify(this.contextAttributesMapper).apply(eq(authorizeRequest));

		OAuth2AuthorizationContext authorizationContext = this.authorizationContextCaptor.getValue();
		assertThat(authorizationContext.getClientRegistration()).isEqualTo(this.clientRegistration);
		assertThat(authorizationContext.getAuthorizedClient()).isNull();
		assertThat(authorizationContext.getPrincipal()).isEqualTo(this.principal);

		verify(this.authorizedClientService, never()).removeAuthorizedClient(any(), any());
		verify(this.authorizedClientService, never()).saveAuthorizedClient(any(), any());
	}

	@Test
	public void authorizeWhenOAuth2AuthorizationExceptionThenDoNotRemoveAuthorizedClient() {
		when(this.clientRegistrationRepository.findByRegistrationId(eq(this.clientRegistration.getRegistrationId())))
				.thenReturn(Mono.just(this.clientRegistration));

		when(this.authorizedClientService.loadAuthorizedClient(any(), any())).thenReturn(Mono.empty());

		OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest
				.withClientRegistrationId(this.clientRegistration.getRegistrationId()).principal(this.principal)
				.build();

		OAuth2AuthorizationException exception = new OAuth2AuthorizationException(
				new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT, null, null));

		when(this.authorizedClientProvider.authorize(any(OAuth2AuthorizationContext.class)))
				.thenReturn(Mono.error(exception));

		assertThatCode(() -> this.authorizedClientManager.authorize(authorizeRequest).block()).isEqualTo(exception);

		verify(this.authorizedClientProvider).authorize(this.authorizationContextCaptor.capture());
		verify(this.contextAttributesMapper).apply(eq(authorizeRequest));

		OAuth2AuthorizationContext authorizationContext = this.authorizationContextCaptor.getValue();
		assertThat(authorizationContext.getClientRegistration()).isEqualTo(this.clientRegistration);
		assertThat(authorizationContext.getAuthorizedClient()).isNull();
		assertThat(authorizationContext.getPrincipal()).isEqualTo(this.principal);

		verify(this.authorizedClientService, never()).removeAuthorizedClient(any(), any());
		verify(this.authorizedClientService, never()).saveAuthorizedClient(any(), any());
	}

	@Test
	public void authorizeWhenOAuth2AuthorizationExceptionAndCustomFailureHandlerThenInvokeCustomFailureHandler() {
		when(this.clientRegistrationRepository.findByRegistrationId(eq(this.clientRegistration.getRegistrationId())))
				.thenReturn(Mono.just(this.clientRegistration));

		when(this.authorizedClientService.loadAuthorizedClient(any(), any())).thenReturn(Mono.empty());

		OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest
				.withClientRegistrationId(this.clientRegistration.getRegistrationId()).principal(this.principal)
				.build();

		OAuth2AuthorizationException exception = new OAuth2AuthorizationException(
				new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT, null, null));

		when(this.authorizedClientProvider.authorize(any(OAuth2AuthorizationContext.class)))
				.thenReturn(Mono.error(exception));

		PublisherProbe<Void> authorizationFailureHandlerProbe = PublisherProbe.empty();
		this.authorizedClientManager.setAuthorizationFailureHandler(
				(client, principal, attributes) -> authorizationFailureHandlerProbe.mono());

		assertThatCode(() -> this.authorizedClientManager.authorize(authorizeRequest).block()).isEqualTo(exception);

		verify(this.authorizedClientProvider).authorize(this.authorizationContextCaptor.capture());
		verify(this.contextAttributesMapper).apply(eq(authorizeRequest));

		OAuth2AuthorizationContext authorizationContext = this.authorizationContextCaptor.getValue();
		assertThat(authorizationContext.getClientRegistration()).isEqualTo(this.clientRegistration);
		assertThat(authorizationContext.getAuthorizedClient()).isNull();
		assertThat(authorizationContext.getPrincipal()).isEqualTo(this.principal);

		authorizationFailureHandlerProbe.assertWasSubscribed();
		verify(this.authorizedClientService, never()).removeAuthorizedClient(any(), any());
		verify(this.authorizedClientService, never()).saveAuthorizedClient(any(), any());
	}

	@SuppressWarnings("unchecked")
	@Test
	public void authorizeWhenAuthorizedAndSupportedProviderThenReauthorized() {
		when(this.clientRegistrationRepository.findByRegistrationId(eq(this.clientRegistration.getRegistrationId())))
				.thenReturn(Mono.just(this.clientRegistration));
		when(this.authorizedClientService.loadAuthorizedClient(eq(this.clientRegistration.getRegistrationId()),
				eq(this.principal.getName()))).thenReturn(Mono.just(this.authorizedClient));

		OAuth2AuthorizedClient reauthorizedClient = new OAuth2AuthorizedClient(this.clientRegistration,
				this.principal.getName(), TestOAuth2AccessTokens.noScopes(), TestOAuth2RefreshTokens.refreshToken());

		when(this.authorizedClientProvider.authorize(any(OAuth2AuthorizationContext.class)))
				.thenReturn(Mono.just(reauthorizedClient));

		OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest
				.withClientRegistrationId(this.clientRegistration.getRegistrationId()).principal(this.principal)
				.build();
		Mono<OAuth2AuthorizedClient> authorizedClient = this.authorizedClientManager.authorize(authorizeRequest);

		StepVerifier.create(authorizedClient).expectNext(reauthorizedClient).verifyComplete();
		verify(this.authorizedClientProvider).authorize(this.authorizationContextCaptor.capture());
		verify(this.contextAttributesMapper).apply(eq(authorizeRequest));

		OAuth2AuthorizationContext authorizationContext = this.authorizationContextCaptor.getValue();
		assertThat(authorizationContext.getClientRegistration()).isEqualTo(this.clientRegistration);
		assertThat(authorizationContext.getAuthorizedClient()).isSameAs(this.authorizedClient);
		assertThat(authorizationContext.getPrincipal()).isEqualTo(this.principal);

		verify(this.authorizedClientService).saveAuthorizedClient(eq(reauthorizedClient), eq(this.principal));
		this.saveAuthorizedClientProbe.assertWasSubscribed();
		verify(this.authorizedClientService, never()).removeAuthorizedClient(any(), any());
	}

	@SuppressWarnings("unchecked")
	@Test
	public void reauthorizeWhenUnsupportedProviderThenNotReauthorized() {
		when(this.authorizedClientProvider.authorize(any(OAuth2AuthorizationContext.class))).thenReturn(Mono.empty());
		OAuth2AuthorizeRequest reauthorizeRequest = OAuth2AuthorizeRequest.withAuthorizedClient(this.authorizedClient)
				.principal(this.principal).build();
		Mono<OAuth2AuthorizedClient> authorizedClient = this.authorizedClientManager.authorize(reauthorizeRequest);

		StepVerifier.create(authorizedClient).expectNext(this.authorizedClient).verifyComplete();
		verify(this.authorizedClientProvider).authorize(this.authorizationContextCaptor.capture());
		verify(this.contextAttributesMapper).apply(eq(reauthorizeRequest));

		OAuth2AuthorizationContext authorizationContext = this.authorizationContextCaptor.getValue();
		assertThat(authorizationContext.getClientRegistration()).isEqualTo(this.clientRegistration);
		assertThat(authorizationContext.getAuthorizedClient()).isSameAs(this.authorizedClient);
		assertThat(authorizationContext.getPrincipal()).isEqualTo(this.principal);

		verify(this.authorizedClientService, never()).saveAuthorizedClient(any(OAuth2AuthorizedClient.class),
				eq(this.principal));
	}

	@SuppressWarnings("unchecked")
	@Test
	public void reauthorizeWhenSupportedProviderThenReauthorized() {
		OAuth2AuthorizedClient reauthorizedClient = new OAuth2AuthorizedClient(this.clientRegistration,
				this.principal.getName(), TestOAuth2AccessTokens.noScopes(), TestOAuth2RefreshTokens.refreshToken());

		when(this.authorizedClientProvider.authorize(any(OAuth2AuthorizationContext.class)))
				.thenReturn(Mono.just(reauthorizedClient));

		OAuth2AuthorizeRequest reauthorizeRequest = OAuth2AuthorizeRequest.withAuthorizedClient(this.authorizedClient)
				.principal(this.principal).build();
		Mono<OAuth2AuthorizedClient> authorizedClient = this.authorizedClientManager.authorize(reauthorizeRequest);

		StepVerifier.create(authorizedClient).expectNext(reauthorizedClient).verifyComplete();

		verify(this.authorizedClientProvider).authorize(this.authorizationContextCaptor.capture());
		verify(this.contextAttributesMapper).apply(eq(reauthorizeRequest));

		OAuth2AuthorizationContext authorizationContext = this.authorizationContextCaptor.getValue();
		assertThat(authorizationContext.getClientRegistration()).isEqualTo(this.clientRegistration);
		assertThat(authorizationContext.getAuthorizedClient()).isSameAs(this.authorizedClient);
		assertThat(authorizationContext.getPrincipal()).isEqualTo(this.principal);

		verify(this.authorizedClientService).saveAuthorizedClient(eq(reauthorizedClient), eq(this.principal));
		this.saveAuthorizedClientProbe.assertWasSubscribed();
		verify(this.authorizedClientService, never()).removeAuthorizedClient(any(), any());
	}

	@SuppressWarnings("unchecked")
	@Test
	public void reauthorizeWhenRequestAttributeScopeThenMappedToContext() {
		OAuth2AuthorizedClient reauthorizedClient = new OAuth2AuthorizedClient(this.clientRegistration,
				this.principal.getName(), TestOAuth2AccessTokens.noScopes(), TestOAuth2RefreshTokens.refreshToken());

		when(this.authorizedClientProvider.authorize(any(OAuth2AuthorizationContext.class)))
				.thenReturn(Mono.just(reauthorizedClient));

		OAuth2AuthorizeRequest reauthorizeRequest = OAuth2AuthorizeRequest.withAuthorizedClient(this.authorizedClient)
				.principal(this.principal).attribute(OAuth2ParameterNames.SCOPE, "read write").build();

		this.authorizedClientManager.setContextAttributesMapper(
				new AuthorizedClientServiceReactiveOAuth2AuthorizedClientManager.DefaultContextAttributesMapper());
		Mono<OAuth2AuthorizedClient> authorizedClient = this.authorizedClientManager.authorize(reauthorizeRequest);

		StepVerifier.create(authorizedClient).expectNext(reauthorizedClient).verifyComplete();
		verify(this.authorizedClientService).saveAuthorizedClient(eq(reauthorizedClient), eq(this.principal));
		this.saveAuthorizedClientProbe.assertWasSubscribed();
		verify(this.authorizedClientService, never()).removeAuthorizedClient(any(), any());

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

	}

}
