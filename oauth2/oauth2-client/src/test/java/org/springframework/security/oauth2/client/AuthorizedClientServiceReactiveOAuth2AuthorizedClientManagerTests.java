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
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

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
		given(this.authorizedClientService.saveAuthorizedClient(any(), any()))
				.willReturn(this.saveAuthorizedClientProbe.mono());
		this.removeAuthorizedClientProbe = PublisherProbe.empty();
		given(this.authorizedClientService.removeAuthorizedClient(any(), any()))
				.willReturn(this.removeAuthorizedClientProbe.mono());
		this.authorizedClientProvider = mock(ReactiveOAuth2AuthorizedClientProvider.class);
		this.contextAttributesMapper = mock(Function.class);
		given(this.contextAttributesMapper.apply(any())).willReturn(Mono.empty());
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
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new AuthorizedClientServiceReactiveOAuth2AuthorizedClientManager(null,
						this.authorizedClientService))
				.withMessage("clientRegistrationRepository cannot be null");
	}

	@Test
	public void constructorWhenOAuth2AuthorizedClientServiceIsNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new AuthorizedClientServiceReactiveOAuth2AuthorizedClientManager(
						this.clientRegistrationRepository, null))
				.withMessage("authorizedClientService cannot be null");
	}

	@Test
	public void setAuthorizedClientProviderWhenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.authorizedClientManager.setAuthorizedClientProvider(null))
				.withMessage("authorizedClientProvider cannot be null");
	}

	@Test
	public void setContextAttributesMapperWhenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.authorizedClientManager.setContextAttributesMapper(null))
				.withMessage("contextAttributesMapper cannot be null");
	}

	@Test
	public void setAuthorizationSuccessHandlerWhenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.authorizedClientManager.setAuthorizationSuccessHandler(null))
				.withMessage("authorizationSuccessHandler cannot be null");
	}

	@Test
	public void setAuthorizationFailureHandlerWhenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.authorizedClientManager.setAuthorizationFailureHandler(null))
				.withMessage("authorizationFailureHandler cannot be null");
	}

	@Test
	public void authorizeWhenRequestIsNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.authorizedClientManager.authorize(null))
				.withMessage("authorizeRequest cannot be null");
	}

	@Test
	public void authorizeWhenClientRegistrationNotFoundThenThrowIllegalArgumentException() {
		String clientRegistrationId = "invalid-registration-id";
		OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest.withClientRegistrationId(clientRegistrationId)
				.principal(this.principal).build();
		given(this.clientRegistrationRepository.findByRegistrationId(clientRegistrationId)).willReturn(Mono.empty());
		StepVerifier.create(this.authorizedClientManager.authorize(authorizeRequest))
				.verifyError(IllegalArgumentException.class);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void authorizeWhenNotAuthorizedAndUnsupportedProviderThenNotAuthorized() {
		given(this.clientRegistrationRepository.findByRegistrationId(eq(this.clientRegistration.getRegistrationId())))
				.willReturn(Mono.just(this.clientRegistration));
		given(this.authorizedClientService.loadAuthorizedClient(any(), any())).willReturn(Mono.empty());
		given(this.authorizedClientProvider.authorize(any())).willReturn(Mono.empty());
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
		given(this.clientRegistrationRepository.findByRegistrationId(eq(this.clientRegistration.getRegistrationId())))
				.willReturn(Mono.just(this.clientRegistration));
		given(this.authorizedClientService.loadAuthorizedClient(any(), any())).willReturn(Mono.empty());
		given(this.authorizedClientProvider.authorize(any(OAuth2AuthorizationContext.class)))
				.willReturn(Mono.just(this.authorizedClient));
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
		given(this.clientRegistrationRepository.findByRegistrationId(eq(this.clientRegistration.getRegistrationId())))
				.willReturn(Mono.just(this.clientRegistration));
		given(this.authorizedClientService.loadAuthorizedClient(any(), any())).willReturn(Mono.empty());
		given(this.authorizedClientProvider.authorize(any(OAuth2AuthorizationContext.class)))
				.willReturn(Mono.just(this.authorizedClient));
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
		given(this.clientRegistrationRepository.findByRegistrationId(eq(this.clientRegistration.getRegistrationId())))
				.willReturn(Mono.just(this.clientRegistration));
		given(this.authorizedClientService.loadAuthorizedClient(any(), any())).willReturn(Mono.empty());
		OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest
				.withClientRegistrationId(this.clientRegistration.getRegistrationId()).principal(this.principal)
				.build();
		ClientAuthorizationException exception = new ClientAuthorizationException(
				new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN, null, null),
				this.clientRegistration.getRegistrationId());
		given(this.authorizedClientProvider.authorize(any(OAuth2AuthorizationContext.class)))
				.willReturn(Mono.error(exception));
		assertThatExceptionOfType(ClientAuthorizationException.class)
				.isThrownBy(() -> this.authorizedClientManager.authorize(authorizeRequest).block())
				.isEqualTo(exception);
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
		given(this.clientRegistrationRepository.findByRegistrationId(eq(this.clientRegistration.getRegistrationId())))
				.willReturn(Mono.just(this.clientRegistration));
		given(this.authorizedClientService.loadAuthorizedClient(any(), any())).willReturn(Mono.empty());
		OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest
				.withClientRegistrationId(this.clientRegistration.getRegistrationId()).principal(this.principal)
				.build();
		ClientAuthorizationException exception = new ClientAuthorizationException(
				new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT, null, null),
				this.clientRegistration.getRegistrationId());
		given(this.authorizedClientProvider.authorize(any(OAuth2AuthorizationContext.class)))
				.willReturn(Mono.error(exception));
		assertThatExceptionOfType(ClientAuthorizationException.class)
				.isThrownBy(() -> this.authorizedClientManager.authorize(authorizeRequest).block())
				.isEqualTo(exception);
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
		given(this.clientRegistrationRepository.findByRegistrationId(eq(this.clientRegistration.getRegistrationId())))
				.willReturn(Mono.just(this.clientRegistration));
		given(this.authorizedClientService.loadAuthorizedClient(any(), any())).willReturn(Mono.empty());
		OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest
				.withClientRegistrationId(this.clientRegistration.getRegistrationId()).principal(this.principal)
				.build();
		ClientAuthorizationException exception = new ClientAuthorizationException(
				new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR, null, null),
				this.clientRegistration.getRegistrationId());
		given(this.authorizedClientProvider.authorize(any(OAuth2AuthorizationContext.class)))
				.willReturn(Mono.error(exception));
		assertThatExceptionOfType(ClientAuthorizationException.class)
				.isThrownBy(() -> this.authorizedClientManager.authorize(authorizeRequest).block())
				.isEqualTo(exception);
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
		given(this.clientRegistrationRepository.findByRegistrationId(eq(this.clientRegistration.getRegistrationId())))
				.willReturn(Mono.just(this.clientRegistration));
		given(this.authorizedClientService.loadAuthorizedClient(any(), any())).willReturn(Mono.empty());
		OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest
				.withClientRegistrationId(this.clientRegistration.getRegistrationId()).principal(this.principal)
				.build();
		OAuth2AuthorizationException exception = new OAuth2AuthorizationException(
				new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT, null, null));
		given(this.authorizedClientProvider.authorize(any(OAuth2AuthorizationContext.class)))
				.willReturn(Mono.error(exception));
		assertThatExceptionOfType(OAuth2AuthorizationException.class)
				.isThrownBy(() -> this.authorizedClientManager.authorize(authorizeRequest).block())
				.isEqualTo(exception);
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
		given(this.clientRegistrationRepository.findByRegistrationId(eq(this.clientRegistration.getRegistrationId())))
				.willReturn(Mono.just(this.clientRegistration));
		given(this.authorizedClientService.loadAuthorizedClient(any(), any())).willReturn(Mono.empty());
		OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest
				.withClientRegistrationId(this.clientRegistration.getRegistrationId()).principal(this.principal)
				.build();
		OAuth2AuthorizationException exception = new OAuth2AuthorizationException(
				new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT, null, null));
		given(this.authorizedClientProvider.authorize(any(OAuth2AuthorizationContext.class)))
				.willReturn(Mono.error(exception));
		PublisherProbe<Void> authorizationFailureHandlerProbe = PublisherProbe.empty();
		this.authorizedClientManager.setAuthorizationFailureHandler(
				(client, principal, attributes) -> authorizationFailureHandlerProbe.mono());
		assertThatExceptionOfType(OAuth2AuthorizationException.class)
				.isThrownBy(() -> this.authorizedClientManager.authorize(authorizeRequest).block())
				.isEqualTo(exception);
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
		given(this.clientRegistrationRepository.findByRegistrationId(eq(this.clientRegistration.getRegistrationId())))
				.willReturn(Mono.just(this.clientRegistration));
		given(this.authorizedClientService.loadAuthorizedClient(eq(this.clientRegistration.getRegistrationId()),
				eq(this.principal.getName()))).willReturn(Mono.just(this.authorizedClient));
		OAuth2AuthorizedClient reauthorizedClient = new OAuth2AuthorizedClient(this.clientRegistration,
				this.principal.getName(), TestOAuth2AccessTokens.noScopes(), TestOAuth2RefreshTokens.refreshToken());
		given(this.authorizedClientProvider.authorize(any(OAuth2AuthorizationContext.class)))
				.willReturn(Mono.just(reauthorizedClient));
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
		given(this.authorizedClientProvider.authorize(any(OAuth2AuthorizationContext.class))).willReturn(Mono.empty());
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
		given(this.authorizedClientProvider.authorize(any(OAuth2AuthorizationContext.class)))
				.willReturn(Mono.just(reauthorizedClient));
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
		given(this.authorizedClientProvider.authorize(any(OAuth2AuthorizationContext.class)))
				.willReturn(Mono.just(reauthorizedClient));
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
