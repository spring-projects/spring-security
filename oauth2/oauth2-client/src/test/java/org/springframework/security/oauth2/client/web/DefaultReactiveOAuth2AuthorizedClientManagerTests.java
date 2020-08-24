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

package org.springframework.security.oauth2.client.web;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import reactor.core.publisher.Mono;
import reactor.test.publisher.PublisherProbe;
import reactor.util.context.Context;

import org.springframework.http.MediaType;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.ClientAuthorizationException;
import org.springframework.security.oauth2.client.OAuth2AuthorizationContext;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.TestOAuth2AccessTokens;
import org.springframework.security.oauth2.core.TestOAuth2RefreshTokens;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.web.server.ServerWebExchange;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

/**
 * Tests for {@link DefaultReactiveOAuth2AuthorizedClientManager}.
 *
 * @author Joe Grandja
 */
public class DefaultReactiveOAuth2AuthorizedClientManagerTests {

	private ReactiveClientRegistrationRepository clientRegistrationRepository;

	private ServerOAuth2AuthorizedClientRepository authorizedClientRepository;

	private ReactiveOAuth2AuthorizedClientProvider authorizedClientProvider;

	private Function contextAttributesMapper;

	private DefaultReactiveOAuth2AuthorizedClientManager authorizedClientManager;

	private ClientRegistration clientRegistration;

	private Authentication principal;

	private OAuth2AuthorizedClient authorizedClient;

	private MockServerWebExchange serverWebExchange;

	private Context context;

	private ArgumentCaptor<OAuth2AuthorizationContext> authorizationContextCaptor;

	private PublisherProbe<OAuth2AuthorizedClient> loadAuthorizedClientProbe;

	private PublisherProbe<Void> saveAuthorizedClientProbe;

	private PublisherProbe<Void> removeAuthorizedClientProbe;

	@SuppressWarnings("unchecked")
	@Before
	public void setup() {
		this.clientRegistrationRepository = mock(ReactiveClientRegistrationRepository.class);
		given(this.clientRegistrationRepository.findByRegistrationId(anyString())).willReturn(Mono.empty());
		this.authorizedClientRepository = mock(ServerOAuth2AuthorizedClientRepository.class);
		this.loadAuthorizedClientProbe = PublisherProbe.empty();
		given(this.authorizedClientRepository.loadAuthorizedClient(anyString(), any(Authentication.class),
				any(ServerWebExchange.class))).willReturn(this.loadAuthorizedClientProbe.mono());
		this.saveAuthorizedClientProbe = PublisherProbe.empty();
		given(this.authorizedClientRepository.saveAuthorizedClient(any(OAuth2AuthorizedClient.class),
				any(Authentication.class), any(ServerWebExchange.class)))
						.willReturn(this.saveAuthorizedClientProbe.mono());
		this.removeAuthorizedClientProbe = PublisherProbe.empty();
		given(this.authorizedClientRepository.removeAuthorizedClient(any(String.class), any(Authentication.class),
				any(ServerWebExchange.class))).willReturn(this.removeAuthorizedClientProbe.mono());
		this.authorizedClientProvider = mock(ReactiveOAuth2AuthorizedClientProvider.class);
		given(this.authorizedClientProvider.authorize(any(OAuth2AuthorizationContext.class))).willReturn(Mono.empty());
		this.contextAttributesMapper = mock(Function.class);
		given(this.contextAttributesMapper.apply(any())).willReturn(Mono.just(Collections.emptyMap()));
		this.authorizedClientManager = new DefaultReactiveOAuth2AuthorizedClientManager(
				this.clientRegistrationRepository, this.authorizedClientRepository);
		this.authorizedClientManager.setAuthorizedClientProvider(this.authorizedClientProvider);
		this.authorizedClientManager.setContextAttributesMapper(this.contextAttributesMapper);
		this.clientRegistration = TestClientRegistrations.clientRegistration().build();
		this.principal = new TestingAuthenticationToken("principal", "password");
		this.authorizedClient = new OAuth2AuthorizedClient(this.clientRegistration, this.principal.getName(),
				TestOAuth2AccessTokens.scopes("read", "write"), TestOAuth2RefreshTokens.refreshToken());
		this.serverWebExchange = MockServerWebExchange.builder(MockServerHttpRequest.get("/")).build();
		this.context = Context.of(ServerWebExchange.class, this.serverWebExchange);
		this.authorizationContextCaptor = ArgumentCaptor.forClass(OAuth2AuthorizationContext.class);
	}

	@Test
	public void constructorWhenClientRegistrationRepositoryIsNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(
						() -> new DefaultReactiveOAuth2AuthorizedClientManager(null, this.authorizedClientRepository))
				.withMessage("clientRegistrationRepository cannot be null");
	}

	@Test
	public void constructorWhenOAuth2AuthorizedClientRepositoryIsNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(
						() -> new DefaultReactiveOAuth2AuthorizedClientManager(this.clientRegistrationRepository, null))
				.withMessage("authorizedClientRepository cannot be null");
	}

	@Test
	public void setAuthorizedClientProviderWhenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.authorizedClientManager.setAuthorizedClientProvider(null))
				.withMessage("authorizedClientProvider cannot be null");
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
	public void setContextAttributesMapperWhenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.authorizedClientManager.setContextAttributesMapper(null))
				.withMessage("contextAttributesMapper cannot be null");
	}

	@Test
	public void authorizeWhenRequestIsNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.authorizedClientManager.authorize(null).block())
				.withMessage("authorizeRequest cannot be null");
	}

	@Test
	public void authorizeWhenExchangeIsNullThenThrowIllegalArgumentException() {
		OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest
				.withClientRegistrationId(this.clientRegistration.getRegistrationId()).principal(this.principal)
				.build();
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.authorizedClientManager.authorize(authorizeRequest).block())
				.withMessage("serverWebExchange cannot be null");
	}

	@Test
	public void authorizeWhenClientRegistrationNotFoundThenThrowIllegalArgumentException() {
		OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest
				.withClientRegistrationId("invalid-registration-id").principal(this.principal).build();
		assertThatIllegalArgumentException().isThrownBy(
				() -> this.authorizedClientManager.authorize(authorizeRequest).subscriberContext(this.context).block())
				.withMessage("Could not find ClientRegistration with id 'invalid-registration-id'");
	}

	@SuppressWarnings("unchecked")
	@Test
	public void authorizeWhenNotAuthorizedAndUnsupportedProviderThenNotAuthorized() {
		given(this.clientRegistrationRepository.findByRegistrationId(eq(this.clientRegistration.getRegistrationId())))
				.willReturn(Mono.just(this.clientRegistration));
		OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest
				.withClientRegistrationId(this.clientRegistration.getRegistrationId()).principal(this.principal)
				.build();
		OAuth2AuthorizedClient authorizedClient = this.authorizedClientManager.authorize(authorizeRequest)
				.subscriberContext(this.context).block();
		verify(this.authorizedClientProvider).authorize(this.authorizationContextCaptor.capture());
		verify(this.contextAttributesMapper).apply(eq(authorizeRequest));
		OAuth2AuthorizationContext authorizationContext = this.authorizationContextCaptor.getValue();
		assertThat(authorizationContext.getClientRegistration()).isEqualTo(this.clientRegistration);
		assertThat(authorizationContext.getAuthorizedClient()).isNull();
		assertThat(authorizationContext.getPrincipal()).isEqualTo(this.principal);
		assertThat(authorizedClient).isNull();
		this.loadAuthorizedClientProbe.assertWasSubscribed();
		this.saveAuthorizedClientProbe.assertWasNotSubscribed();
	}

	@SuppressWarnings("unchecked")
	@Test
	public void authorizeWhenNotAuthorizedAndSupportedProviderThenAuthorized() {
		given(this.clientRegistrationRepository.findByRegistrationId(eq(this.clientRegistration.getRegistrationId())))
				.willReturn(Mono.just(this.clientRegistration));
		given(this.authorizedClientProvider.authorize(any(OAuth2AuthorizationContext.class)))
				.willReturn(Mono.just(this.authorizedClient));
		OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest
				.withClientRegistrationId(this.clientRegistration.getRegistrationId()).principal(this.principal)
				.build();
		OAuth2AuthorizedClient authorizedClient = this.authorizedClientManager.authorize(authorizeRequest)
				.subscriberContext(this.context).block();
		verify(this.authorizedClientProvider).authorize(this.authorizationContextCaptor.capture());
		verify(this.contextAttributesMapper).apply(eq(authorizeRequest));
		OAuth2AuthorizationContext authorizationContext = this.authorizationContextCaptor.getValue();
		assertThat(authorizationContext.getClientRegistration()).isEqualTo(this.clientRegistration);
		assertThat(authorizationContext.getAuthorizedClient()).isNull();
		assertThat(authorizationContext.getPrincipal()).isEqualTo(this.principal);
		assertThat(authorizedClient).isSameAs(this.authorizedClient);
		verify(this.authorizedClientRepository).saveAuthorizedClient(eq(this.authorizedClient), eq(this.principal),
				eq(this.serverWebExchange));
		this.saveAuthorizedClientProbe.assertWasSubscribed();
		verify(this.authorizedClientRepository, never()).removeAuthorizedClient(any(), any(), any());
	}

	@SuppressWarnings("unchecked")
	@Test
	public void authorizeWhenNotAuthorizedAndSupportedProviderAndCustomSuccessHandlerThenInvokeCustomSuccessHandler() {
		given(this.clientRegistrationRepository.findByRegistrationId(eq(this.clientRegistration.getRegistrationId())))
				.willReturn(Mono.just(this.clientRegistration));
		given(this.authorizedClientProvider.authorize(any(OAuth2AuthorizationContext.class)))
				.willReturn(Mono.just(this.authorizedClient));
		OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest
				.withClientRegistrationId(this.clientRegistration.getRegistrationId()).principal(this.principal)
				.build();
		PublisherProbe<Void> authorizationSuccessHandlerProbe = PublisherProbe.empty();
		this.authorizedClientManager.setAuthorizationSuccessHandler(
				(client, principal, attributes) -> authorizationSuccessHandlerProbe.mono());
		OAuth2AuthorizedClient authorizedClient = this.authorizedClientManager.authorize(authorizeRequest)
				.subscriberContext(this.context).block();
		verify(this.authorizedClientProvider).authorize(this.authorizationContextCaptor.capture());
		verify(this.contextAttributesMapper).apply(eq(authorizeRequest));
		OAuth2AuthorizationContext authorizationContext = this.authorizationContextCaptor.getValue();
		assertThat(authorizationContext.getClientRegistration()).isEqualTo(this.clientRegistration);
		assertThat(authorizationContext.getAuthorizedClient()).isNull();
		assertThat(authorizationContext.getPrincipal()).isEqualTo(this.principal);
		assertThat(authorizedClient).isSameAs(this.authorizedClient);
		authorizationSuccessHandlerProbe.assertWasSubscribed();
		verify(this.authorizedClientRepository, never()).saveAuthorizedClient(any(), any(), any());
		verify(this.authorizedClientRepository, never()).removeAuthorizedClient(any(), any(), any());
	}

	@SuppressWarnings("unchecked")
	@Test
	public void authorizeWhenInvalidTokenThenRemoveAuthorizedClient() {
		given(this.clientRegistrationRepository.findByRegistrationId(eq(this.clientRegistration.getRegistrationId())))
				.willReturn(Mono.just(this.clientRegistration));
		OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest
				.withClientRegistrationId(this.clientRegistration.getRegistrationId()).principal(this.principal)
				.build();
		ClientAuthorizationException exception = new ClientAuthorizationException(
				new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN, null, null),
				this.clientRegistration.getRegistrationId());
		given(this.authorizedClientProvider.authorize(any(OAuth2AuthorizationContext.class)))
				.willReturn(Mono.error(exception));
		assertThatExceptionOfType(ClientAuthorizationException.class).isThrownBy(
				() -> this.authorizedClientManager.authorize(authorizeRequest).subscriberContext(this.context).block())
				.isEqualTo(exception);
		verify(this.authorizedClientProvider).authorize(this.authorizationContextCaptor.capture());
		verify(this.contextAttributesMapper).apply(eq(authorizeRequest));
		OAuth2AuthorizationContext authorizationContext = this.authorizationContextCaptor.getValue();
		assertThat(authorizationContext.getClientRegistration()).isEqualTo(this.clientRegistration);
		assertThat(authorizationContext.getAuthorizedClient()).isNull();
		assertThat(authorizationContext.getPrincipal()).isEqualTo(this.principal);
		verify(this.authorizedClientRepository).removeAuthorizedClient(eq(this.clientRegistration.getRegistrationId()),
				eq(this.principal), eq(this.serverWebExchange));
		this.removeAuthorizedClientProbe.assertWasSubscribed();
		verify(this.authorizedClientRepository, never()).saveAuthorizedClient(any(), any(), any());
	}

	@SuppressWarnings("unchecked")
	@Test
	public void authorizeWhenInvalidGrantThenRemoveAuthorizedClient() {
		given(this.clientRegistrationRepository.findByRegistrationId(eq(this.clientRegistration.getRegistrationId())))
				.willReturn(Mono.just(this.clientRegistration));
		OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest
				.withClientRegistrationId(this.clientRegistration.getRegistrationId()).principal(this.principal)
				.build();
		ClientAuthorizationException exception = new ClientAuthorizationException(
				new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT, null, null),
				this.clientRegistration.getRegistrationId());
		given(this.authorizedClientProvider.authorize(any(OAuth2AuthorizationContext.class)))
				.willReturn(Mono.error(exception));
		assertThatExceptionOfType(ClientAuthorizationException.class).isThrownBy(
				() -> this.authorizedClientManager.authorize(authorizeRequest).subscriberContext(this.context).block())
				.isEqualTo(exception);
		verify(this.authorizedClientProvider).authorize(this.authorizationContextCaptor.capture());
		verify(this.contextAttributesMapper).apply(eq(authorizeRequest));
		OAuth2AuthorizationContext authorizationContext = this.authorizationContextCaptor.getValue();
		assertThat(authorizationContext.getClientRegistration()).isEqualTo(this.clientRegistration);
		assertThat(authorizationContext.getAuthorizedClient()).isNull();
		assertThat(authorizationContext.getPrincipal()).isEqualTo(this.principal);
		verify(this.authorizedClientRepository).removeAuthorizedClient(eq(this.clientRegistration.getRegistrationId()),
				eq(this.principal), eq(this.serverWebExchange));
		this.removeAuthorizedClientProbe.assertWasSubscribed();
		verify(this.authorizedClientRepository, never()).saveAuthorizedClient(any(), any(), any());
	}

	@SuppressWarnings("unchecked")
	@Test
	public void authorizeWhenServerErrorThenDoNotRemoveAuthorizedClient() {
		given(this.clientRegistrationRepository.findByRegistrationId(eq(this.clientRegistration.getRegistrationId())))
				.willReturn(Mono.just(this.clientRegistration));
		OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest
				.withClientRegistrationId(this.clientRegistration.getRegistrationId()).principal(this.principal)
				.build();
		ClientAuthorizationException exception = new ClientAuthorizationException(
				new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR, null, null),
				this.clientRegistration.getRegistrationId());
		given(this.authorizedClientProvider.authorize(any(OAuth2AuthorizationContext.class)))
				.willReturn(Mono.error(exception));
		assertThatExceptionOfType(ClientAuthorizationException.class).isThrownBy(
				() -> this.authorizedClientManager.authorize(authorizeRequest).subscriberContext(this.context).block())
				.isEqualTo(exception);
		verify(this.authorizedClientProvider).authorize(this.authorizationContextCaptor.capture());
		verify(this.contextAttributesMapper).apply(eq(authorizeRequest));
		OAuth2AuthorizationContext authorizationContext = this.authorizationContextCaptor.getValue();
		assertThat(authorizationContext.getClientRegistration()).isEqualTo(this.clientRegistration);
		assertThat(authorizationContext.getAuthorizedClient()).isNull();
		assertThat(authorizationContext.getPrincipal()).isEqualTo(this.principal);
		verify(this.authorizedClientRepository, never()).removeAuthorizedClient(any(), any(), any());
		verify(this.authorizedClientRepository, never()).saveAuthorizedClient(any(), any(), any());
	}

	@SuppressWarnings("unchecked")
	@Test
	public void authorizeWhenOAuth2AuthorizationExceptionThenDoNotRemoveAuthorizedClient() {
		given(this.clientRegistrationRepository.findByRegistrationId(eq(this.clientRegistration.getRegistrationId())))
				.willReturn(Mono.just(this.clientRegistration));
		OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest
				.withClientRegistrationId(this.clientRegistration.getRegistrationId()).principal(this.principal)
				.build();
		OAuth2AuthorizationException exception = new OAuth2AuthorizationException(
				new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT, null, null));
		given(this.authorizedClientProvider.authorize(any(OAuth2AuthorizationContext.class)))
				.willReturn(Mono.error(exception));
		assertThatExceptionOfType(OAuth2AuthorizationException.class).isThrownBy(
				() -> this.authorizedClientManager.authorize(authorizeRequest).subscriberContext(this.context).block())
				.isEqualTo(exception);
		verify(this.authorizedClientProvider).authorize(this.authorizationContextCaptor.capture());
		verify(this.contextAttributesMapper).apply(eq(authorizeRequest));
		OAuth2AuthorizationContext authorizationContext = this.authorizationContextCaptor.getValue();
		assertThat(authorizationContext.getClientRegistration()).isEqualTo(this.clientRegistration);
		assertThat(authorizationContext.getAuthorizedClient()).isNull();
		assertThat(authorizationContext.getPrincipal()).isEqualTo(this.principal);
		verify(this.authorizedClientRepository, never()).removeAuthorizedClient(any(), any(), any());
		verify(this.authorizedClientRepository, never()).saveAuthorizedClient(any(), any(), any());
	}

	@SuppressWarnings("unchecked")
	@Test
	public void authorizeWhenOAuth2AuthorizationExceptionAndCustomFailureHandlerThenInvokeCustomFailureHandler() {
		given(this.clientRegistrationRepository.findByRegistrationId(eq(this.clientRegistration.getRegistrationId())))
				.willReturn(Mono.just(this.clientRegistration));
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
		assertThatExceptionOfType(OAuth2AuthorizationException.class).isThrownBy(
				() -> this.authorizedClientManager.authorize(authorizeRequest).subscriberContext(this.context).block())
				.isEqualTo(exception);
		verify(this.authorizedClientProvider).authorize(this.authorizationContextCaptor.capture());
		verify(this.contextAttributesMapper).apply(eq(authorizeRequest));
		OAuth2AuthorizationContext authorizationContext = this.authorizationContextCaptor.getValue();
		assertThat(authorizationContext.getClientRegistration()).isEqualTo(this.clientRegistration);
		assertThat(authorizationContext.getAuthorizedClient()).isNull();
		assertThat(authorizationContext.getPrincipal()).isEqualTo(this.principal);
		authorizationFailureHandlerProbe.assertWasSubscribed();
		verify(this.authorizedClientRepository, never()).removeAuthorizedClient(any(), any(), any());
		verify(this.authorizedClientRepository, never()).saveAuthorizedClient(any(), any(), any());
	}

	@SuppressWarnings("unchecked")
	@Test
	public void authorizeWhenAuthorizedAndSupportedProviderThenReauthorized() {
		given(this.clientRegistrationRepository.findByRegistrationId(eq(this.clientRegistration.getRegistrationId())))
				.willReturn(Mono.just(this.clientRegistration));
		this.loadAuthorizedClientProbe = PublisherProbe.of(Mono.just(this.authorizedClient));
		given(this.authorizedClientRepository.loadAuthorizedClient(eq(this.clientRegistration.getRegistrationId()),
				eq(this.principal), eq(this.serverWebExchange))).willReturn(this.loadAuthorizedClientProbe.mono());
		OAuth2AuthorizedClient reauthorizedClient = new OAuth2AuthorizedClient(this.clientRegistration,
				this.principal.getName(), TestOAuth2AccessTokens.noScopes(), TestOAuth2RefreshTokens.refreshToken());
		given(this.authorizedClientProvider.authorize(any(OAuth2AuthorizationContext.class)))
				.willReturn(Mono.just(reauthorizedClient));
		OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest
				.withClientRegistrationId(this.clientRegistration.getRegistrationId()).principal(this.principal)
				.build();
		OAuth2AuthorizedClient authorizedClient = this.authorizedClientManager.authorize(authorizeRequest)
				.subscriberContext(this.context).block();
		verify(this.authorizedClientProvider).authorize(this.authorizationContextCaptor.capture());
		verify(this.contextAttributesMapper).apply(any());
		OAuth2AuthorizationContext authorizationContext = this.authorizationContextCaptor.getValue();
		assertThat(authorizationContext.getClientRegistration()).isEqualTo(this.clientRegistration);
		assertThat(authorizationContext.getAuthorizedClient()).isSameAs(this.authorizedClient);
		assertThat(authorizationContext.getPrincipal()).isEqualTo(this.principal);
		assertThat(authorizedClient).isSameAs(reauthorizedClient);
		verify(this.authorizedClientRepository).saveAuthorizedClient(eq(reauthorizedClient), eq(this.principal),
				eq(this.serverWebExchange));
		this.saveAuthorizedClientProbe.assertWasSubscribed();
		verify(this.authorizedClientRepository, never()).removeAuthorizedClient(any(), any(), any());
	}

	@Test
	public void authorizeWhenRequestFormParameterUsernamePasswordThenMappedToContext() {
		given(this.clientRegistrationRepository.findByRegistrationId(eq(this.clientRegistration.getRegistrationId())))
				.willReturn(Mono.just(this.clientRegistration));
		given(this.authorizedClientProvider.authorize(any(OAuth2AuthorizationContext.class)))
				.willReturn(Mono.just(this.authorizedClient));
		// Set custom contextAttributesMapper capable of mapping the form parameters
		this.authorizedClientManager.setContextAttributesMapper((authorizeRequest) -> currentServerWebExchange()
				.flatMap(ServerWebExchange::getFormData).map((formData) -> {
					Map<String, Object> contextAttributes = new HashMap<>();
					String username = formData.getFirst(OAuth2ParameterNames.USERNAME);
					contextAttributes.put(OAuth2AuthorizationContext.USERNAME_ATTRIBUTE_NAME, username);
					String password = formData.getFirst(OAuth2ParameterNames.PASSWORD);
					contextAttributes.put(OAuth2AuthorizationContext.PASSWORD_ATTRIBUTE_NAME, password);
					return contextAttributes;
				}));
		this.serverWebExchange = MockServerWebExchange.builder(MockServerHttpRequest.post("/")
				.contentType(MediaType.APPLICATION_FORM_URLENCODED).body("username=username&password=password"))
				.build();
		this.context = Context.of(ServerWebExchange.class, this.serverWebExchange);
		OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest
				.withClientRegistrationId(this.clientRegistration.getRegistrationId()).principal(this.principal)
				.build();
		this.authorizedClientManager.authorize(authorizeRequest).subscriberContext(this.context).block();
		verify(this.authorizedClientProvider).authorize(this.authorizationContextCaptor.capture());
		OAuth2AuthorizationContext authorizationContext = this.authorizationContextCaptor.getValue();
		String username = authorizationContext.getAttribute(OAuth2AuthorizationContext.USERNAME_ATTRIBUTE_NAME);
		assertThat(username).isEqualTo("username");
		String password = authorizationContext.getAttribute(OAuth2AuthorizationContext.PASSWORD_ATTRIBUTE_NAME);
		assertThat(password).isEqualTo("password");
	}

	@SuppressWarnings("unchecked")
	@Test
	public void reauthorizeWhenUnsupportedProviderThenNotReauthorized() {
		OAuth2AuthorizeRequest reauthorizeRequest = OAuth2AuthorizeRequest.withAuthorizedClient(this.authorizedClient)
				.principal(this.principal).build();
		OAuth2AuthorizedClient authorizedClient = this.authorizedClientManager.authorize(reauthorizeRequest)
				.subscriberContext(this.context).block();
		verify(this.authorizedClientProvider).authorize(this.authorizationContextCaptor.capture());
		verify(this.contextAttributesMapper).apply(eq(reauthorizeRequest));
		OAuth2AuthorizationContext authorizationContext = this.authorizationContextCaptor.getValue();
		assertThat(authorizationContext.getClientRegistration()).isEqualTo(this.clientRegistration);
		assertThat(authorizationContext.getAuthorizedClient()).isSameAs(this.authorizedClient);
		assertThat(authorizationContext.getPrincipal()).isEqualTo(this.principal);
		assertThat(authorizedClient).isSameAs(this.authorizedClient);
		this.saveAuthorizedClientProbe.assertWasNotSubscribed();
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
		OAuth2AuthorizedClient authorizedClient = this.authorizedClientManager.authorize(reauthorizeRequest)
				.subscriberContext(this.context).block();
		verify(this.authorizedClientProvider).authorize(this.authorizationContextCaptor.capture());
		verify(this.contextAttributesMapper).apply(eq(reauthorizeRequest));
		OAuth2AuthorizationContext authorizationContext = this.authorizationContextCaptor.getValue();
		assertThat(authorizationContext.getClientRegistration()).isEqualTo(this.clientRegistration);
		assertThat(authorizationContext.getAuthorizedClient()).isSameAs(this.authorizedClient);
		assertThat(authorizationContext.getPrincipal()).isEqualTo(this.principal);
		assertThat(authorizedClient).isSameAs(reauthorizedClient);
		verify(this.authorizedClientRepository).saveAuthorizedClient(eq(reauthorizedClient), eq(this.principal),
				eq(this.serverWebExchange));
		this.saveAuthorizedClientProbe.assertWasSubscribed();
		verify(this.authorizedClientRepository, never()).removeAuthorizedClient(any(), any(), any());
	}

	@Test
	public void reauthorizeWhenRequestParameterScopeThenMappedToContext() {
		OAuth2AuthorizedClient reauthorizedClient = new OAuth2AuthorizedClient(this.clientRegistration,
				this.principal.getName(), TestOAuth2AccessTokens.noScopes(), TestOAuth2RefreshTokens.refreshToken());
		given(this.authorizedClientProvider.authorize(any(OAuth2AuthorizationContext.class)))
				.willReturn(Mono.just(reauthorizedClient));
		// Override the mock with the default
		this.authorizedClientManager.setContextAttributesMapper(
				new DefaultReactiveOAuth2AuthorizedClientManager.DefaultContextAttributesMapper());
		this.serverWebExchange = MockServerWebExchange
				.builder(MockServerHttpRequest.get("/").queryParam(OAuth2ParameterNames.SCOPE, "read write")).build();
		this.context = Context.of(ServerWebExchange.class, this.serverWebExchange);
		OAuth2AuthorizeRequest reauthorizeRequest = OAuth2AuthorizeRequest.withAuthorizedClient(this.authorizedClient)
				.principal(this.principal).build();
		this.authorizedClientManager.authorize(reauthorizeRequest).subscriberContext(this.context).block();
		verify(this.authorizedClientProvider).authorize(this.authorizationContextCaptor.capture());
		OAuth2AuthorizationContext authorizationContext = this.authorizationContextCaptor.getValue();
		String[] requestScopeAttribute = authorizationContext
				.getAttribute(OAuth2AuthorizationContext.REQUEST_SCOPE_ATTRIBUTE_NAME);
		assertThat(requestScopeAttribute).contains("read", "write");
	}

	private Mono<ServerWebExchange> currentServerWebExchange() {
		return Mono.subscriberContext().filter((c) -> c.hasKey(ServerWebExchange.class))
				.map((c) -> c.get(ServerWebExchange.class));
	}

}
