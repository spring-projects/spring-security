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
import org.springframework.http.MediaType;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizationContext;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.TestOAuth2AccessTokens;
import org.springframework.security.oauth2.core.TestOAuth2RefreshTokens;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import reactor.util.context.Context;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

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

	@SuppressWarnings("unchecked")
	@Before
	public void setup() {
		this.clientRegistrationRepository = mock(ReactiveClientRegistrationRepository.class);
		when(this.clientRegistrationRepository.findByRegistrationId(
				anyString())).thenReturn(Mono.empty());
		this.authorizedClientRepository = mock(ServerOAuth2AuthorizedClientRepository.class);
		when(this.authorizedClientRepository.loadAuthorizedClient(
				anyString(), any(Authentication.class), any(ServerWebExchange.class))).thenReturn(Mono.empty());
		when(this.authorizedClientRepository.saveAuthorizedClient(
				any(OAuth2AuthorizedClient.class), any(Authentication.class), any(ServerWebExchange.class))).thenReturn(Mono.empty());
		this.authorizedClientProvider = mock(ReactiveOAuth2AuthorizedClientProvider.class);
		when(this.authorizedClientProvider.authorize(any(OAuth2AuthorizationContext.class))).thenReturn(Mono.empty());
		this.contextAttributesMapper = mock(Function.class);
		when(this.contextAttributesMapper.apply(any())).thenReturn(Mono.just(Collections.emptyMap()));
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
		assertThatThrownBy(() -> new DefaultReactiveOAuth2AuthorizedClientManager(null, this.authorizedClientRepository))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("clientRegistrationRepository cannot be null");
	}

	@Test
	public void constructorWhenOAuth2AuthorizedClientRepositoryIsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new DefaultReactiveOAuth2AuthorizedClientManager(this.clientRegistrationRepository, null))
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
	public void authorizeWhenRequestIsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> this.authorizedClientManager.authorize(null).block())
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("authorizeRequest cannot be null");
	}

	@Test
	public void authorizeWhenClientRegistrationNotFoundThenThrowIllegalArgumentException() {
		OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest.withClientRegistrationId("invalid-registration-id")
				.principal(this.principal)
				.build();
		assertThatThrownBy(() -> this.authorizedClientManager.authorize(authorizeRequest).subscriberContext(this.context).block())
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("Could not find ClientRegistration with id 'invalid-registration-id'");
	}

	@SuppressWarnings("unchecked")
	@Test
	public void authorizeWhenNotAuthorizedAndUnsupportedProviderThenNotAuthorized() {
		when(this.clientRegistrationRepository.findByRegistrationId(
				eq(this.clientRegistration.getRegistrationId()))).thenReturn(Mono.just(this.clientRegistration));

		OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest.withClientRegistrationId(this.clientRegistration.getRegistrationId())
				.principal(this.principal)
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
		verify(this.authorizedClientRepository, never()).saveAuthorizedClient(any(), any(), any());
	}

	@SuppressWarnings("unchecked")
	@Test
	public void authorizeWhenNotAuthorizedAndSupportedProviderThenAuthorized() {
		when(this.clientRegistrationRepository.findByRegistrationId(
				eq(this.clientRegistration.getRegistrationId()))).thenReturn(Mono.just(this.clientRegistration));
		when(this.authorizedClientProvider.authorize(
				any(OAuth2AuthorizationContext.class))).thenReturn(Mono.just(this.authorizedClient));

		OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest.withClientRegistrationId(this.clientRegistration.getRegistrationId())
				.principal(this.principal)
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
		verify(this.authorizedClientRepository).saveAuthorizedClient(
				eq(this.authorizedClient), eq(this.principal), eq(this.serverWebExchange));
	}

	@Test
	public void authorizeWhenNotAuthorizedAndSupportedProviderAndExchangeUnavailableThenAuthorizedButNotSaved() {
		when(this.clientRegistrationRepository.findByRegistrationId(
				eq(this.clientRegistration.getRegistrationId()))).thenReturn(Mono.just(this.clientRegistration));

		when(this.authorizedClientProvider.authorize(
				any(OAuth2AuthorizationContext.class))).thenReturn(Mono.just(this.authorizedClient));

		OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest.withClientRegistrationId(this.clientRegistration.getRegistrationId())
				.principal(this.principal)
				.build();
		OAuth2AuthorizedClient authorizedClient = this.authorizedClientManager.authorize(authorizeRequest).block();

		verify(this.authorizedClientProvider).authorize(this.authorizationContextCaptor.capture());
		verify(this.contextAttributesMapper).apply(eq(authorizeRequest));

		OAuth2AuthorizationContext authorizationContext = this.authorizationContextCaptor.getValue();
		assertThat(authorizationContext.getClientRegistration()).isEqualTo(this.clientRegistration);
		assertThat(authorizationContext.getAuthorizedClient()).isNull();
		assertThat(authorizationContext.getPrincipal()).isEqualTo(this.principal);

		assertThat(authorizedClient).isSameAs(this.authorizedClient);
		verify(this.authorizedClientRepository, never()).saveAuthorizedClient(any(), any(), any());
	}

	@SuppressWarnings("unchecked")
	@Test
	public void authorizeWhenAuthorizedAndSupportedProviderThenReauthorized() {
		when(this.clientRegistrationRepository.findByRegistrationId(
				eq(this.clientRegistration.getRegistrationId()))).thenReturn(Mono.just(this.clientRegistration));
		when(this.authorizedClientRepository.loadAuthorizedClient(
				eq(this.clientRegistration.getRegistrationId()), eq(this.principal), eq(this.serverWebExchange))).thenReturn(Mono.just(this.authorizedClient));

		OAuth2AuthorizedClient reauthorizedClient = new OAuth2AuthorizedClient(
				this.clientRegistration, this.principal.getName(),
				TestOAuth2AccessTokens.noScopes(), TestOAuth2RefreshTokens.refreshToken());

		when(this.authorizedClientProvider.authorize(any(OAuth2AuthorizationContext.class))).thenReturn(Mono.just(reauthorizedClient));

		OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest.withClientRegistrationId(this.clientRegistration.getRegistrationId())
				.principal(this.principal)
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
		verify(this.authorizedClientRepository).saveAuthorizedClient(
				eq(reauthorizedClient), eq(this.principal), eq(this.serverWebExchange));
	}

	@Test
	public void authorizeWhenRequestFormParameterUsernamePasswordThenMappedToContext() {
		when(this.clientRegistrationRepository.findByRegistrationId(
				eq(this.clientRegistration.getRegistrationId()))).thenReturn(Mono.just(this.clientRegistration));

		when(this.authorizedClientProvider.authorize(any(OAuth2AuthorizationContext.class))).thenReturn(Mono.just(this.authorizedClient));

		// Set custom contextAttributesMapper capable of mapping the form parameters
		this.authorizedClientManager.setContextAttributesMapper(authorizeRequest ->
				currentServerWebExchange()
					.flatMap(ServerWebExchange::getFormData)
					.map(formData -> {
						Map<String, Object> contextAttributes = new HashMap<>();
						String username = formData.getFirst(OAuth2ParameterNames.USERNAME);
						contextAttributes.put(OAuth2AuthorizationContext.USERNAME_ATTRIBUTE_NAME, username);
						String password = formData.getFirst(OAuth2ParameterNames.PASSWORD);
						contextAttributes.put(OAuth2AuthorizationContext.PASSWORD_ATTRIBUTE_NAME, password);
						return contextAttributes;
					})
		);

		this.serverWebExchange = MockServerWebExchange.builder(
				MockServerHttpRequest
						.post("/")
						.contentType(MediaType.APPLICATION_FORM_URLENCODED)
						.body("username=username&password=password"))
				.build();
		this.context = Context.of(ServerWebExchange.class, this.serverWebExchange);

		OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest.withClientRegistrationId(this.clientRegistration.getRegistrationId())
				.principal(this.principal)
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
				.principal(this.principal)
				.build();
		OAuth2AuthorizedClient authorizedClient = this.authorizedClientManager.authorize(reauthorizeRequest)
				.subscriberContext(this.context).block();

		verify(this.authorizedClientProvider).authorize(this.authorizationContextCaptor.capture());
		verify(this.contextAttributesMapper).apply(eq(reauthorizeRequest));

		OAuth2AuthorizationContext authorizationContext = this.authorizationContextCaptor.getValue();
		assertThat(authorizationContext.getClientRegistration()).isEqualTo(this.clientRegistration);
		assertThat(authorizationContext.getAuthorizedClient()).isSameAs(this.authorizedClient);
		assertThat(authorizationContext.getPrincipal()).isEqualTo(this.principal);

		assertThat(authorizedClient).isSameAs(this.authorizedClient);
		verify(this.authorizedClientRepository, never()).saveAuthorizedClient(any(), any(), any());
	}

	@SuppressWarnings("unchecked")
	@Test
	public void reauthorizeWhenSupportedProviderThenReauthorized() {
		OAuth2AuthorizedClient reauthorizedClient = new OAuth2AuthorizedClient(
				this.clientRegistration, this.principal.getName(),
				TestOAuth2AccessTokens.noScopes(), TestOAuth2RefreshTokens.refreshToken());

		when(this.authorizedClientProvider.authorize(any(OAuth2AuthorizationContext.class))).thenReturn(Mono.just(reauthorizedClient));

		OAuth2AuthorizeRequest reauthorizeRequest = OAuth2AuthorizeRequest.withAuthorizedClient(this.authorizedClient)
				.principal(this.principal)
				.build();
		OAuth2AuthorizedClient authorizedClient = this.authorizedClientManager.authorize(reauthorizeRequest)
				.subscriberContext(this.context).block();

		verify(this.authorizedClientProvider).authorize(this.authorizationContextCaptor.capture());
		verify(this.contextAttributesMapper).apply(eq(reauthorizeRequest));

		OAuth2AuthorizationContext authorizationContext = this.authorizationContextCaptor.getValue();
		assertThat(authorizationContext.getClientRegistration()).isEqualTo(this.clientRegistration);
		assertThat(authorizationContext.getAuthorizedClient()).isSameAs(this.authorizedClient);
		assertThat(authorizationContext.getPrincipal()).isEqualTo(this.principal);

		assertThat(authorizedClient).isSameAs(reauthorizedClient);
		verify(this.authorizedClientRepository).saveAuthorizedClient(
				eq(reauthorizedClient), eq(this.principal), eq(this.serverWebExchange));
	}

	@Test
	public void reauthorizeWhenRequestParameterScopeThenMappedToContext() {
		OAuth2AuthorizedClient reauthorizedClient = new OAuth2AuthorizedClient(
				this.clientRegistration, this.principal.getName(),
				TestOAuth2AccessTokens.noScopes(), TestOAuth2RefreshTokens.refreshToken());

		when(this.authorizedClientProvider.authorize(any(OAuth2AuthorizationContext.class))).thenReturn(Mono.just(reauthorizedClient));

		// Override the mock with the default
		this.authorizedClientManager.setContextAttributesMapper(
				new DefaultReactiveOAuth2AuthorizedClientManager.DefaultContextAttributesMapper());

		this.serverWebExchange = MockServerWebExchange.builder(
				MockServerHttpRequest
						.get("/")
						.queryParam(OAuth2ParameterNames.SCOPE, "read write"))
				.build();
		this.context = Context.of(ServerWebExchange.class, this.serverWebExchange);

		OAuth2AuthorizeRequest reauthorizeRequest = OAuth2AuthorizeRequest.withAuthorizedClient(this.authorizedClient)
				.principal(this.principal)
				.build();
		this.authorizedClientManager.authorize(reauthorizeRequest).subscriberContext(this.context).block();

		verify(this.authorizedClientProvider).authorize(this.authorizationContextCaptor.capture());

		OAuth2AuthorizationContext authorizationContext = this.authorizationContextCaptor.getValue();
		String[] requestScopeAttribute = authorizationContext.getAttribute(OAuth2AuthorizationContext.REQUEST_SCOPE_ATTRIBUTE_NAME);
		assertThat(requestScopeAttribute).contains("read", "write");
	}

	private Mono<ServerWebExchange> currentServerWebExchange() {
		return Mono.subscriberContext()
				.filter(c -> c.hasKey(ServerWebExchange.class))
				.map(c -> c.get(ServerWebExchange.class));
	}
}
