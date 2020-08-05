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

package org.springframework.security.oauth2.client.web.reactive.result.method.annotation;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.core.MethodParameter;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.client.ClientAuthorizationRequiredException;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.client.web.DefaultReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.TestOAuth2AccessTokens;
import org.springframework.util.ReflectionUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import reactor.util.context.Context;

import java.lang.reflect.Method;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * @author Rob Winch
 * @since 5.1
 */
@RunWith(MockitoJUnitRunner.class)
public class OAuth2AuthorizedClientArgumentResolverTests {

	@Mock
	private ReactiveClientRegistrationRepository clientRegistrationRepository;

	@Mock
	private ServerOAuth2AuthorizedClientRepository authorizedClientRepository;

	private ServerWebExchange serverWebExchange = MockServerWebExchange.builder(MockServerHttpRequest.get("/")).build();

	private OAuth2AuthorizedClientArgumentResolver argumentResolver;

	private ClientRegistration clientRegistration;

	private OAuth2AuthorizedClient authorizedClient;

	private Authentication authentication = new TestingAuthenticationToken("test", "this");

	@Before
	public void setUp() {
		ReactiveOAuth2AuthorizedClientProvider authorizedClientProvider = ReactiveOAuth2AuthorizedClientProviderBuilder
				.builder().authorizationCode().refreshToken().clientCredentials().build();
		DefaultReactiveOAuth2AuthorizedClientManager authorizedClientManager = new DefaultReactiveOAuth2AuthorizedClientManager(
				this.clientRegistrationRepository, this.authorizedClientRepository);
		authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);
		this.argumentResolver = new OAuth2AuthorizedClientArgumentResolver(authorizedClientManager);
		this.clientRegistration = TestClientRegistrations.clientRegistration().build();
		this.authorizedClient = new OAuth2AuthorizedClient(this.clientRegistration, this.authentication.getName(),
				TestOAuth2AccessTokens.noScopes());
		when(this.authorizedClientRepository.loadAuthorizedClient(anyString(), any(), any()))
				.thenReturn(Mono.just(this.authorizedClient));
	}

	@Test
	public void constructorWhenClientRegistrationRepositoryIsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OAuth2AuthorizedClientArgumentResolver(null, this.authorizedClientRepository))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void constructorWhenOAuth2AuthorizedClientRepositoryIsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OAuth2AuthorizedClientArgumentResolver(this.clientRegistrationRepository, null))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void constructorWhenAuthorizedClientManagerIsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OAuth2AuthorizedClientArgumentResolver(null))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void supportsParameterWhenParameterTypeOAuth2AuthorizedClientThenTrue() {
		MethodParameter methodParameter = this.getMethodParameter("paramTypeAuthorizedClient",
				OAuth2AuthorizedClient.class);
		assertThat(this.argumentResolver.supportsParameter(methodParameter)).isTrue();
	}

	@Test
	public void supportsParameterWhenParameterTypeOAuth2AuthorizedClientWithoutAnnotationThenFalse() {
		MethodParameter methodParameter = this.getMethodParameter("paramTypeAuthorizedClientWithoutAnnotation",
				OAuth2AuthorizedClient.class);
		assertThat(this.argumentResolver.supportsParameter(methodParameter)).isFalse();
	}

	@Test
	public void supportsParameterWhenParameterTypeUnsupportedWithoutAnnotationThenFalse() {
		MethodParameter methodParameter = this.getMethodParameter("paramTypeUnsupportedWithoutAnnotation",
				String.class);
		assertThat(this.argumentResolver.supportsParameter(methodParameter)).isFalse();
	}

	@Test
	public void resolveArgumentWhenRegistrationIdEmptyAndNotOAuth2AuthenticationThenThrowIllegalArgumentException() {
		MethodParameter methodParameter = this.getMethodParameter("registrationIdEmpty", OAuth2AuthorizedClient.class);
		assertThatThrownBy(() -> resolveArgument(methodParameter)).isInstanceOf(IllegalArgumentException.class)
				.hasMessage("The clientRegistrationId could not be resolved. Please provide one");
	}

	@Test
	public void resolveArgumentWhenRegistrationIdEmptyAndOAuth2AuthenticationThenResolves() {
		this.authentication = mock(OAuth2AuthenticationToken.class);
		when(((OAuth2AuthenticationToken) this.authentication).getAuthorizedClientRegistrationId())
				.thenReturn("client1");
		MethodParameter methodParameter = this.getMethodParameter("registrationIdEmpty", OAuth2AuthorizedClient.class);
		resolveArgument(methodParameter);
	}

	@Test
	public void resolveArgumentWhenParameterTypeOAuth2AuthorizedClientAndCurrentAuthenticationNullThenResolves() {
		this.authentication = null;
		MethodParameter methodParameter = this.getMethodParameter("paramTypeAuthorizedClient",
				OAuth2AuthorizedClient.class);
		assertThat(resolveArgument(methodParameter)).isSameAs(this.authorizedClient);
	}

	@Test
	public void resolveArgumentWhenOAuth2AuthorizedClientFoundThenResolves() {
		MethodParameter methodParameter = this.getMethodParameter("paramTypeAuthorizedClient",
				OAuth2AuthorizedClient.class);
		assertThat(resolveArgument(methodParameter)).isSameAs(this.authorizedClient);
	}

	@Test
	public void resolveArgumentWhenOAuth2AuthorizedClientNotFoundThenThrowClientAuthorizationRequiredException() {
		when(this.clientRegistrationRepository.findByRegistrationId(any()))
				.thenReturn(Mono.just(this.clientRegistration));
		when(this.authorizedClientRepository.loadAuthorizedClient(anyString(), any(), any())).thenReturn(Mono.empty());
		MethodParameter methodParameter = this.getMethodParameter("paramTypeAuthorizedClient",
				OAuth2AuthorizedClient.class);
		assertThatThrownBy(() -> resolveArgument(methodParameter))
				.isInstanceOf(ClientAuthorizationRequiredException.class);
	}

	private Object resolveArgument(MethodParameter methodParameter) {
		return this.argumentResolver.resolveArgument(methodParameter, null, null)
				.subscriberContext(this.authentication == null ? Context.empty()
						: ReactiveSecurityContextHolder.withAuthentication(this.authentication))
				.subscriberContext(serverWebExchange()).block();
	}

	private Context serverWebExchange() {
		return Context.of(ServerWebExchange.class, this.serverWebExchange);
	}

	private MethodParameter getMethodParameter(String methodName, Class<?>... paramTypes) {
		Method method = ReflectionUtils.findMethod(TestController.class, methodName, paramTypes);
		return new MethodParameter(method, 0);
	}

	static class TestController {

		void paramTypeAuthorizedClient(
				@RegisteredOAuth2AuthorizedClient("client1") OAuth2AuthorizedClient authorizedClient) {
		}

		void paramTypeAuthorizedClientWithoutAnnotation(OAuth2AuthorizedClient authorizedClient) {
		}

		void paramTypeUnsupported(@RegisteredOAuth2AuthorizedClient("client1") String param) {
		}

		void paramTypeUnsupportedWithoutAnnotation(String param) {
		}

		void registrationIdEmpty(@RegisteredOAuth2AuthorizedClient OAuth2AuthorizedClient authorizedClient) {
		}

	}

}
