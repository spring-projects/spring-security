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

package org.springframework.security.oauth2.client.web.reactive.result.method.annotation;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.core.MethodParameter;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.client.ClientAuthorizationRequiredException;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.endpoint.OAuth2ClientCredentialsGrantRequest;
import org.springframework.security.oauth2.client.endpoint.ReactiveOAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.util.ReflectionUtils;
import reactor.core.publisher.Mono;
import reactor.util.context.Context;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;
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
	private OAuth2AuthorizedClientArgumentResolver argumentResolver;
	private OAuth2AuthorizedClient authorizedClient;

	private Authentication authentication = new TestingAuthenticationToken("test", "this");

	@Before
	public void setUp() {
		this.argumentResolver = new OAuth2AuthorizedClientArgumentResolver(this.clientRegistrationRepository, this.authorizedClientRepository);
		this.authorizedClient = mock(OAuth2AuthorizedClient.class);
		when(this.authorizedClientRepository.loadAuthorizedClient(anyString(), any(), any())).thenReturn(Mono.just(this.authorizedClient));
	}

	@Test
	public void constructorWhenOAuth2AuthorizedClientServiceIsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OAuth2AuthorizedClientArgumentResolver(this.clientRegistrationRepository, null))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void supportsParameterWhenParameterTypeOAuth2AuthorizedClientThenTrue() {
		MethodParameter methodParameter = this.getMethodParameter("paramTypeAuthorizedClient", OAuth2AuthorizedClient.class);
		assertThat(this.argumentResolver.supportsParameter(methodParameter)).isTrue();
	}

	@Test
	public void supportsParameterWhenParameterTypeOAuth2AuthorizedClientWithoutAnnotationThenFalse() {
		MethodParameter methodParameter = this.getMethodParameter("paramTypeAuthorizedClientWithoutAnnotation", OAuth2AuthorizedClient.class);
		assertThat(this.argumentResolver.supportsParameter(methodParameter)).isFalse();
	}

	@Test
	public void supportsParameterWhenParameterTypeUnsupportedWithoutAnnotationThenFalse() {
		MethodParameter methodParameter = this.getMethodParameter("paramTypeUnsupportedWithoutAnnotation", String.class);
		assertThat(this.argumentResolver.supportsParameter(methodParameter)).isFalse();
	}

	@Test
	public void resolveArgumentWhenRegistrationIdEmptyAndNotOAuth2AuthenticationThenThrowIllegalArgumentException() {
		MethodParameter methodParameter = this.getMethodParameter("registrationIdEmpty", OAuth2AuthorizedClient.class);
		assertThatThrownBy(() -> resolveArgument(methodParameter))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("The clientRegistrationId could not be resolved. Please provide one");
	}

	@Test
	public void resolveArgumentWhenRegistrationIdEmptyAndOAuth2AuthenticationThenResolves() {
		when(this.clientRegistrationRepository.findByRegistrationId(any())).thenReturn(Mono.just(
				TestClientRegistrations.clientRegistration().build()));
		this.authentication = mock(OAuth2AuthenticationToken.class);
		when(((OAuth2AuthenticationToken) this.authentication).getAuthorizedClientRegistrationId()).thenReturn("client1");
		MethodParameter methodParameter = this.getMethodParameter("registrationIdEmpty", OAuth2AuthorizedClient.class);
		resolveArgument(methodParameter);
	}

	@Test
	public void resolveArgumentWhenParameterTypeOAuth2AuthorizedClientAndCurrentAuthenticationNullThenResolves() {
		this.authentication = null;
		when(this.clientRegistrationRepository.findByRegistrationId(any())).thenReturn(Mono.just(
				TestClientRegistrations.clientRegistration().build()));
		MethodParameter methodParameter = this.getMethodParameter("paramTypeAuthorizedClient", OAuth2AuthorizedClient.class);
		assertThat(resolveArgument(methodParameter)).isSameAs(this.authorizedClient);
	}

	@Test
	public void resolveArgumentWhenOAuth2AuthorizedClientFoundThenResolves() {
		when(this.clientRegistrationRepository.findByRegistrationId(any())).thenReturn(Mono.just(
				TestClientRegistrations.clientRegistration().build()));
		MethodParameter methodParameter = this.getMethodParameter("paramTypeAuthorizedClient", OAuth2AuthorizedClient.class);
		assertThat(resolveArgument(methodParameter)).isSameAs(this.authorizedClient);
	}

	@Test
	public void resolveArgumentWhenOAuth2AuthorizedClientNotFoundThenThrowClientAuthorizationRequiredException() {
		when(this.clientRegistrationRepository.findByRegistrationId(any())).thenReturn(Mono.just(
				TestClientRegistrations.clientRegistration().build()));
		when(this.authorizedClientRepository.loadAuthorizedClient(anyString(), any(), any())).thenReturn(Mono.empty());
		MethodParameter methodParameter = this.getMethodParameter("paramTypeAuthorizedClient", OAuth2AuthorizedClient.class);
		assertThatThrownBy(() -> resolveArgument(methodParameter))
				.isInstanceOf(ClientAuthorizationRequiredException.class);
	}

	@Test
	public void resolveArgumentClientCredentialsExpireReacquireToken() { //throws Exception {
		ReactiveOAuth2AccessTokenResponseClient<OAuth2ClientCredentialsGrantRequest> clientCredentialsTokenResponseClient =
				mock(ReactiveOAuth2AccessTokenResponseClient.class);
		setClientCredentialsTokenResponseClient(clientCredentialsTokenResponseClient);

		OAuth2AccessTokenResponse accessTokenResponse = OAuth2AccessTokenResponse
				.withToken("access-token-1234")
				.tokenType(OAuth2AccessToken.TokenType.BEARER)
				.expiresIn(0)
				.build();

		ClientRegistration registration = ClientRegistration.withRegistrationId("client2")
				.clientId("client-2")
				.clientSecret("secret")
				.clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.scope("read", "write")
				.tokenUri("https://provider.com/oauth2/token")
				.build();
		when(clientCredentialsTokenResponseClient.getTokenResponse(any())).thenReturn(Mono.just(accessTokenResponse));

		OAuth2AuthorizedClient authorizedClient2 = new OAuth2AuthorizedClient(registration, authentication.getPrincipal().toString(), accessTokenResponse.getAccessToken());
		when(this.authorizedClientRepository.loadAuthorizedClient(anyString(), any(Authentication.class), any())).thenReturn(Mono.just(authorizedClient2));
		when(this.authorizedClientRepository.saveAuthorizedClient(any(OAuth2AuthorizedClient.class), any(Authentication.class), any())).thenReturn(Mono.empty());
		when(this.clientRegistrationRepository.findByRegistrationId(any())).thenReturn(Mono.just(registration));

		MethodParameter methodParameter = this.getMethodParameter("paramTypeAuthorizedClient2", OAuth2AuthorizedClient.class);
		OAuth2AuthorizedClient resolvedClient = (OAuth2AuthorizedClient) resolveArgument(methodParameter);
		assertThat(resolvedClient).isNotSameAs(authorizedClient2);
		assertThat(resolvedClient).isEqualToComparingFieldByField(authorizedClient2);
	}

	private Object resolveArgument(MethodParameter methodParameter) {
		return this.argumentResolver.resolveArgument(methodParameter, null, null)
				.subscriberContext(this.authentication == null ? Context.empty() : ReactiveSecurityContextHolder.withAuthentication(this.authentication))
				.block();
	}

	private MethodParameter getMethodParameter(String methodName, Class<?>... paramTypes) {
		Method method = ReflectionUtils.findMethod(
				TestController.class, methodName, paramTypes);
		return new MethodParameter(method, 0);
	}

	private void setClientCredentialsTokenResponseClient(ReactiveOAuth2AccessTokenResponseClient<OAuth2ClientCredentialsGrantRequest> clientCredentialsTokenResponseClient) {
		try {
			Field clientResolverField = OAuth2AuthorizedClientArgumentResolver.class.getDeclaredField("authorizedClientResolver");
			clientResolverField.setAccessible(true);
			OAuth2AuthorizedClientResolver clientResolver = (OAuth2AuthorizedClientResolver) clientResolverField.get(this.argumentResolver);

			Method setClientCredsTokenRespClientMethod = OAuth2AuthorizedClientResolver.class.getMethod("setClientCredentialsTokenResponseClient", ReactiveOAuth2AccessTokenResponseClient.class);
			setClientCredsTokenRespClientMethod.invoke(clientResolver, clientCredentialsTokenResponseClient);
		} catch (NoSuchMethodException | IllegalAccessException | InvocationTargetException | NoSuchFieldException e) {
			e.printStackTrace();
		}
	}

	static class TestController {
		void paramTypeAuthorizedClient(@RegisteredOAuth2AuthorizedClient("client1") OAuth2AuthorizedClient authorizedClient) {
		}

		void paramTypeAuthorizedClient2(@RegisteredOAuth2AuthorizedClient("client2") OAuth2AuthorizedClient authorizedClient) {
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
