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
package org.springframework.security.oauth2.client.web.method.annotation;

import org.junit.Before;
import org.junit.Test;
import org.springframework.core.MethodParameter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.ClientAuthorizationRequiredException;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.annotation.OAuth2Client;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.util.ReflectionUtils;

import java.lang.reflect.Method;

import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;
import static org.assertj.core.api.AssertionsForInterfaceTypes.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link OAuth2ClientArgumentResolver}.
 *
 * @author Joe Grandja
 */
public class OAuth2ClientArgumentResolverTests {
	private ClientRegistrationRepository clientRegistrationRepository;
	private OAuth2AuthorizedClientService authorizedClientService;
	private OAuth2ClientArgumentResolver argumentResolver;
	private ClientRegistration clientRegistration;
	private OAuth2AuthorizedClient authorizedClient;
	private OAuth2AccessToken accessToken;

	@Before
	public void setUp() {
		this.clientRegistrationRepository = mock(ClientRegistrationRepository.class);
		this.authorizedClientService = mock(OAuth2AuthorizedClientService.class);
		this.argumentResolver = new OAuth2ClientArgumentResolver(
			this.clientRegistrationRepository, this.authorizedClientService);
		this.clientRegistration = ClientRegistration.withRegistrationId("client1")
				.clientId("client-id")
				.clientSecret("secret")
				.clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.redirectUriTemplate("{baseUrl}/client1")
				.scope("scope1", "scope2")
				.authorizationUri("https://provider.com/oauth2/auth")
				.tokenUri("https://provider.com/oauth2/token")
				.clientName("Client 1")
				.build();
		when(this.clientRegistrationRepository.findByRegistrationId(anyString())).thenReturn(this.clientRegistration);
		this.authorizedClient = mock(OAuth2AuthorizedClient.class);
		when(this.authorizedClientService.loadAuthorizedClient(anyString(), any())).thenReturn(this.authorizedClient);
		this.accessToken = mock(OAuth2AccessToken.class);
		when(this.authorizedClient.getAccessToken()).thenReturn(this.accessToken);
		SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
		securityContext.setAuthentication(mock(Authentication.class));
		SecurityContextHolder.setContext(securityContext);
	}

	@Test
	public void constructorWhenClientRegistrationRepositoryIsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OAuth2ClientArgumentResolver(null, this.authorizedClientService))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void constructorWhenOAuth2AuthorizedClientServiceIsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OAuth2ClientArgumentResolver(this.clientRegistrationRepository, null))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void supportsParameterWhenParameterTypeOAuth2AccessTokenThenTrue() {
		MethodParameter methodParameter = this.getMethodParameter("paramTypeAccessToken", OAuth2AccessToken.class);
		assertThat(this.argumentResolver.supportsParameter(methodParameter)).isTrue();
	}

	@Test
	public void supportsParameterWhenParameterTypeOAuth2AccessTokenWithoutAnnotationThenFalse() {
		MethodParameter methodParameter = this.getMethodParameter("paramTypeAccessTokenWithoutAnnotation", OAuth2AccessToken.class);
		assertThat(this.argumentResolver.supportsParameter(methodParameter)).isFalse();
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
	public void supportsParameterWhenParameterTypeClientRegistrationThenTrue() {
		MethodParameter methodParameter = this.getMethodParameter("paramTypeClientRegistration", ClientRegistration.class);
		assertThat(this.argumentResolver.supportsParameter(methodParameter)).isTrue();
	}

	@Test
	public void supportsParameterWhenParameterTypeClientRegistrationWithoutAnnotationThenFalse() {
		MethodParameter methodParameter = this.getMethodParameter("paramTypeClientRegistrationWithoutAnnotation", ClientRegistration.class);
		assertThat(this.argumentResolver.supportsParameter(methodParameter)).isFalse();
	}

	@Test
	public void supportsParameterWhenParameterTypeUnsupportedThenFalse() {
		MethodParameter methodParameter = this.getMethodParameter("paramTypeUnsupported", String.class);
		assertThat(this.argumentResolver.supportsParameter(methodParameter)).isFalse();
	}

	@Test
	public void supportsParameterWhenParameterTypeUnsupportedWithoutAnnotationThenFalse() {
		MethodParameter methodParameter = this.getMethodParameter("paramTypeUnsupportedWithoutAnnotation", String.class);
		assertThat(this.argumentResolver.supportsParameter(methodParameter)).isFalse();
	}

	@Test
	public void resolveArgumentWhenRegistrationIdEmptyAndNotOAuth2AuthenticationThenThrowIllegalArgumentException() throws Exception {
		MethodParameter methodParameter = this.getMethodParameter("registrationIdEmpty", OAuth2AccessToken.class);
		assertThatThrownBy(() -> this.argumentResolver.resolveArgument(methodParameter, null, null, null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("Unable to resolve the Client Registration Identifier. It must be provided via @OAuth2Client(\"client1\") or @OAuth2Client(registrationId = \"client1\").");
	}

	@Test
	public void resolveArgumentWhenRegistrationIdEmptyAndOAuth2AuthenticationThenResolves() throws Exception {
		OAuth2AuthenticationToken authentication = mock(OAuth2AuthenticationToken.class);
		when(authentication.getAuthorizedClientRegistrationId()).thenReturn("client1");
		SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
		securityContext.setAuthentication(authentication);
		SecurityContextHolder.setContext(securityContext);
		MethodParameter methodParameter = this.getMethodParameter("registrationIdEmpty", OAuth2AccessToken.class);
		this.argumentResolver.resolveArgument(methodParameter, null, null, null);
	}

	@Test
	public void resolveArgumentWhenClientRegistrationFoundThenResolves() throws Exception {
		MethodParameter methodParameter = this.getMethodParameter("paramTypeClientRegistration", ClientRegistration.class);
		assertThat(this.argumentResolver.resolveArgument(methodParameter, null, null, null)).isSameAs(this.clientRegistration);
	}

	@Test
	public void resolveArgumentWhenClientRegistrationNotFoundThenThrowIllegalArgumentException() throws Exception {
		when(this.clientRegistrationRepository.findByRegistrationId(anyString())).thenReturn(null);
		MethodParameter methodParameter = this.getMethodParameter("paramTypeClientRegistration", ClientRegistration.class);
		assertThatThrownBy(() -> this.argumentResolver.resolveArgument(methodParameter, null, null, null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("Unable to find ClientRegistration with registration identifier \"client1\".");
	}

	@Test
	public void resolveArgumentWhenParameterTypeOAuth2AuthorizedClientAndCurrentAuthenticationNullThenThrowIllegalStateException() throws Exception {
		SecurityContextHolder.clearContext();
		MethodParameter methodParameter = this.getMethodParameter("paramTypeAuthorizedClient", OAuth2AuthorizedClient.class);
		assertThatThrownBy(() -> this.argumentResolver.resolveArgument(methodParameter, null, null, null))
				.isInstanceOf(IllegalStateException.class)
				.hasMessage("Unable to resolve the Authorized Client with registration identifier \"client1\". " +
						"An \"authenticated\" or \"unauthenticated\" session is required. " +
						"To allow for unauthenticated access, ensure HttpSecurity.anonymous() is configured.");
	}

	@Test
	public void resolveArgumentWhenOAuth2AuthorizedClientFoundThenResolves() throws Exception {
		MethodParameter methodParameter = this.getMethodParameter("paramTypeAuthorizedClient", OAuth2AuthorizedClient.class);
		assertThat(this.argumentResolver.resolveArgument(methodParameter, null, null, null)).isSameAs(this.authorizedClient);
	}

	@Test
	public void resolveArgumentWhenOAuth2AuthorizedClientNotFoundThenThrowClientAuthorizationRequiredException() throws Exception {
		when(this.authorizedClientService.loadAuthorizedClient(anyString(), any())).thenReturn(null);
		MethodParameter methodParameter = this.getMethodParameter("paramTypeAuthorizedClient", OAuth2AuthorizedClient.class);
		assertThatThrownBy(() -> this.argumentResolver.resolveArgument(methodParameter, null, null, null))
				.isInstanceOf(ClientAuthorizationRequiredException.class);
	}

	@Test
	public void resolveArgumentWhenOAuth2AccessTokenAndOAuth2AuthorizedClientFoundThenResolves() throws Exception {
		MethodParameter methodParameter = this.getMethodParameter("paramTypeAccessToken", OAuth2AccessToken.class);
		assertThat(this.argumentResolver.resolveArgument(methodParameter, null, null, null)).isSameAs(this.authorizedClient.getAccessToken());
	}

	@Test
	public void resolveArgumentWhenOAuth2AccessTokenAndOAuth2AuthorizedClientNotFoundThenThrowClientAuthorizationRequiredException() throws Exception {
		when(this.authorizedClientService.loadAuthorizedClient(anyString(), any())).thenReturn(null);
		MethodParameter methodParameter = this.getMethodParameter("paramTypeAccessToken", OAuth2AccessToken.class);
		assertThatThrownBy(() -> this.argumentResolver.resolveArgument(methodParameter, null, null, null))
				.isInstanceOf(ClientAuthorizationRequiredException.class);
	}

	@Test
	public void resolveArgumentWhenOAuth2AccessTokenAndAnnotationRegistrationIdSetThenResolves() throws Exception {
		MethodParameter methodParameter = this.getMethodParameter("paramTypeAccessTokenAnnotationRegistrationId", OAuth2AccessToken.class);
		assertThat(this.argumentResolver.resolveArgument(methodParameter, null, null, null)).isSameAs(this.authorizedClient.getAccessToken());
	}

	private MethodParameter getMethodParameter(String methodName, Class<?>... paramTypes) {
		Method method = ReflectionUtils.findMethod(TestController.class, methodName, paramTypes);
		return new MethodParameter(method, 0);
	}

	static class TestController {
		void paramTypeAccessToken(@OAuth2Client("client1") OAuth2AccessToken accessToken) {
		}

		void paramTypeAccessTokenWithoutAnnotation(OAuth2AccessToken accessToken) {
		}

		void paramTypeAuthorizedClient(@OAuth2Client("client1") OAuth2AuthorizedClient authorizedClient) {
		}

		void paramTypeAuthorizedClientWithoutAnnotation(OAuth2AuthorizedClient authorizedClient) {
		}

		void paramTypeClientRegistration(@OAuth2Client("client1") ClientRegistration clientRegistration) {
		}

		void paramTypeClientRegistrationWithoutAnnotation(ClientRegistration clientRegistration) {
		}

		void paramTypeUnsupported(@OAuth2Client("client1") String param) {
		}

		void paramTypeUnsupportedWithoutAnnotation(String param) {
		}

		void registrationIdEmpty(@OAuth2Client OAuth2AccessToken accessToken) {
		}

		void paramTypeAccessTokenAnnotationRegistrationId(@OAuth2Client(registrationId = "client1") OAuth2AccessToken accessToken) {
		}
	}
}
