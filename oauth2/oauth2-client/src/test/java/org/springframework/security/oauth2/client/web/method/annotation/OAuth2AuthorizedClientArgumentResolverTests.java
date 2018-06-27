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

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.core.MethodParameter;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.ClientAuthorizationRequiredException;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.util.ReflectionUtils;
import org.springframework.web.context.request.ServletWebRequest;

import javax.servlet.http.HttpServletRequest;
import java.lang.reflect.Method;

import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;
import static org.assertj.core.api.AssertionsForInterfaceTypes.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link OAuth2AuthorizedClientArgumentResolver}.
 *
 * @author Joe Grandja
 */
public class OAuth2AuthorizedClientArgumentResolverTests {
	private OAuth2AuthorizedClientRepository authorizedClientRepository;
	private OAuth2AuthorizedClientArgumentResolver argumentResolver;
	private OAuth2AuthorizedClient authorizedClient;
	private MockHttpServletRequest request;

	@Before
	public void setup() {
		this.authorizedClientRepository = mock(OAuth2AuthorizedClientRepository.class);
		this.argumentResolver = new OAuth2AuthorizedClientArgumentResolver(this.authorizedClientRepository);
		this.authorizedClient = mock(OAuth2AuthorizedClient.class);
		this.request = new MockHttpServletRequest();
		when(this.authorizedClientRepository.loadAuthorizedClient(anyString(), any(), any(HttpServletRequest.class)))
				.thenReturn(this.authorizedClient);
		SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
		securityContext.setAuthentication(mock(Authentication.class));
		SecurityContextHolder.setContext(securityContext);
	}

	@After
	public void cleanup() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void constructorWhenOAuth2AuthorizedClientServiceIsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OAuth2AuthorizedClientArgumentResolver(null))
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
		MethodParameter methodParameter = this.getMethodParameter("registrationIdEmpty", OAuth2AuthorizedClient.class);
		assertThatThrownBy(() -> this.argumentResolver.resolveArgument(methodParameter, null, null, null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("Unable to resolve the Client Registration Identifier. It must be provided via @RegisteredOAuth2AuthorizedClient(\"client1\") or @RegisteredOAuth2AuthorizedClient(registrationId = \"client1\").");
	}

	@Test
	public void resolveArgumentWhenRegistrationIdEmptyAndOAuth2AuthenticationThenResolves() throws Exception {
		OAuth2AuthenticationToken authentication = mock(OAuth2AuthenticationToken.class);
		when(authentication.getAuthorizedClientRegistrationId()).thenReturn("client1");
		SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
		securityContext.setAuthentication(authentication);
		SecurityContextHolder.setContext(securityContext);
		MethodParameter methodParameter = this.getMethodParameter("registrationIdEmpty", OAuth2AuthorizedClient.class);
		this.argumentResolver.resolveArgument(methodParameter, null, new ServletWebRequest(this.request), null);
	}

	@Test
	public void resolveArgumentWhenOAuth2AuthorizedClientFoundThenResolves() throws Exception {
		MethodParameter methodParameter = this.getMethodParameter("paramTypeAuthorizedClient", OAuth2AuthorizedClient.class);
		assertThat(this.argumentResolver.resolveArgument(
				methodParameter, null, new ServletWebRequest(this.request), null)).isSameAs(this.authorizedClient);
	}

	@Test
	public void resolveArgumentWhenOAuth2AuthorizedClientNotFoundThenThrowClientAuthorizationRequiredException() throws Exception {
		when(this.authorizedClientRepository.loadAuthorizedClient(anyString(), any(), any(HttpServletRequest.class)))
				.thenReturn(null);
		MethodParameter methodParameter = this.getMethodParameter("paramTypeAuthorizedClient", OAuth2AuthorizedClient.class);
		assertThatThrownBy(() -> this.argumentResolver.resolveArgument(methodParameter, null, new ServletWebRequest(this.request), null))
				.isInstanceOf(ClientAuthorizationRequiredException.class);
	}

	private MethodParameter getMethodParameter(String methodName, Class<?>... paramTypes) {
		Method method = ReflectionUtils.findMethod(TestController.class, methodName, paramTypes);
		return new MethodParameter(method, 0);
	}

	static class TestController {
		void paramTypeAuthorizedClient(@RegisteredOAuth2AuthorizedClient("client1") OAuth2AuthorizedClient authorizedClient) {
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
