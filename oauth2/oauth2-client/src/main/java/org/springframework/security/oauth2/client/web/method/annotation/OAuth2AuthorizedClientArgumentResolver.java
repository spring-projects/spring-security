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
package org.springframework.security.oauth2.client.web.method.annotation;

import org.springframework.core.MethodParameter;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.lang.NonNull;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.ClientCredentialsOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2ClientCredentialsGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * An implementation of a {@link HandlerMethodArgumentResolver} that is capable
 * of resolving a method parameter to an argument value of type {@link OAuth2AuthorizedClient}.
 *
 * <p>
 * For example:
 * <pre>
 * &#64;Controller
 * public class MyController {
 *     &#64;GetMapping("/authorized-client")
 *     public String authorizedClient(@RegisteredOAuth2AuthorizedClient("login-client") OAuth2AuthorizedClient authorizedClient) {
 *         // do something with authorizedClient
 *     }
 * }
 * </pre>
 *
 * @author Joe Grandja
 * @since 5.1
 * @see RegisteredOAuth2AuthorizedClient
 */
public final class OAuth2AuthorizedClientArgumentResolver implements HandlerMethodArgumentResolver {
	private static final Authentication ANONYMOUS_AUTHENTICATION = new AnonymousAuthenticationToken(
			"anonymous", "anonymousUser", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));
	private OAuth2AuthorizedClientManager authorizedClientManager;
	private boolean defaultAuthorizedClientManager;

	/**
	 * Constructs an {@code OAuth2AuthorizedClientArgumentResolver} using the provided parameters.
	 *
	 * @since 5.2
	 * @param authorizedClientManager the {@link OAuth2AuthorizedClientManager} which manages the authorized client(s)
	 */
	public OAuth2AuthorizedClientArgumentResolver(OAuth2AuthorizedClientManager authorizedClientManager) {
		Assert.notNull(authorizedClientManager, "authorizedClientManager cannot be null");
		this.authorizedClientManager = authorizedClientManager;
	}

	/**
	 * Constructs an {@code OAuth2AuthorizedClientArgumentResolver} using the provided parameters.
	 *
	 * @param clientRegistrationRepository the repository of client registrations
	 * @param authorizedClientRepository the repository of authorized clients
	 */
	public OAuth2AuthorizedClientArgumentResolver(ClientRegistrationRepository clientRegistrationRepository,
													OAuth2AuthorizedClientRepository authorizedClientRepository) {
		Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
		Assert.notNull(authorizedClientRepository, "authorizedClientRepository cannot be null");
		this.authorizedClientManager = new DefaultOAuth2AuthorizedClientManager(
				clientRegistrationRepository, authorizedClientRepository);
		this.defaultAuthorizedClientManager = true;
	}

	@Override
	public boolean supportsParameter(MethodParameter parameter) {
		Class<?> parameterType = parameter.getParameterType();
		return (OAuth2AuthorizedClient.class.isAssignableFrom(parameterType) &&
				(AnnotatedElementUtils.findMergedAnnotation(
						parameter.getParameter(), RegisteredOAuth2AuthorizedClient.class) != null));
	}

	@NonNull
	@Override
	public Object resolveArgument(MethodParameter parameter,
									@Nullable ModelAndViewContainer mavContainer,
									NativeWebRequest webRequest,
									@Nullable WebDataBinderFactory binderFactory) {

		String clientRegistrationId = this.resolveClientRegistrationId(parameter);
		if (StringUtils.isEmpty(clientRegistrationId)) {
			throw new IllegalArgumentException("Unable to resolve the Client Registration Identifier. " +
					"It must be provided via @RegisteredOAuth2AuthorizedClient(\"client1\") or " +
					"@RegisteredOAuth2AuthorizedClient(registrationId = \"client1\").");
		}

		Authentication principal = SecurityContextHolder.getContext().getAuthentication();
		if (principal == null) {
			principal = ANONYMOUS_AUTHENTICATION;
		}
		HttpServletRequest servletRequest = webRequest.getNativeRequest(HttpServletRequest.class);
		HttpServletResponse servletResponse = webRequest.getNativeResponse(HttpServletResponse.class);

		OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest.withClientRegistrationId(clientRegistrationId)
				.principal(principal)
				.attribute(HttpServletRequest.class.getName(), servletRequest)
				.attribute(HttpServletResponse.class.getName(), servletResponse)
				.build();

		return this.authorizedClientManager.authorize(authorizeRequest);
	}

	private String resolveClientRegistrationId(MethodParameter parameter) {
		RegisteredOAuth2AuthorizedClient authorizedClientAnnotation = AnnotatedElementUtils.findMergedAnnotation(
				parameter.getParameter(), RegisteredOAuth2AuthorizedClient.class);

		Authentication principal = SecurityContextHolder.getContext().getAuthentication();

		String clientRegistrationId = null;
		if (!StringUtils.isEmpty(authorizedClientAnnotation.registrationId())) {
			clientRegistrationId = authorizedClientAnnotation.registrationId();
		} else if (!StringUtils.isEmpty(authorizedClientAnnotation.value())) {
			clientRegistrationId = authorizedClientAnnotation.value();
		} else if (principal != null && OAuth2AuthenticationToken.class.isAssignableFrom(principal.getClass())) {
			clientRegistrationId = ((OAuth2AuthenticationToken) principal).getAuthorizedClientRegistrationId();
		}

		return clientRegistrationId;
	}

	/**
	 * Sets the client used when requesting an access token credential at the Token Endpoint for the {@code client_credentials} grant.
	 *
	 * @deprecated Use {@link #OAuth2AuthorizedClientArgumentResolver(OAuth2AuthorizedClientManager)} instead.
	 * 				Create an instance of {@link ClientCredentialsOAuth2AuthorizedClientProvider} configured with a
	 * 				{@link ClientCredentialsOAuth2AuthorizedClientProvider#setAccessTokenResponseClient(OAuth2AccessTokenResponseClient) DefaultClientCredentialsTokenResponseClient}
	 * 				(or a custom one) and than supply it to {@link DefaultOAuth2AuthorizedClientManager#setAuthorizedClientProvider(OAuth2AuthorizedClientProvider) DefaultOAuth2AuthorizedClientManager}.
	 *
	 * @param clientCredentialsTokenResponseClient the client used when requesting an access token credential at the Token Endpoint for the {@code client_credentials} grant
	 */
	@Deprecated
	public void setClientCredentialsTokenResponseClient(
			OAuth2AccessTokenResponseClient<OAuth2ClientCredentialsGrantRequest> clientCredentialsTokenResponseClient) {
		Assert.notNull(clientCredentialsTokenResponseClient, "clientCredentialsTokenResponseClient cannot be null");
		Assert.state(this.defaultAuthorizedClientManager, "The client cannot be set when the constructor used is \"OAuth2AuthorizedClientArgumentResolver(OAuth2AuthorizedClientManager)\". " +
				"Instead, use the constructor \"OAuth2AuthorizedClientArgumentResolver(ClientRegistrationRepository, OAuth2AuthorizedClientRepository)\".");
		updateDefaultAuthorizedClientManager(clientCredentialsTokenResponseClient);
	}

	private void updateDefaultAuthorizedClientManager(
			OAuth2AccessTokenResponseClient<OAuth2ClientCredentialsGrantRequest> clientCredentialsTokenResponseClient) {

		OAuth2AuthorizedClientProvider authorizedClientProvider =
				OAuth2AuthorizedClientProviderBuilder.builder()
						.authorizationCode()
						.refreshToken()
						.clientCredentials(configurer -> configurer.accessTokenResponseClient(clientCredentialsTokenResponseClient))
						.password()
						.build();
		((DefaultOAuth2AuthorizedClientManager) this.authorizedClientManager).setAuthorizedClientProvider(authorizedClientProvider);
	}
}
