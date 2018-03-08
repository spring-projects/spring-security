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

import org.springframework.core.MethodParameter;
import org.springframework.lang.NonNull;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.ClientAuthorizationRequiredException;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.annotation.OAuth2Client;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;

/**
 * An implementation of a {@link HandlerMethodArgumentResolver} that is capable
 * of resolving a method parameter into an argument value for the following types:
 * {@link ClientRegistration}, {@link OAuth2AuthorizedClient} and {@link OAuth2AccessToken}.
 *
 * <p>
 * For example:
 * <pre>
 * &#64;Controller
 * public class MyController {
 *     &#64;GetMapping("/client-registration")
 *     public String clientRegistration(@OAuth2Client("login-client") ClientRegistration clientRegistration) {
 *         // do something with clientRegistration
 *     }
 *
 *     &#64;GetMapping("/authorized-client")
 *     public String authorizedClient(@OAuth2Client("login-client") OAuth2AuthorizedClient authorizedClient) {
 *         // do something with authorizedClient
 *     }
 *
 *     &#64;GetMapping("/access-token")
 *     public String accessToken(@OAuth2Client("login-client") OAuth2AccessToken accessToken) {
 *         // do something with accessToken
 *     }
 * }
 * </pre>
 *
 * @author Joe Grandja
 * @since 5.1
 * @see OAuth2Client
 */
public final class OAuth2ClientArgumentResolver implements HandlerMethodArgumentResolver {
	private final ClientRegistrationRepository clientRegistrationRepository;
	private final OAuth2AuthorizedClientService authorizedClientService;

	/**
	 * Constructs an {@code OAuth2ClientArgumentResolver} using the provided parameters.
	 *
	 * @param clientRegistrationRepository the repository of client registrations
	 * @param authorizedClientService the authorized client service
	 */
	public OAuth2ClientArgumentResolver(ClientRegistrationRepository clientRegistrationRepository,
										OAuth2AuthorizedClientService authorizedClientService) {
		Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
		Assert.notNull(authorizedClientService, "authorizedClientService cannot be null");
		this.clientRegistrationRepository = clientRegistrationRepository;
		this.authorizedClientService = authorizedClientService;
	}

	@Override
	public boolean supportsParameter(MethodParameter parameter) {
		Class<?> parameterType = parameter.getParameterType();
		return ((OAuth2AccessToken.class.isAssignableFrom(parameterType) ||
				OAuth2AuthorizedClient.class.isAssignableFrom(parameterType) ||
				ClientRegistration.class.isAssignableFrom(parameterType)) &&
				(parameter.hasParameterAnnotation(OAuth2Client.class)));
	}

	@NonNull
	@Override
	public Object resolveArgument(MethodParameter parameter,
									@Nullable ModelAndViewContainer mavContainer,
									NativeWebRequest webRequest,
									@Nullable WebDataBinderFactory binderFactory) throws Exception {

		OAuth2Client oauth2ClientAnnotation = parameter.getParameterAnnotation(OAuth2Client.class);
		Authentication principal = SecurityContextHolder.getContext().getAuthentication();

		String clientRegistrationId = null;
		if (!StringUtils.isEmpty(oauth2ClientAnnotation.registrationId())) {
			clientRegistrationId = oauth2ClientAnnotation.registrationId();
		} else if (!StringUtils.isEmpty(oauth2ClientAnnotation.value())) {
			clientRegistrationId = oauth2ClientAnnotation.value();
		} else if (principal != null && OAuth2AuthenticationToken.class.isAssignableFrom(principal.getClass())) {
			clientRegistrationId = ((OAuth2AuthenticationToken) principal).getAuthorizedClientRegistrationId();
		}
		if (StringUtils.isEmpty(clientRegistrationId)) {
			throw new IllegalArgumentException("Unable to resolve the Client Registration Identifier. " +
					"It must be provided via @OAuth2Client(\"client1\") or @OAuth2Client(registrationId = \"client1\").");
		}

		if (ClientRegistration.class.isAssignableFrom(parameter.getParameterType())) {
			ClientRegistration clientRegistration = this.clientRegistrationRepository.findByRegistrationId(clientRegistrationId);
			if (clientRegistration == null) {
				throw new IllegalArgumentException("Unable to find ClientRegistration with registration identifier \"" +
						clientRegistrationId + "\".");
			}
			return clientRegistration;
		}

		if (principal == null) {
			// An Authentication is required given that an OAuth2AuthorizedClient is associated to a Principal
			throw new IllegalStateException("Unable to resolve the Authorized Client with registration identifier \"" +
					clientRegistrationId + "\". An \"authenticated\" or \"unauthenticated\" session is required. " +
					"To allow for unauthenticated access, ensure HttpSecurity.anonymous() is configured.");
		}

		OAuth2AuthorizedClient authorizedClient = this.authorizedClientService.loadAuthorizedClient(
			clientRegistrationId, principal.getName());
		if (authorizedClient == null) {
			throw new ClientAuthorizationRequiredException(clientRegistrationId);
		}

		return OAuth2AccessToken.class.isAssignableFrom(parameter.getParameterType()) ?
			authorizedClient.getAccessToken() : authorizedClient;
	}
}
