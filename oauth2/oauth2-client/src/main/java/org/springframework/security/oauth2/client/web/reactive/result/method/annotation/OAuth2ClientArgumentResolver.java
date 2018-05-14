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

import org.springframework.core.MethodParameter;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.client.ClientAuthorizationRequiredException;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.annotation.OAuth2Client;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.reactive.BindingContext;
import org.springframework.web.reactive.result.method.HandlerMethodArgumentResolver;
import org.springframework.web.server.ServerWebExchange;

import reactor.core.publisher.Mono;

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
 *     public Mono<String></String> clientRegistration(@OAuth2Client("login-client") ClientRegistration clientRegistration) {
 *         // do something with clientRegistration
 *     }
 *
 *     &#64;GetMapping("/authorized-client")
 *     public Mono<String></String> authorizedClient(@OAuth2Client("login-client") OAuth2AuthorizedClient authorizedClient) {
 *         // do something with authorizedClient
 *     }
 *
 *     &#64;GetMapping("/access-token")
 *     public Mono<String> accessToken(@OAuth2Client("login-client") OAuth2AccessToken accessToken) {
 *         // do something with accessToken
 *     }
 * }
 * </pre>
 *
 * @author Rob Winch
 * @since 5.1
 * @see OAuth2Client
 */
public final class OAuth2ClientArgumentResolver implements HandlerMethodArgumentResolver {
	private final ReactiveClientRegistrationRepository clientRegistrationRepository;
	private final ReactiveOAuth2AuthorizedClientService authorizedClientService;

	/**
	 * Constructs an {@code OAuth2ClientArgumentResolver} using the provided parameters.
	 *
	 * @param clientRegistrationRepository the repository of client registrations
	 * @param authorizedClientService the authorized client service
	 */
	public OAuth2ClientArgumentResolver(ReactiveClientRegistrationRepository clientRegistrationRepository,
			ReactiveOAuth2AuthorizedClientService authorizedClientService) {
		Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
		Assert.notNull(authorizedClientService, "authorizedClientService cannot be null");
		this.clientRegistrationRepository = clientRegistrationRepository;
		this.authorizedClientService = authorizedClientService;
	}

	@Override
	public boolean supportsParameter(MethodParameter parameter) {
		return AnnotatedElementUtils.findMergedAnnotation(parameter.getParameter(), OAuth2Client.class) != null;
	}

	@Override
	public Mono<Object> resolveArgument(
			MethodParameter parameter, BindingContext bindingContext, ServerWebExchange exchange) {
		return Mono.defer(() -> {
			OAuth2Client oauth2ClientAnnotation = AnnotatedElementUtils
					.findMergedAnnotation(parameter.getParameter(), OAuth2Client.class);

			Mono<String> clientRegistrationId = Mono.justOrEmpty(oauth2ClientAnnotation.registrationId())
					.filter(id -> !StringUtils.isEmpty(id))
					.switchIfEmpty(clientRegistrationId())
					.switchIfEmpty(Mono.defer(() -> Mono.error(new IllegalArgumentException(
							"Unable to resolve the Client Registration Identifier. It must be provided via @OAuth2Client(\"client1\") or @OAuth2Client(registrationId = \"client1\")."))));

			if (ClientRegistration.class.isAssignableFrom(parameter.getParameterType())) {
				return clientRegistrationId.flatMap(id -> this.clientRegistrationRepository.findByRegistrationId(id)
						.switchIfEmpty(Mono.defer(() -> Mono.error(new IllegalArgumentException(
								"Unable to find ClientRegistration with registration identifier \""
										+ id + "\"."))))).cast(Object.class);
			}

			Mono<String> principalName = ReactiveSecurityContextHolder.getContext()
					.map(SecurityContext::getAuthentication).map(Authentication::getName);

			Mono<OAuth2AuthorizedClient> authorizedClient = Mono
					.zip(clientRegistrationId, principalName).switchIfEmpty(
							clientRegistrationId.flatMap(id -> Mono.error(new IllegalStateException(
									"Unable to resolve the Authorized Client with registration identifier \""
											+ id
											+ "\". An \"authenticated\" or \"unauthenticated\" session is required. To allow for unauthenticated access, ensure ServerHttpSecurity.anonymous() is configured."))))
					.flatMap(zipped -> {
						String registrationId = zipped.getT1();
						String username = zipped.getT2();
						return this.authorizedClientService
								.loadAuthorizedClient(registrationId, username).switchIfEmpty(Mono.defer(() -> Mono
										.error(new ClientAuthorizationRequiredException(
												registrationId))));
					}).cast(OAuth2AuthorizedClient.class);

			if (OAuth2AccessToken.class.isAssignableFrom(parameter.getParameterType())) {
				return authorizedClient.map(OAuth2AuthorizedClient::getAccessToken);
			}

			return authorizedClient.cast(Object.class);
		});
	}

	private Mono<String> clientRegistrationId() {
		return ReactiveSecurityContextHolder.getContext()
				.map(SecurityContext::getAuthentication)
				.filter(authentication -> authentication instanceof OAuth2AuthenticationToken)
				.cast(OAuth2AuthenticationToken.class)
				.map(OAuth2AuthenticationToken::getAuthorizedClientRegistrationId);
	}
}
