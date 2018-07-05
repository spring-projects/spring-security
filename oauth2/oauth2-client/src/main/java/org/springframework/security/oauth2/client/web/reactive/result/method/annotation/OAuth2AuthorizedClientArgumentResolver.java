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
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.reactive.BindingContext;
import org.springframework.web.reactive.result.method.HandlerMethodArgumentResolver;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

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
 *     public Mono&lt;String&gt; authorizedClient(@RegisteredOAuth2AuthorizedClient("login-client") OAuth2AuthorizedClient authorizedClient) {
 *         // do something with authorizedClient
 *     }
 * }
 * </pre>
 *
 * @author Rob Winch
 * @since 5.1
 * @see RegisteredOAuth2AuthorizedClient
 */
public final class OAuth2AuthorizedClientArgumentResolver implements HandlerMethodArgumentResolver {
	private final ReactiveOAuth2AuthorizedClientService authorizedClientService;

	/**
	 * Constructs an {@code OAuth2AuthorizedClientArgumentResolver} using the provided parameters.
	 *
	 * @param authorizedClientService the authorized client service
	 */
	public OAuth2AuthorizedClientArgumentResolver(ReactiveOAuth2AuthorizedClientService authorizedClientService) {
		Assert.notNull(authorizedClientService, "authorizedClientService cannot be null");
		this.authorizedClientService = authorizedClientService;
	}

	@Override
	public boolean supportsParameter(MethodParameter parameter) {
		return AnnotatedElementUtils.findMergedAnnotation(parameter.getParameter(), RegisteredOAuth2AuthorizedClient.class) != null;
	}

	@Override
	public Mono<Object> resolveArgument(
			MethodParameter parameter, BindingContext bindingContext, ServerWebExchange exchange) {
		return Mono.defer(() -> {
			RegisteredOAuth2AuthorizedClient authorizedClientAnnotation = AnnotatedElementUtils
					.findMergedAnnotation(parameter.getParameter(), RegisteredOAuth2AuthorizedClient.class);

			Mono<String> clientRegistrationId = Mono.justOrEmpty(authorizedClientAnnotation.registrationId())
					.filter(id -> !StringUtils.isEmpty(id))
					.switchIfEmpty(clientRegistrationId())
					.switchIfEmpty(Mono.defer(() -> Mono.error(new IllegalArgumentException(
							"Unable to resolve the Client Registration Identifier. It must be provided via @RegisteredOAuth2AuthorizedClient(\"client1\") or @RegisteredOAuth2AuthorizedClient(registrationId = \"client1\")."))));

			Mono<String> principalName = ReactiveSecurityContextHolder.getContext()
					.map(SecurityContext::getAuthentication).map(Authentication::getName);

			Mono<OAuth2AuthorizedClient> authorizedClient = Mono
					.zip(clientRegistrationId, principalName).switchIfEmpty(
							clientRegistrationId.flatMap(id -> Mono.error(new IllegalStateException(
									"Unable to resolve the Authorized Client with registration identifier \""
											+ id
											+ "\". An \"authenticated\" or \"anonymous\" request is required. To allow for anonymous access, ensure ServerHttpSecurity.anonymous() is configured."))))
					.flatMap(zipped -> {
						String registrationId = zipped.getT1();
						String username = zipped.getT2();
						return this.authorizedClientService
								.loadAuthorizedClient(registrationId, username).switchIfEmpty(Mono.defer(() -> Mono
										.error(new ClientAuthorizationRequiredException(
												registrationId))));
					}).cast(OAuth2AuthorizedClient.class);

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
