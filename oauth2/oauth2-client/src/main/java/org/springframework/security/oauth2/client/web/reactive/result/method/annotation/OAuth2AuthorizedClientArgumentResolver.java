/*
 * Copyright 2002-2018 the original author or authors.
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

import org.springframework.core.MethodParameter;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
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

	private final OAuth2AuthorizedClientResolver authorizedClientResolver;

	/**
	 * Constructs an {@code OAuth2AuthorizedClientArgumentResolver} using the provided parameters.
	 *
	 * @param authorizedClientRepository the authorized client repository
	 */
	public OAuth2AuthorizedClientArgumentResolver(ReactiveClientRegistrationRepository clientRegistrationRepository, ServerOAuth2AuthorizedClientRepository authorizedClientRepository) {
		Assert.notNull(authorizedClientRepository, "authorizedClientRepository cannot be null");
		this.authorizedClientResolver = new OAuth2AuthorizedClientResolver(clientRegistrationRepository, authorizedClientRepository);
		this.authorizedClientResolver.setDefaultOAuth2AuthorizedClient(true);
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

			String clientRegistrationId = StringUtils.hasLength(authorizedClientAnnotation.registrationId()) ?
					authorizedClientAnnotation.registrationId() : null;

			return this.authorizedClientResolver.createDefaultedRequest(clientRegistrationId, null, exchange)
					.flatMap(this.authorizedClientResolver::loadAuthorizedClient);
		});
	}
}
