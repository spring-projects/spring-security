/*
 * Copyright 2002-2020 the original author or authors.
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
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.reactive.BindingContext;
import org.springframework.web.reactive.result.method.HandlerMethodArgumentResolver;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * An implementation of a {@link HandlerMethodArgumentResolver} that is capable of
 * resolving a method parameter to an argument value of type
 * {@link OAuth2AuthorizedClient}.
 *
 * <p>
 * For example: <pre>
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
 * @author Joe Grandja
 * @since 5.1
 * @see RegisteredOAuth2AuthorizedClient
 */
public final class OAuth2AuthorizedClientArgumentResolver implements HandlerMethodArgumentResolver {

	private static final AnonymousAuthenticationToken ANONYMOUS_USER_TOKEN = new AnonymousAuthenticationToken(
			"anonymous", "anonymousUser", AuthorityUtils.createAuthorityList("ROLE_USER"));

	private ReactiveOAuth2AuthorizedClientManager authorizedClientManager;

	/**
	 * Constructs an {@code OAuth2AuthorizedClientArgumentResolver} using the provided
	 * parameters.
	 *
	 * @since 5.2
	 * @param authorizedClientManager the {@link ReactiveOAuth2AuthorizedClientManager}
	 * which manages the authorized client(s)
	 */
	public OAuth2AuthorizedClientArgumentResolver(ReactiveOAuth2AuthorizedClientManager authorizedClientManager) {
		Assert.notNull(authorizedClientManager, "authorizedClientManager cannot be null");
		this.authorizedClientManager = authorizedClientManager;
	}

	/**
	 * Constructs an {@code OAuth2AuthorizedClientArgumentResolver} using the provided
	 * parameters.
	 * @param clientRegistrationRepository the repository of client registrations
	 * @param authorizedClientRepository the repository of authorized clients
	 */
	public OAuth2AuthorizedClientArgumentResolver(ReactiveClientRegistrationRepository clientRegistrationRepository,
			ServerOAuth2AuthorizedClientRepository authorizedClientRepository) {
		Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
		Assert.notNull(authorizedClientRepository, "authorizedClientRepository cannot be null");
		this.authorizedClientManager = new DefaultReactiveOAuth2AuthorizedClientManager(clientRegistrationRepository,
				authorizedClientRepository);
	}

	@Override
	public boolean supportsParameter(MethodParameter parameter) {
		return AnnotatedElementUtils.findMergedAnnotation(parameter.getParameter(),
				RegisteredOAuth2AuthorizedClient.class) != null;
	}

	@Override
	public Mono<Object> resolveArgument(MethodParameter parameter, BindingContext bindingContext,
			ServerWebExchange exchange) {
		return Mono.defer(() -> {
			RegisteredOAuth2AuthorizedClient authorizedClientAnnotation = AnnotatedElementUtils
					.findMergedAnnotation(parameter.getParameter(), RegisteredOAuth2AuthorizedClient.class);

			String clientRegistrationId = StringUtils.hasLength(authorizedClientAnnotation.registrationId())
					? authorizedClientAnnotation.registrationId() : null;

			return authorizeRequest(clientRegistrationId, exchange).flatMap(this.authorizedClientManager::authorize);
		});
	}

	private Mono<OAuth2AuthorizeRequest> authorizeRequest(String registrationId, ServerWebExchange exchange) {
		Mono<Authentication> defaultedAuthentication = currentAuthentication();

		Mono<String> defaultedRegistrationId = Mono.justOrEmpty(registrationId)
				.switchIfEmpty(clientRegistrationId(defaultedAuthentication))
				.switchIfEmpty(Mono.error(() -> new IllegalArgumentException(
						"The clientRegistrationId could not be resolved. Please provide one")));

		Mono<ServerWebExchange> defaultedExchange = Mono.justOrEmpty(exchange)
				.switchIfEmpty(currentServerWebExchange());

		return Mono.zip(defaultedRegistrationId, defaultedAuthentication, defaultedExchange)
				.map(t3 -> OAuth2AuthorizeRequest.withClientRegistrationId(t3.getT1()).principal(t3.getT2())
						.attribute(ServerWebExchange.class.getName(), t3.getT3()).build());
	}

	private Mono<Authentication> currentAuthentication() {
		return ReactiveSecurityContextHolder.getContext().map(SecurityContext::getAuthentication)
				.defaultIfEmpty(ANONYMOUS_USER_TOKEN);
	}

	private Mono<String> clientRegistrationId(Mono<Authentication> authentication) {
		return authentication.filter(t -> t instanceof OAuth2AuthenticationToken).cast(OAuth2AuthenticationToken.class)
				.map(OAuth2AuthenticationToken::getAuthorizedClientRegistrationId);
	}

	private Mono<ServerWebExchange> currentServerWebExchange() {
		return Mono.subscriberContext().filter(c -> c.hasKey(ServerWebExchange.class))
				.map(c -> c.get(ServerWebExchange.class));
	}

}
