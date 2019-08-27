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

package org.springframework.security.oauth2.server.resource.web.server;

import java.util.Map;
import java.util.function.Consumer;

import reactor.core.publisher.Mono;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.core.AbstractOAuth2Token;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import org.springframework.web.reactive.function.client.ExchangeFunction;

/**
 * An {@link ExchangeFilterFunction} that adds the
 * <a href="https://tools.ietf.org/html/rfc6750#section-1.2" target="_blank">Bearer Token</a>
 * from an existing {@link AbstractOAuth2Token} tied to the current {@link Authentication}.
 *
 * Suitable for Reactive applications, applying it to a typical {@link org.springframework.web.reactive.function.client.WebClient}
 * configuration:
 *
 * <pre>
 *  @Bean
 *  WebClient webClient() {
 *      ServerBearerExchangeFilterFunction bearer = new ServerBearerExchangeFilterFunction();
 *      return WebClient.builder()
 *              .filter(bearer).build();
 *  }
 * </pre>
 *
 * @author Josh Cummings
 * @since 5.2
 */
public class ServerBearerExchangeFilterFunction
		implements ExchangeFilterFunction {

	private static final String AUTHENTICATION_ATTR_NAME = Authentication.class.getName();

	private static final AnonymousAuthenticationToken ANONYMOUS_USER_TOKEN = new AnonymousAuthenticationToken("anonymous", "anonymousUser",
			AuthorityUtils.createAuthorityList("ROLE_USER"));

	/**
	 * Modifies the {@link ClientRequest#attributes()} to include the {@link Authentication} to be used for
	 * providing the Bearer Token. Example usage:
	 *
	 * <pre>
	 * WebClient webClient = WebClient.builder()
	 *    .filter(new ServerBearerExchangeFilterFunction())
	 *    .build();
	 * Mono<String> response = webClient
	 *    .get()
	 *    .uri(uri)
	 *    .attributes(authentication(authentication))
	 *    // ...
	 *    .retrieve()
	 *    .bodyToMono(String.class);
	 * </pre>
	 * @param authentication the {@link Authentication} to use
	 * @return the {@link Consumer} to populate the client request attributes
	 */
	public static Consumer<Map<String, Object>> authentication(Authentication authentication) {
		return attributes -> attributes.put(AUTHENTICATION_ATTR_NAME, authentication);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Mono<ClientResponse> filter(ClientRequest request, ExchangeFunction next) {
		return oauth2Token(request.attributes())
				.map(oauth2Token -> bearer(request, oauth2Token))
				.defaultIfEmpty(request)
				.flatMap(next::exchange);
	}

	private Mono<AbstractOAuth2Token> oauth2Token(Map<String, Object> attrs) {
		return Mono.justOrEmpty(attrs.get(AUTHENTICATION_ATTR_NAME))
				.cast(Authentication.class)
				.switchIfEmpty(currentAuthentication())
				.filter(authentication -> authentication.getCredentials() instanceof AbstractOAuth2Token)
				.map(Authentication::getCredentials)
				.cast(AbstractOAuth2Token.class);
	}

	private Mono<Authentication> currentAuthentication() {
		return ReactiveSecurityContextHolder.getContext()
				.map(SecurityContext::getAuthentication)
				.defaultIfEmpty(ANONYMOUS_USER_TOKEN);
	}

	private ClientRequest bearer(ClientRequest request, AbstractOAuth2Token token) {
		return ClientRequest.from(request)
				.headers(headers -> headers.setBearerAuth(token.getTokenValue()))
				.build();
	}
}
