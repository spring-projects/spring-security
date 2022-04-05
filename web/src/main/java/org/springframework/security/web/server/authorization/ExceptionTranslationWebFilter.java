/*
 * Copyright 2002-2022 the original author or authors.
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

package org.springframework.security.web.server.authorization;

import reactor.core.publisher.Mono;

import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.security.web.server.authentication.HttpBasicServerAuthenticationEntryPoint;
import org.springframework.util.Assert;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;

/**
 * @author Rob Winch
 * @author César Revert
 * @since 5.0
 */
public class ExceptionTranslationWebFilter implements WebFilter {

	private ServerAuthenticationEntryPoint authenticationEntryPoint = new HttpBasicServerAuthenticationEntryPoint();

	private ServerAccessDeniedHandler accessDeniedHandler = new HttpStatusServerAccessDeniedHandler(
			HttpStatus.FORBIDDEN);

	private AuthenticationTrustResolver authenticationTrustResolver = new AuthenticationTrustResolverImpl();

	@Override
	public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
		return chain.filter(exchange).onErrorResume(AccessDeniedException.class, (denied) -> exchange.getPrincipal()
				.filter((principal) -> (!(principal instanceof Authentication) || (principal instanceof Authentication
						&& !(this.authenticationTrustResolver.isAnonymous((Authentication) principal)))))
				.switchIfEmpty(commenceAuthentication(exchange,
						new InsufficientAuthenticationException(
								"Full authentication is required to access this resource")))
				.flatMap((principal) -> this.accessDeniedHandler.handle(exchange, denied)).then());
	}

	/**
	 * Sets the access denied handler.
	 * @param accessDeniedHandler the access denied handler to use. Default is
	 * HttpStatusAccessDeniedHandler with HttpStatus.FORBIDDEN
	 */
	public void setAccessDeniedHandler(ServerAccessDeniedHandler accessDeniedHandler) {
		Assert.notNull(accessDeniedHandler, "accessDeniedHandler cannot be null");
		this.accessDeniedHandler = accessDeniedHandler;
	}

	/**
	 * Sets the authentication entry point used when authentication is required
	 * @param authenticationEntryPoint the authentication entry point to use. Default is
	 * {@link HttpBasicServerAuthenticationEntryPoint}
	 */
	public void setAuthenticationEntryPoint(ServerAuthenticationEntryPoint authenticationEntryPoint) {
		Assert.notNull(authenticationEntryPoint, "authenticationEntryPoint cannot be null");
		this.authenticationEntryPoint = authenticationEntryPoint;
	}

	/**
	 * Sets the authentication trust resolver.
	 * @param authenticationTrustResolver the authentication trust resolver to use.
	 * Default is {@link AuthenticationTrustResolverImpl}
	 *
	 * @since 5.5
	 */
	public void setAuthenticationTrustResolver(AuthenticationTrustResolver authenticationTrustResolver) {
		Assert.notNull(authenticationTrustResolver, "authenticationTrustResolver must not be null");
		this.authenticationTrustResolver = authenticationTrustResolver;
	}

	private <T> Mono<T> commenceAuthentication(ServerWebExchange exchange, AuthenticationException denied) {
		return this.authenticationEntryPoint
				.commence(exchange, new AuthenticationCredentialsNotFoundException("Not Authenticated", denied))
				.then(Mono.empty());
	}

}
