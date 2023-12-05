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

package org.springframework.security.web.server.authorization;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import reactor.core.publisher.Mono;

import org.springframework.core.log.LogMessage;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.ReactiveAuthorizationEventPublisher;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.util.Assert;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;

/**
 * @author Rob Winch
 * @author Mathieu Ouellet
 * @since 5.0
 */
public class AuthorizationWebFilter implements WebFilter {

	private static final Log logger = LogFactory.getLog(AuthorizationWebFilter.class);

	private ReactiveAuthorizationManager<? super ServerWebExchange> authorizationManager;

	private ReactiveAuthorizationEventPublisher eventPublisher = new NoopReactiveAuthorizationEventPublisher();

	public AuthorizationWebFilter(ReactiveAuthorizationManager<? super ServerWebExchange> authorizationManager) {
		this.authorizationManager = authorizationManager;
	}

	@Override
	public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
		return ReactiveSecurityContextHolder.getContext()
			.filter((c) -> c.getAuthentication() != null)
			.map(SecurityContext::getAuthentication)
			.as((authentication) -> check(exchange, authentication))
			.doOnSuccess((it) -> logger.debug("Authorization successful"))
			.doOnError(AccessDeniedException.class,
					(ex) -> logger.debug(LogMessage.format("Authorization failed: %s", ex.getMessage())))
			.switchIfEmpty(chain.filter(exchange));
	}

	private Mono<Void> check(ServerWebExchange exchange, Mono<Authentication> authentication) {
		return this.authorizationManager.check(authentication, exchange)
			.doOnNext((decision) -> this.eventPublisher.publishAuthorizationEvent(authentication, exchange, decision))
			.filter(AuthorizationDecision::isGranted)
			.switchIfEmpty(Mono.defer(() -> Mono.error(new AccessDeniedException("Access Denied"))))
			.flatMap((decision) -> Mono.empty());
	}

	/**
	 * Sets the {@link ReactiveAuthorizationEventPublisher} to use. The default is to not
	 * publish any events.
	 * @param eventPublisher the {@link ReactiveAuthorizationEventPublisher} to use
	 * @since 6.3
	 */
	public void setAuthorizationEventPublisher(ReactiveAuthorizationEventPublisher eventPublisher) {
		Assert.notNull(eventPublisher, "eventPublisher cannot be null");
		this.eventPublisher = eventPublisher;
	}

	private static class NoopReactiveAuthorizationEventPublisher implements ReactiveAuthorizationEventPublisher {

		@Override
		public <T> void publishAuthorizationEvent(Mono<Authentication> authentication, T object,
				AuthorizationDecision decision) {

		}

	}

}
