/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.web.server.authentication;

import java.util.List;

import reactor.core.publisher.Mono;
import reactor.util.function.Tuples;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.session.ReactiveSessionInformation;
import org.springframework.security.core.session.ReactiveSessionRegistry;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.util.Assert;
import org.springframework.web.server.WebSession;

/**
 * Controls the number of sessions a user can have concurrently authenticated in an
 * application. It also allows for customizing behaviour when an authentication attempt is
 * made while the user already has the maximum number of sessions open. By default, it
 * allows a maximum of 1 session per user, if the maximum is exceeded, the user's least
 * recently used session(s) will be expired.
 *
 * @author Marcus da Coregio
 * @since 6.3
 * @see ServerMaximumSessionsExceededHandler
 * @see RegisterSessionServerAuthenticationSuccessHandler
 */
public final class ConcurrentSessionControlServerAuthenticationSuccessHandler
		implements ServerAuthenticationSuccessHandler {

	private final ReactiveSessionRegistry sessionRegistry;

	private final ServerMaximumSessionsExceededHandler maximumSessionsExceededHandler;

	private SessionLimit sessionLimit = SessionLimit.of(1);

	public ConcurrentSessionControlServerAuthenticationSuccessHandler(ReactiveSessionRegistry sessionRegistry,
			ServerMaximumSessionsExceededHandler maximumSessionsExceededHandler) {
		Assert.notNull(sessionRegistry, "sessionRegistry cannot be null");
		Assert.notNull(maximumSessionsExceededHandler, "maximumSessionsExceededHandler cannot be null");
		this.sessionRegistry = sessionRegistry;
		this.maximumSessionsExceededHandler = maximumSessionsExceededHandler;
	}

	@Override
	public Mono<Void> onAuthenticationSuccess(WebFilterExchange exchange, Authentication authentication) {
		return this.sessionLimit.apply(authentication)
			.flatMap((maxSessions) -> handleConcurrency(exchange, authentication, maxSessions));
	}

	private Mono<Void> handleConcurrency(WebFilterExchange exchange, Authentication authentication,
			Integer maximumSessions) {
		return this.sessionRegistry.getAllSessions(authentication.getPrincipal())
			.collectList()
			.flatMap((registeredSessions) -> exchange.getExchange()
				.getSession()
				.map((currentSession) -> Tuples.of(currentSession, registeredSessions)))
			.flatMap((sessionTuple) -> {
				WebSession currentSession = sessionTuple.getT1();
				List<ReactiveSessionInformation> registeredSessions = sessionTuple.getT2();
				int registeredSessionsCount = registeredSessions.size();
				if (registeredSessionsCount < maximumSessions) {
					return Mono.empty();
				}
				if (registeredSessionsCount == maximumSessions) {
					for (ReactiveSessionInformation registeredSession : registeredSessions) {
						if (registeredSession.getSessionId().equals(currentSession.getId())) {
							return Mono.empty();
						}
					}
				}
				return this.maximumSessionsExceededHandler.handle(new MaximumSessionsContext(authentication,
						registeredSessions, maximumSessions, currentSession));
			});
	}

	/**
	 * Sets the strategy used to resolve the maximum number of sessions that are allowed
	 * for a specific {@link Authentication}. By default, it returns {@code 1} for any
	 * authentication.
	 * @param sessionLimit the {@link SessionLimit} to use
	 */
	public void setSessionLimit(SessionLimit sessionLimit) {
		Assert.notNull(sessionLimit, "sessionLimit cannot be null");
		this.sessionLimit = sessionLimit;
	}

}
