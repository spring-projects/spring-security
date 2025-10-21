/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.rsocket.authorization;

import reactor.core.publisher.Mono;

import org.springframework.core.Ordered;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.rsocket.api.PayloadExchange;
import org.springframework.security.rsocket.api.PayloadInterceptor;
import org.springframework.security.rsocket.api.PayloadInterceptorChain;
import org.springframework.util.Assert;

/**
 * Provides authorization of the {@link PayloadExchange}.
 *
 * @author Rob Winch
 * @since 5.2
 */
public class AuthorizationPayloadInterceptor implements PayloadInterceptor, Ordered {

	private final ReactiveAuthorizationManager<PayloadExchange> authorizationManager;

	private int order;

	public AuthorizationPayloadInterceptor(ReactiveAuthorizationManager<PayloadExchange> authorizationManager) {
		Assert.notNull(authorizationManager, "authorizationManager cannot be null");
		this.authorizationManager = authorizationManager;
	}

	@Override
	public int getOrder() {
		return this.order;
	}

	public void setOrder(int order) {
		this.order = order;
	}

	@Override
	@SuppressWarnings("NullAway") // https://github.com/uber/NullAway/issues/1290
	public Mono<Void> intercept(PayloadExchange exchange, PayloadInterceptorChain chain) {
		return ReactiveSecurityContextHolder.getContext()
			.mapNotNull(SecurityContext::getAuthentication)
			.switchIfEmpty(Mono.error(() -> new AuthenticationCredentialsNotFoundException(
					"An Authentication (possibly AnonymousAuthenticationToken) is required.")))
			.as((authentication) -> this.authorizationManager.verify(authentication, exchange))
			.then(chain.next(exchange));
	}

}
