/*
 * Copyright 2019 the original author or authors.
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

package org.springframework.security.rsocket.authentication;

import org.springframework.core.Ordered;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.rsocket.api.PayloadExchange;
import org.springframework.security.rsocket.api.PayloadInterceptor;
import org.springframework.security.rsocket.api.PayloadInterceptorChain;
import org.springframework.util.Assert;
import reactor.core.publisher.Mono;

/**
 * Uses the provided {@code ReactiveAuthenticationManager} to authenticate a Payload. If
 * authentication is successful, then the result is added to
 * {@link ReactiveSecurityContextHolder}.
 *
 * @author Rob Winch
 * @since 5.2
 */
public class AuthenticationPayloadInterceptor implements PayloadInterceptor, Ordered {

	private final ReactiveAuthenticationManager authenticationManager;

	private int order;

	private PayloadExchangeAuthenticationConverter authenticationConverter = new BasicAuthenticationPayloadExchangeConverter();

	/**
	 * Creates a new instance
	 * @param authenticationManager the manager to use. Cannot be null
	 */
	public AuthenticationPayloadInterceptor(ReactiveAuthenticationManager authenticationManager) {
		Assert.notNull(authenticationManager, "authenticationManager cannot be null");
		this.authenticationManager = authenticationManager;
	}

	@Override
	public int getOrder() {
		return this.order;
	}

	public void setOrder(int order) {
		this.order = order;
	}

	/**
	 * Sets the convert to be used
	 * @param authenticationConverter
	 */
	public void setAuthenticationConverter(PayloadExchangeAuthenticationConverter authenticationConverter) {
		Assert.notNull(authenticationConverter, "authenticationConverter cannot be null");
		this.authenticationConverter = authenticationConverter;
	}

	public Mono<Void> intercept(PayloadExchange exchange, PayloadInterceptorChain chain) {
		return this.authenticationConverter.convert(exchange).switchIfEmpty(chain.next(exchange).then(Mono.empty()))
				.flatMap(a -> this.authenticationManager.authenticate(a))
				.flatMap(a -> onAuthenticationSuccess(chain.next(exchange), a));
	}

	private Mono<Void> onAuthenticationSuccess(Mono<Void> payload, Authentication authentication) {
		return payload.subscriberContext(ReactiveSecurityContextHolder.withAuthentication(authentication));
	}

}
