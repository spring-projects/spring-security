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

package org.springframework.security.rsocket.core;

import java.util.List;
import java.util.ListIterator;

import org.jspecify.annotations.Nullable;
import reactor.core.publisher.Mono;
import reactor.util.context.Context;

import org.springframework.security.rsocket.api.PayloadExchange;
import org.springframework.security.rsocket.api.PayloadInterceptor;
import org.springframework.security.rsocket.api.PayloadInterceptorChain;

/**
 * A {@link PayloadInterceptorChain} which exposes the Reactor {@link Context} via a
 * member variable. This class is not Thread safe, so a new instance must be created for
 * each Thread.
 *
 * Internally {@code ContextPayloadInterceptorChain} is used to ensure that the Reactor
 * {@code Context} is captured so it can be transferred to subscribers outside of this
 * {@code Context} in {@code PayloadSocketAcceptor}.
 *
 * @author Rob Winch
 * @since 5.2
 * @see PayloadSocketAcceptor
 */
class ContextPayloadInterceptorChain implements PayloadInterceptorChain {

	private final @Nullable PayloadInterceptor currentInterceptor;

	private final @Nullable ContextPayloadInterceptorChain next;

	private @Nullable Context context;

	ContextPayloadInterceptorChain(List<PayloadInterceptor> interceptors) {
		if (interceptors == null) {
			throw new IllegalArgumentException("interceptors cannot be null");
		}
		if (interceptors.isEmpty()) {
			throw new IllegalArgumentException("interceptors cannot be empty");
		}
		ContextPayloadInterceptorChain interceptor = init(interceptors);
		this.currentInterceptor = interceptor.currentInterceptor;
		this.next = interceptor.next;
	}

	private static ContextPayloadInterceptorChain init(List<PayloadInterceptor> interceptors) {
		ContextPayloadInterceptorChain interceptor = new ContextPayloadInterceptorChain(null, null);
		ListIterator<? extends PayloadInterceptor> iterator = interceptors.listIterator(interceptors.size());
		while (iterator.hasPrevious()) {
			interceptor = new ContextPayloadInterceptorChain(iterator.previous(), interceptor);
		}
		return interceptor;
	}

	private ContextPayloadInterceptorChain(@Nullable PayloadInterceptor currentInterceptor,
			@Nullable ContextPayloadInterceptorChain next) {
		this.currentInterceptor = currentInterceptor;
		this.next = next;
	}

	@Override
	@SuppressWarnings("NullAway") // Dataflow analysis limitation
	public Mono<Void> next(PayloadExchange exchange) {
		return Mono.defer(() -> shouldIntercept() ? this.currentInterceptor.intercept(exchange, this.next)
				: Mono.deferContextual(Mono::just).cast(Context.class).doOnNext((c) -> this.context = c).then());
	}

	@Nullable Context getContext() {
		if (this.next == null) {
			return this.context;
		}
		return this.next.getContext();
	}

	private boolean shouldIntercept() {
		return this.currentInterceptor != null && this.next != null;
	}

	@Override
	public String toString() {
		return getClass().getSimpleName() + "[currentInterceptor=" + this.currentInterceptor + "]";
	}

}
