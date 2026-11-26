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

package org.springframework.security.authorization.method;

import org.aopalliance.intercept.MethodInvocation;
import org.jspecify.annotations.Nullable;
import org.reactivestreams.Publisher;
import reactor.core.Exceptions;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * For internal use only, as this contract is likely to change.
 *
 * @author Evgeniy Cheban
 * @since 5.8
 */
final class ReactiveMethodInvocationUtils {

	static @Nullable <T> T proceed(MethodInvocation mi) {
		try {
			return (T) mi.proceed();
		}
		catch (Throwable ex) {
			throw Exceptions.propagate(ex);
		}
	}

	/**
	 * Proceeds with the {@link MethodInvocation} and adapts the result to a {@link Mono}.
	 * <p>
	 * Kotlin suspending functions are invoked by Spring AOP as {@link Mono}, but other
	 * advisors in the chain (for example, {@code @Cacheable} on a cache hit) may return a
	 * plain value. This method normalizes both cases so reactive method security can
	 * compose over the invocation result.
	 * @param mi the method invocation
	 * @return a {@link Mono} that emits the invocation result
	 */
	static Mono<Object> proceedAsMono(MethodInvocation mi) {
		return toMono(proceed(mi));
	}

	/**
	 * Proceeds with the {@link MethodInvocation} and adapts the result to a {@link Flux}.
	 * @param mi the method invocation
	 * @return a {@link Flux} that emits the invocation result(s)
	 * @see #proceedAsMono(MethodInvocation)
	 */
	static Flux<Object> proceedAsFlux(MethodInvocation mi) {
		return toFlux(proceed(mi));
	}

	@SuppressWarnings("unchecked")
	private static Mono<Object> toMono(@Nullable Object result) {
		if (result instanceof Mono<?> mono) {
			return (Mono<Object>) mono;
		}
		if (result instanceof Publisher<?> publisher) {
			return Mono.from(publisher);
		}
		return Mono.justOrEmpty(result);
	}

	@SuppressWarnings("unchecked")
	private static Flux<Object> toFlux(@Nullable Object result) {
		if (result instanceof Flux<?> flux) {
			return (Flux<Object>) flux;
		}
		if (result instanceof Publisher<?> publisher) {
			return Flux.from(publisher);
		}
		return (result != null) ? Flux.just(result) : Flux.empty();
	}

	private ReactiveMethodInvocationUtils() {
	}

}
