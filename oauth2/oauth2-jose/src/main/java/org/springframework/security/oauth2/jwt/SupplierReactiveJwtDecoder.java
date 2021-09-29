/*
 * Copyright 2002-2021 the original author or authors.
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

package org.springframework.security.oauth2.jwt;

import java.time.Duration;
import java.util.function.Supplier;

import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

/**
 * A {@link ReactiveJwtDecoder} that lazily initializes another {@link ReactiveJwtDecoder}
 *
 * @author Josh Cummings
 * @since 5.6
 */
public final class SupplierReactiveJwtDecoder implements ReactiveJwtDecoder {

	private static final Duration FOREVER = Duration.ofMillis(Long.MAX_VALUE);

	private Mono<ReactiveJwtDecoder> jwtDecoderMono;

	public SupplierReactiveJwtDecoder(Supplier<ReactiveJwtDecoder> supplier) {
		// @formatter:off
		this.jwtDecoderMono = Mono.fromSupplier(supplier)
				.subscribeOn(Schedulers.boundedElastic())
				.publishOn(Schedulers.parallel())
				.onErrorMap(this::wrapException)
				.cache((delegate) -> FOREVER, (ex) -> Duration.ZERO, () -> Duration.ZERO);
		// @formatter:on
	}

	private JwtDecoderInitializationException wrapException(Throwable t) {
		return new JwtDecoderInitializationException("Failed to lazily resolve the supplied JwtDecoder instance", t);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Mono<Jwt> decode(String token) throws JwtException {
		return this.jwtDecoderMono.flatMap((decoder) -> decoder.decode(token));
	}

}
