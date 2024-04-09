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
import java.util.function.Function;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;
import org.springframework.web.server.ServerWebExchange;

/**
 * A {@link ServerAuthenticationConverter} that delegates to other
 * {@link ServerAuthenticationConverter} instances.
 *
 * @author DingHao
 * @since 6.3
 */
public final class DelegatingServerAuthenticationConverter implements ServerAuthenticationConverter {

	private final List<ServerAuthenticationConverter> delegates;

	private boolean continueOnError = false;

	private final Log logger = LogFactory.getLog(getClass());

	public DelegatingServerAuthenticationConverter(ServerAuthenticationConverter... converters) {
		this(List.of(converters));
	}

	public DelegatingServerAuthenticationConverter(List<ServerAuthenticationConverter> converters) {
		Assert.notEmpty(converters, "converters cannot be null");
		this.delegates = converters;
	}

	@Override
	public Mono<Authentication> convert(ServerWebExchange exchange) {
		Flux<ServerAuthenticationConverter> result = Flux.fromIterable(this.delegates);
		Function<ServerAuthenticationConverter, Mono<Authentication>> logging = (
				converter) -> converter.convert(exchange).doOnError(this.logger::debug);
		return ((this.continueOnError) ? result.concatMapDelayError(logging) : result.concatMap(logging)).next();
	}

	/**
	 * Continue iterating when a delegate errors, defaults to {@code false}
	 * @param continueOnError whether to continue when a delegate errors
	 * @since 6.3
	 */
	public void setContinueOnError(boolean continueOnError) {
		this.continueOnError = continueOnError;
	}

}
