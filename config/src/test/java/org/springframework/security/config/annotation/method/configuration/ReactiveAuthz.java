/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.config.annotation.method.configuration;

import org.reactivestreams.Publisher;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import org.springframework.security.core.Authentication;

/**
 * @author Eric Deandrea
 * @since 5.1.2
 */
public class ReactiveAuthz {
	public Mono<Boolean> check(boolean result) {
		return Mono.defer(() -> Mono.just(result));
	}

	public Mono<Boolean> check(long id) {
		return Mono.defer(() -> Mono.just(id % 2 == 0));
	}

	public Mono<Boolean> check(Authentication authentication, Flux<String> message) {
		return check(authentication, Mono.from(message));
	}

	public Mono<Boolean> check(Authentication authentication, Mono<String> message) {
		return message
				.filter(m -> m.contains(authentication.getName()))
				.map(m -> true)
				.defaultIfEmpty(false);
	}

	public Mono<Boolean> containsAuthenticationName(Mono<String> mono, String authenticationName) {
		return mono
				.map(string -> (string != null) && string.contains(authenticationName))
				.defaultIfEmpty(false);
	}

	public Mono<Boolean> containsAuthenticationName(Flux<String> flux, String authenticationName) {
		return flux
				.filter(string -> (string != null) && string.contains(authenticationName))
				.flatMap(string -> Mono.just(true))
				.defaultIfEmpty(false)
				.next();
	}

	public Mono<Boolean> containsAuthenticationName(Publisher<String> publisher, String authenticationName) {
		return containsAuthenticationName(Flux.first(publisher), authenticationName);
	}
}
