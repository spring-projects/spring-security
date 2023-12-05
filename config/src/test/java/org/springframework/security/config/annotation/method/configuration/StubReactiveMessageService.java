/*
 * Copyright 2002-2023 the original author or authors.
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

package org.springframework.security.config.annotation.method.configuration;

import org.reactivestreams.Publisher;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

public class StubReactiveMessageService implements ReactiveMessageService {

	@Override
	public String notPublisherPreAuthorizeFindById(long id) {
		return null;
	}

	@Override
	public Mono<String> monoFindById(long id) {
		return Mono.empty();
	}

	@Override
	public Mono<String> monoPreAuthorizeHasRoleFindById(long id) {
		return Mono.empty();
	}

	@Override
	public Mono<String> monoPostAuthorizeFindById(long id) {
		return Mono.just("user");
	}

	@Override
	public Mono<String> monoPreAuthorizeBeanFindById(long id) {
		return Mono.empty();
	}

	@Override
	public Mono<String> monoPreAuthorizeBeanFindByIdReactiveExpression(long id) {
		return Mono.empty();
	}

	@Override
	public Mono<String> monoPostAuthorizeBeanFindById(long id) {
		return Mono.empty();
	}

	@Override
	public Flux<String> fluxFindById(long id) {
		return Flux.empty();
	}

	@Override
	public Flux<String> fluxPreAuthorizeHasRoleFindById(long id) {
		return Flux.empty();
	}

	@Override
	public Flux<String> fluxPostAuthorizeFindById(long id) {
		return Flux.just("user");
	}

	@Override
	public Flux<String> fluxPreAuthorizeBeanFindById(long id) {
		return Flux.empty();
	}

	@Override
	public Flux<String> fluxPostAuthorizeBeanFindById(long id) {
		return Flux.empty();
	}

	@Override
	public Flux<String> fluxManyAnnotations(Flux<String> flux) {
		return Flux.empty();
	}

	@Override
	public Flux<String> fluxPostFilter(Flux<String> flux) {
		return Flux.empty();
	}

	@Override
	public Publisher<String> publisherFindById(long id) {
		return Flux.empty();
	}

	@Override
	public Publisher<String> publisherPreAuthorizeHasRoleFindById(long id) {
		return Flux.empty();
	}

	@Override
	public Publisher<String> publisherPostAuthorizeFindById(long id) {
		return Flux.empty();
	}

	@Override
	public Publisher<String> publisherPreAuthorizeBeanFindById(long id) {
		return Flux.empty();
	}

	@Override
	public Publisher<String> publisherPostAuthorizeBeanFindById(long id) {
		return Flux.empty();
	}

}
