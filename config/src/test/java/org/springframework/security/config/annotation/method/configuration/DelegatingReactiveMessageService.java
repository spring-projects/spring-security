/*
 * Copyright 2002-2017 the original author or authors.
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
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

public class DelegatingReactiveMessageService implements ReactiveMessageService {
	private final ReactiveMessageService delegate;

	public DelegatingReactiveMessageService(ReactiveMessageService delegate) {
		this.delegate = delegate;
	}

	@Override
	@PreAuthorize("denyAll")
	public String notPublisherPreAuthorizeFindById(long id) {
		return this.delegate.notPublisherPreAuthorizeFindById(id);
	}

	@Override
	public Mono<String> monoFindById(long id) {
		return delegate.monoFindById(id);
	}

	@Override
	@PreAuthorize("hasRole('ADMIN')")
	public Mono<String> monoPreAuthorizeHasRoleFindById(
			long id) {
		return delegate.monoPreAuthorizeHasRoleFindById(id);
	}

	@Override
	@PostAuthorize("returnObject?.contains(authentication?.name)")
	public Mono<String> monoPostAuthorizeFindById(
			long id) {
		return delegate.monoPostAuthorizeFindById(id);
	}

	@Override
	@PreAuthorize("@authz.check(#id)")
	public Mono<String> monoPreAuthorizeBeanFindById(
			long id) {
		return delegate.monoPreAuthorizeBeanFindById(id);
	}

	@Override
	@PreAuthorize("@authz.checkReactive(#id)")
	public Mono<String> monoReactivePreAuthorizeBeanFindById(
			long id) {
		return delegate.monoReactivePreAuthorizeBeanFindById(id);
	}

	@Override
	@PostAuthorize("@authz.check(authentication, returnObject)")
	public Mono<String> monoPostAuthorizeBeanFindById(
			long id) {
		return delegate.monoPostAuthorizeBeanFindById(id);
	}

	@Override
	public Flux<String> fluxFindById(long id) {
		return delegate.fluxFindById(id);
	}

	@Override
	@PreAuthorize("hasRole('ADMIN')")
	public Flux<String> fluxPreAuthorizeHasRoleFindById(
			long id) {
		return delegate.fluxPreAuthorizeHasRoleFindById(id);
	}

	@Override
	@PostAuthorize("returnObject?.contains(authentication?.name)")
	public Flux<String> fluxPostAuthorizeFindById(
			long id) {
		return delegate.fluxPostAuthorizeFindById(id);
	}

	@Override
	@PreAuthorize("@authz.check(#id)")
	public Flux<String> fluxPreAuthorizeBeanFindById(
			long id) {
		return delegate.fluxPreAuthorizeBeanFindById(id);
	}

	@Override
	@PreAuthorize("@authz.checkReactive(#id)")
	public Flux<String> fluxReactivePreAuthorizeBeanFindById(
			long id) {
		return delegate.fluxReactivePreAuthorizeBeanFindById(id);
	}

	@Override
	@PostAuthorize("@authz.check(authentication, returnObject)")
	public Flux<String> fluxPostAuthorizeBeanFindById(
			long id) {
		return delegate.fluxPostAuthorizeBeanFindById(id);
	}

	@Override
	public Publisher<String> publisherFindById(long id) {
		return delegate.publisherFindById(id);
	}

	@Override
	@PreAuthorize("hasRole('ADMIN')")
	public Publisher<String> publisherPreAuthorizeHasRoleFindById(
			long id) {
		return delegate.publisherPreAuthorizeHasRoleFindById(id);
	}

	@Override
	@PostAuthorize("returnObject?.contains(authentication?.name)")
	public Publisher<String> publisherPostAuthorizeFindById(
			long id) {
		return delegate.publisherPostAuthorizeFindById(id);
	}

	@Override
	@PreAuthorize("@authz.check(#id)")
	public Publisher<String> publisherPreAuthorizeBeanFindById(
			long id) {
		return delegate.publisherPreAuthorizeBeanFindById(id);
	}

	@Override
	@PreAuthorize("@authz.checkReactive(#id)")
	public Publisher<String> publisherReactivePreAuthorizeBeanFindById(
			long id) {
		return delegate.publisherReactivePreAuthorizeBeanFindById(id);
	}

	@Override
	@PostAuthorize("@authz.check(authentication, returnObject)")
	public Publisher<String> publisherPostAuthorizeBeanFindById(
			long id) {
		return delegate.publisherPostAuthorizeBeanFindById(id);
	}
}
