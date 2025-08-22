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

package org.springframework.security.core;

import java.util.Collection;
import java.util.function.Consumer;

import org.springframework.util.Assert;

/**
 * An adapter implementation of {@link Authentication.Builder} that provides a no-op
 * implementation for the principal, credentials, and authorities
 *
 * @param <A> the type of {@link Authentication}
 * @author Josh Cummings
 * @since 7.0
 */
class NoopAuthenticationBuilder<A extends Authentication>
		implements Authentication.Builder<A, NoopAuthenticationBuilder<A>> {

	private A original;

	NoopAuthenticationBuilder(A authentication) {
		Assert.isTrue(authentication.isAuthenticated(), "cannot mutate an unauthenticated token");
		Assert.notNull(authentication.getPrincipal(), "principal cannot be null");
		this.original = authentication;
	}

	@Override
	public NoopAuthenticationBuilder<A> authorities(Consumer<Collection<GrantedAuthority>> authorities) {
		return this;
	}

	@Override
	public A build() {
		return this.original;
	}

}
