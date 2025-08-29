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

import org.jspecify.annotations.Nullable;

/**
 * An adapter implementation of {@link Authentication.Builder} that provides a no-op
 * implementation for the principal, credentials, and authorities
 *
 * @author Josh Cummings
 * @since 7.0
 */
class NoopAuthenticationBuilder implements Authentication.Builder<Object, Object, NoopAuthenticationBuilder> {

	private Authentication original;

	NoopAuthenticationBuilder(Authentication authentication) {
		this.original = authentication;
	}

	@Override
	public NoopAuthenticationBuilder authenticated(boolean authenticated) {
		return this;
	}

	@Override
	public NoopAuthenticationBuilder principal(@Nullable Object principal) {
		return this;
	}

	@Override
	public NoopAuthenticationBuilder details(@Nullable Object details) {
		return this;
	}

	@Override
	public NoopAuthenticationBuilder credentials(@Nullable Object credentials) {
		return this;
	}

	@Override
	public NoopAuthenticationBuilder authorities(Consumer<Collection<GrantedAuthority>> authorities) {
		return this;
	}

	@Override
	public Authentication build() {
		return this.original;
	}

}
