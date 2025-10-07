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

package org.springframework.security.authorization;

import java.util.List;
import java.util.function.Supplier;

import org.jspecify.annotations.Nullable;

import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

/**
 * An {@link AuthorizationManager} that requires all the authorities returned by a
 * {@link RequiredAuthoritiesRepository} implementation.
 *
 * @param <T> the type
 * @author Rob Winch
 * @since 7.0
 * @see AllAuthoritiesAuthorizationManager
 */
public class RequiredAuthoritiesAuthorizationManager<T> implements AuthorizationManager<T> {

	private final RequiredAuthoritiesRepository authorities;

	/**
	 * Creates a new instance.
	 * @param authorities the {@link RequiredAuthoritiesRepository} to use. Cannot be
	 * null.
	 */
	public RequiredAuthoritiesAuthorizationManager(RequiredAuthoritiesRepository authorities) {
		Assert.notNull(authorities, "authorities cannot be null");
		this.authorities = authorities;
	}

	@Override
	public @Nullable AuthorizationResult authorize(Supplier<? extends @Nullable Authentication> authentication,
			T object) {
		List<String> authorities = findAuthorities(authentication.get());
		if (authorities.isEmpty()) {
			return new AuthorizationDecision(true);
		}
		AllAuthoritiesAuthorizationManager<T> delegate = AllAuthoritiesAuthorizationManager
			.hasAllAuthorities(authorities);
		return delegate.authorize(authentication, object);
	}

	private List<String> findAuthorities(@Nullable Authentication authentication) {
		if (authentication == null) {
			return List.of();
		}
		String username = authentication.getName();
		return this.authorities.findRequiredAuthorities(username);
	}

}
