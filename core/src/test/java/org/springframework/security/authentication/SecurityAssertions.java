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

package org.springframework.security.authentication;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.function.Predicate;

import org.assertj.core.api.AbstractObjectAssert;
import org.assertj.core.api.Assertions;
import org.assertj.core.api.CollectionAssert;
import org.assertj.core.api.Condition;
import org.assertj.core.api.ObjectAssert;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;

@NullMarked
public final class SecurityAssertions {

	private SecurityAssertions() {

	}

	public static AuthenticationAssert assertThat(@Nullable Authentication authentication) {
		Assertions.assertThat(authentication).isNotNull();
		return new AuthenticationAssert(authentication);
	}

	public static final class AuthenticationAssert extends AbstractObjectAssert<AuthenticationAssert, Authentication> {

		private final Authentication authentication;

		private AuthenticationAssert(Authentication authentication) {
			super(authentication, AuthenticationAssert.class);
			this.authentication = authentication;
		}

		public AuthenticationAssert name(String name) {
			Assertions.assertThat(this.authentication.getName()).isEqualTo(name);
			return this;
		}

		public ObjectAssert<GrantedAuthority> hasAuthority(String authority) {
			Collection<? extends GrantedAuthority> actual = this.authentication.getAuthorities();
			for (GrantedAuthority element : actual) {
				if (element.getAuthority().equals(authority)) {
					return new ObjectAssert<>(element);
				}
			}
			throw new AssertionError(actual + " does not contain " + authority + " as expected");
		}

		public CollectionAssert<GrantedAuthority> hasAuthorities(String... authorities) {
			HasAuthoritiesPredicate test = new HasAuthoritiesPredicate(authorities);
			return authorities().has(new Condition<>(test, "contains %s", Arrays.toString(authorities)));
		}

		public CollectionAssert<GrantedAuthority> authorities() {
			return new CollectionAssert<>(this.authentication.getAuthorities());
		}

	}

	private static final class HasAuthoritiesPredicate implements Predicate<Collection<? extends GrantedAuthority>> {

		private final Collection<String> expected;

		private HasAuthoritiesPredicate(String... expected) {
			this.expected = List.of(expected);
		}

		@Override
		public boolean test(Collection<? extends GrantedAuthority> actual) {
			Set<String> asString = AuthorityUtils.authorityListToSet(actual);
			return asString.containsAll(this.expected);
		}

	}

}
