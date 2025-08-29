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

package org.springframework.security.authentication.ott;

import java.io.Serial;
import java.util.Collection;

import org.jspecify.annotations.Nullable;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.Assert;

/**
 * The result of a successful one-time-token authentication
 *
 * @author Josh Cummings
 * @since 7.0
 */
public class OneTimeTokenAuthentication extends AbstractAuthenticationToken {

	@Serial
	private static final long serialVersionUID = 1195893764725073959L;

	private final Object principal;

	public OneTimeTokenAuthentication(Object principal, Collection<? extends GrantedAuthority> authorities) {
		super(authorities);
		this.principal = principal;
		setAuthenticated(true);
	}

	protected OneTimeTokenAuthentication(Builder<?> builder) {
		super(builder);
		this.principal = builder.principal;
	}

	@Override
	public Object getPrincipal() {
		return this.principal;
	}

	@Override
	public @Nullable Object getCredentials() {
		return null;
	}

	@Override
	public Builder<?> toBuilder() {
		return new Builder<>(this);
	}

	/**
	 * A builder for constructing a {@link OneTimeTokenAuthentication} instance
	 */
	public static class Builder<B extends Builder<B>> extends AbstractAuthenticationBuilder<Object, Object, B> {

		private Object principal;

		protected Builder(OneTimeTokenAuthentication token) {
			super(token);
			this.principal = token.principal;
		}

		/**
		 * Use this principal
		 * @return the {@link Builder} for further configuration
		 */
		@Override
		public B principal(@Nullable Object principal) {
			Assert.notNull(principal, "principal cannot be null");
			this.principal = principal;
			return (B) this;
		}

		@Override
		public OneTimeTokenAuthentication build() {
			return new OneTimeTokenAuthentication(this);
		}

	}

}
