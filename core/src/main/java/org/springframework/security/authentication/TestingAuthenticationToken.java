/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

import org.jspecify.annotations.Nullable;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.util.Assert;

/**
 * An {@link org.springframework.security.core.Authentication} implementation that is
 * designed for use whilst unit testing.
 * <p>
 * The corresponding authentication provider is {@link TestingAuthenticationProvider}.
 *
 * @author Ben Alex
 */
public class TestingAuthenticationToken extends AbstractAuthenticationToken {

	private static final long serialVersionUID = 1L;

	private final @Nullable Object credentials;

	private final Object principal;

	public TestingAuthenticationToken(Object principal, @Nullable Object credentials) {
		super((Collection<? extends GrantedAuthority>) null);
		this.principal = principal;
		this.credentials = credentials;
	}

	public TestingAuthenticationToken(Object principal, @Nullable Object credentials, String... authorities) {
		this(principal, credentials, AuthorityUtils.createAuthorityList(authorities));
	}

	public TestingAuthenticationToken(Object principal, @Nullable Object credentials, GrantedAuthority... authorities) {
		this(principal, credentials, Arrays.asList(authorities));
	}

	public TestingAuthenticationToken(Object principal, @Nullable Object credentials,
			List<? extends GrantedAuthority> authorities) {
		this(principal, credentials, (Collection<? extends GrantedAuthority>) authorities);
	}

	public TestingAuthenticationToken(Object principal, @Nullable Object credentials,
			Collection<? extends GrantedAuthority> authorities) {
		super(authorities);
		this.principal = principal;
		this.credentials = credentials;
		setAuthenticated(true);
	}

	protected TestingAuthenticationToken(Builder<?> builder) {
		super(builder);
		this.principal = builder.principal;
		this.credentials = builder.credentials;
	}

	@Override
	public @Nullable Object getCredentials() {
		return this.credentials;
	}

	@Override
	public Object getPrincipal() {
		return this.principal;
	}

	@Override
	public Builder<?> toBuilder() {
		return new Builder<>(this);
	}

	/**
	 * A builder of {@link TestingAuthenticationToken} instances
	 *
	 * @since 7.0
	 */
	public static class Builder<B extends Builder<B>> extends AbstractAuthenticationBuilder<B> {

		private Object principal;

		private @Nullable Object credentials;

		protected Builder(TestingAuthenticationToken token) {
			super(token);
			this.principal = token.principal;
			this.credentials = token.credentials;
		}

		@Override
		public B principal(@Nullable Object principal) {
			Assert.notNull(principal, "principal cannot be null");
			this.principal = principal;
			return (B) this;
		}

		@Override
		public B credentials(@Nullable Object credentials) {
			this.credentials = credentials;
			return (B) this;
		}

		@Override
		public TestingAuthenticationToken build() {
			return new TestingAuthenticationToken(this);
		}

	}

}
