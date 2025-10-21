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

import java.util.Collection;

import org.jspecify.annotations.Nullable;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.Assert;

/**
 * An {@link org.springframework.security.core.Authentication} implementation that is
 * designed for simple presentation of a username and password.
 * <p>
 * The <code>principal</code> and <code>credentials</code> should be set with an
 * <code>Object</code> that provides the respective property via its
 * <code>Object.toString()</code> method. The simplest such <code>Object</code> to use is
 * <code>String</code>.
 *
 * @author Ben Alex
 * @author Norbert Nowak
 */
public class UsernamePasswordAuthenticationToken extends AbstractAuthenticationToken {

	private static final long serialVersionUID = 620L;

	private final @Nullable Object principal;

	private @Nullable Object credentials;

	/**
	 * This constructor can be safely used by any code that wishes to create a
	 * <code>UsernamePasswordAuthenticationToken</code>, as the {@link #isAuthenticated()}
	 * will return <code>false</code>.
	 *
	 */
	public UsernamePasswordAuthenticationToken(@Nullable Object principal, @Nullable Object credentials) {
		super((Collection<? extends GrantedAuthority>) null);
		this.principal = principal;
		this.credentials = credentials;
		setAuthenticated(false);
	}

	/**
	 * This constructor should only be used by <code>AuthenticationManager</code> or
	 * <code>AuthenticationProvider</code> implementations that are satisfied with
	 * producing a trusted (i.e. {@link #isAuthenticated()} = <code>true</code>)
	 * authentication token.
	 * @param principal
	 * @param credentials
	 * @param authorities
	 */
	public UsernamePasswordAuthenticationToken(Object principal, @Nullable Object credentials,
			Collection<? extends GrantedAuthority> authorities) {
		super(authorities);
		this.principal = principal;
		this.credentials = credentials;
		super.setAuthenticated(true); // must use super, as we override
	}

	protected UsernamePasswordAuthenticationToken(Builder<?> builder) {
		super(builder);
		this.principal = builder.principal;
		this.credentials = builder.credentials;
	}

	/**
	 * This factory method can be safely used by any code that wishes to create a
	 * unauthenticated <code>UsernamePasswordAuthenticationToken</code>.
	 * @param principal
	 * @param credentials
	 * @return UsernamePasswordAuthenticationToken with false isAuthenticated() result
	 *
	 * @since 5.7
	 */
	public static UsernamePasswordAuthenticationToken unauthenticated(@Nullable Object principal,
			@Nullable Object credentials) {
		return new UsernamePasswordAuthenticationToken(principal, credentials);
	}

	/**
	 * This factory method can be safely used by any code that wishes to create a
	 * authenticated <code>UsernamePasswordAuthenticationToken</code>.
	 * @param principal
	 * @param credentials
	 * @return UsernamePasswordAuthenticationToken with true isAuthenticated() result
	 *
	 * @since 5.7
	 */
	public static UsernamePasswordAuthenticationToken authenticated(Object principal, @Nullable Object credentials,
			Collection<? extends GrantedAuthority> authorities) {
		return new UsernamePasswordAuthenticationToken(principal, credentials, authorities);
	}

	@Override
	public @Nullable Object getCredentials() {
		return this.credentials;
	}

	@Override
	public @Nullable Object getPrincipal() {
		return this.principal;
	}

	@Override
	public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
		Assert.isTrue(!isAuthenticated,
				"Cannot set this token to trusted - use constructor which takes a GrantedAuthority list instead");
		super.setAuthenticated(false);
	}

	@Override
	public void eraseCredentials() {
		super.eraseCredentials();
		this.credentials = null;
	}

	@Override
	public Builder<?> toBuilder() {
		return new Builder<>(this);
	}

	/**
	 * A builder of {@link UsernamePasswordAuthenticationToken} instances
	 *
	 * @since 7.0
	 */
	public static class Builder<B extends Builder<B>> extends AbstractAuthenticationBuilder<B> {

		private @Nullable Object principal;

		private @Nullable Object credentials;

		protected Builder(UsernamePasswordAuthenticationToken token) {
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
		public UsernamePasswordAuthenticationToken build() {
			return new UsernamePasswordAuthenticationToken(this);
		}

	}

}
