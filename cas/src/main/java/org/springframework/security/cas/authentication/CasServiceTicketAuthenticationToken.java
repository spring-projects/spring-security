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

package org.springframework.security.cas.authentication;

import java.io.Serial;
import java.util.Collection;

import org.jspecify.annotations.Nullable;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.Assert;

/**
 * An {@link org.springframework.security.core.Authentication} implementation that is
 * designed to process CAS service ticket.
 *
 * @author Hal Deadman
 * @since 6.1
 */
public class CasServiceTicketAuthenticationToken extends AbstractAuthenticationToken {

	static final String CAS_STATELESS_IDENTIFIER = "_cas_stateless_";

	static final String CAS_STATEFUL_IDENTIFIER = "_cas_stateful_";

	@Serial
	private static final long serialVersionUID = 620L;

	private final String identifier;

	private @Nullable Object credentials;

	/**
	 * This constructor can be safely used by any code that wishes to create a
	 * <code>CasServiceTicketAuthenticationToken</code>, as the {@link #isAuthenticated()}
	 * will return <code>false</code>.
	 *
	 */
	public CasServiceTicketAuthenticationToken(String identifier, Object credentials) {
		super((Collection<? extends GrantedAuthority>) null);
		this.identifier = identifier;
		this.credentials = credentials;
		setAuthenticated(false);
	}

	/**
	 * This constructor should only be used by <code>AuthenticationManager</code> or
	 * <code>AuthenticationProvider</code> implementations that are satisfied with
	 * producing a trusted (i.e. {@link #isAuthenticated()} = <code>true</code>)
	 * authentication token.
	 * @param identifier
	 * @param credentials
	 * @param authorities
	 */
	public CasServiceTicketAuthenticationToken(String identifier, Object credentials,
			Collection<? extends GrantedAuthority> authorities) {
		super(authorities);
		this.identifier = identifier;
		this.credentials = credentials;
		super.setAuthenticated(true);
	}

	protected CasServiceTicketAuthenticationToken(Builder<?> builder) {
		super(builder);
		this.identifier = builder.principal;
		this.credentials = builder.credentials;
	}

	public static CasServiceTicketAuthenticationToken stateful(Object credentials) {
		return new CasServiceTicketAuthenticationToken(CAS_STATEFUL_IDENTIFIER, credentials);
	}

	public static CasServiceTicketAuthenticationToken stateless(Object credentials) {
		return new CasServiceTicketAuthenticationToken(CAS_STATELESS_IDENTIFIER, credentials);
	}

	public boolean isStateless() {
		return CAS_STATELESS_IDENTIFIER.equals(this.identifier);
	}

	@Override
	public @Nullable Object getCredentials() {
		return this.credentials;
	}

	@Override
	public Object getPrincipal() {
		return this.identifier;
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

	public Builder<?> toBuilder() {
		return new Builder<>(this);
	}

	/**
	 * A builder of {@link CasServiceTicketAuthenticationToken} instances
	 *
	 * @since 7.0
	 */
	public static class Builder<B extends Builder<B>> extends AbstractAuthenticationBuilder<B> {

		private String principal;

		private @Nullable Object credentials;

		protected Builder(CasServiceTicketAuthenticationToken token) {
			super(token);
			this.principal = token.identifier;
			this.credentials = token.credentials;
		}

		@Override
		public B principal(@Nullable Object principal) {
			Assert.isInstanceOf(String.class, principal, "principal must be of type String");
			this.principal = (String) principal;
			return (B) this;
		}

		@Override
		public B credentials(@Nullable Object credentials) {
			Assert.notNull(credentials, "credentials cannot be null");
			this.credentials = credentials;
			return (B) this;
		}

		@Override
		public CasServiceTicketAuthenticationToken build() {
			return new CasServiceTicketAuthenticationToken(this);
		}

	}

}
