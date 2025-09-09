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

import java.io.Serial;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.function.Consumer;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jspecify.annotations.Nullable;

@Transient
final class SimpleAuthentication implements Authentication {

	@Serial
	private static final long serialVersionUID = 3194696462184782814L;

	private final @Nullable Object principal;

	private final @Nullable Object credentials;

	private final Collection<GrantedAuthority> authorities;

	private final @Nullable Object details;

	private final boolean authenticated;

	private SimpleAuthentication(Builder builder) {
		this.principal = builder.principal;
		this.credentials = builder.credentials;
		this.authorities = builder.authorities;
		this.details = builder.details;
		this.authenticated = builder.authenticated;
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return this.authorities;
	}

	@Override
	public @Nullable Object getCredentials() {
		return this.credentials;
	}

	@Override
	public @Nullable Object getDetails() {
		return this.details;
	}

	@Override
	public @Nullable Object getPrincipal() {
		return this.principal;
	}

	@Override
	public boolean isAuthenticated() {
		return this.authenticated;
	}

	@Override
	public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
		throw new IllegalArgumentException(
				"Instead of calling this setter, please call toBuilder to create a new instance");
	}

	@Override
	public String getName() {
		return (this.principal == null) ? "" : this.principal.toString();
	}

	static final class Builder implements Authentication.Builder<Builder> {

		private final Log logger = LogFactory.getLog(getClass());

		private final Collection<GrantedAuthority> authorities = new LinkedHashSet<>();

		private @Nullable Object principal;

		private @Nullable Object credentials;

		private @Nullable Object details;

		private boolean authenticated;

		Builder(Authentication authentication) {
			this.logger.debug("Creating a builder which will result in exchanging an authentication of type "
					+ authentication.getClass() + " for " + SimpleAuthentication.class.getSimpleName() + ";"
					+ " consider implementing " + authentication.getClass().getSimpleName() + "#toBuilder");
			this.authorities.addAll(authentication.getAuthorities());
			this.principal = authentication.getPrincipal();
			this.credentials = authentication.getCredentials();
			this.details = authentication.getDetails();
			this.authenticated = authentication.isAuthenticated();

		}

		@Override
		public Builder authorities(Consumer<Collection<GrantedAuthority>> authorities) {
			authorities.accept(this.authorities);
			return this;
		}

		@Override
		public Builder details(@Nullable Object details) {
			this.details = details;
			return this;
		}

		@Override
		public Builder principal(@Nullable Object principal) {
			this.principal = principal;
			return this;
		}

		@Override
		public Builder credentials(@Nullable Object credentials) {
			this.credentials = credentials;
			return this;
		}

		@Override
		public Builder authenticated(boolean authenticated) {
			this.authenticated = authenticated;
			return this;
		}

		@Override
		public Authentication build() {
			return new SimpleAuthentication(this);
		}

	}

}
