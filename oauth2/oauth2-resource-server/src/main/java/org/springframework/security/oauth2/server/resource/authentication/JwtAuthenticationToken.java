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

package org.springframework.security.oauth2.server.resource.authentication;

import java.util.Collection;
import java.util.Map;

import org.jspecify.annotations.Nullable;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.Transient;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.Assert;

/**
 * An implementation of an {@link AbstractOAuth2TokenAuthenticationToken} representing a
 * {@link Jwt} {@code Authentication}.
 *
 * @author Joe Grandja
 * @since 5.1
 * @see AbstractOAuth2TokenAuthenticationToken
 * @see Jwt
 */
@Transient
public class JwtAuthenticationToken extends AbstractOAuth2TokenAuthenticationToken<Jwt> {

	private static final long serialVersionUID = 620L;

	private final String name;

	/**
	 * Constructs a {@code JwtAuthenticationToken} using the provided parameters.
	 * @param jwt the JWT
	 */
	public JwtAuthenticationToken(Jwt jwt) {
		super(jwt);
		this.name = jwt.getSubject();
	}

	/**
	 * Constructs a {@code JwtAuthenticationToken} using the provided parameters.
	 * @param jwt the JWT
	 * @param authorities the authorities assigned to the JWT
	 */
	public JwtAuthenticationToken(Jwt jwt, Collection<? extends GrantedAuthority> authorities) {
		super(jwt, authorities);
		this.setAuthenticated(true);
		this.name = jwt.getSubject();
	}

	/**
	 * Constructs a {@code JwtAuthenticationToken} using the provided parameters.
	 * @param jwt the JWT
	 * @param authorities the authorities assigned to the JWT
	 * @param name the principal name
	 */
	public JwtAuthenticationToken(Jwt jwt, Collection<? extends GrantedAuthority> authorities, String name) {
		super(jwt, authorities);
		this.setAuthenticated(true);
		this.name = name;
	}

	protected JwtAuthenticationToken(Builder<?> builder) {
		super(builder);
		this.name = builder.name;
	}

	@Override
	public Map<String, Object> getTokenAttributes() {
		return this.getToken().getClaims();
	}

	/**
	 * The principal name which is, by default, the {@link Jwt}'s subject
	 */
	@Override
	public String getName() {
		return this.name;
	}

	@Override
	public Builder<?> toBuilder() {
		return new Builder<>(this);
	}

	/**
	 * A builder for {@link JwtAuthenticationToken} instances
	 *
	 * @since 7.0
	 * @see Authentication.Builder
	 */
	public static class Builder<B extends Builder<B>> extends AbstractOAuth2TokenAuthenticationBuilder<Jwt, B> {

		private String name;

		protected Builder(JwtAuthenticationToken token) {
			super(token);
			this.name = token.getName();
		}

		/**
		 * A synonym for {@link #token(Jwt)}
		 * @return the {@link Builder} for further configurations
		 */
		@Override
		public B principal(@Nullable Object principal) {
			Assert.isInstanceOf(Jwt.class, principal, "principal must be of type Jwt");
			return token((Jwt) principal);
		}

		/**
		 * A synonym for {@link #token(Jwt)}
		 * @return the {@link Builder} for further configurations
		 */
		@Override
		public B credentials(@Nullable Object credentials) {
			Assert.isInstanceOf(Jwt.class, credentials, "credentials must be of type Jwt");
			return token((Jwt) credentials);
		}

		/**
		 * Use this {@code token} as the token, principal, and credentials. Also sets the
		 * {@code name} to {@link Jwt#getSubject}.
		 * @param token the token to use
		 * @return the {@link Builder} for further configurations
		 */
		@Override
		public B token(Jwt token) {
			super.principal(token);
			super.credentials(token);
			return super.token(token).name(token.getSubject());
		}

		/**
		 * The name to use.
		 * @param name the name to use
		 * @return the {@link Builder} for further configurations
		 */
		public B name(String name) {
			this.name = name;
			return (B) this;
		}

		@Override
		public JwtAuthenticationToken build() {
			return new JwtAuthenticationToken(this);
		}

	}

}
