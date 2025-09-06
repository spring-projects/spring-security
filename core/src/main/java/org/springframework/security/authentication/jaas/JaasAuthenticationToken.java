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

package org.springframework.security.authentication.jaas;

import java.util.List;

import javax.security.auth.login.LoginContext;

import org.jspecify.annotations.Nullable;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.Assert;

/**
 * UsernamePasswordAuthenticationToken extension to carry the Jaas LoginContext that the
 * user was logged into
 *
 * @author Ray Krueger
 */
public class JaasAuthenticationToken extends UsernamePasswordAuthenticationToken {

	private static final long serialVersionUID = 620L;

	private final transient LoginContext loginContext;

	public JaasAuthenticationToken(Object principal, @Nullable Object credentials, LoginContext loginContext) {
		super(principal, credentials);
		this.loginContext = loginContext;
	}

	public JaasAuthenticationToken(Object principal, @Nullable Object credentials, List<GrantedAuthority> authorities,
			LoginContext loginContext) {
		super(principal, credentials, authorities);
		this.loginContext = loginContext;
	}

	protected JaasAuthenticationToken(Builder<?> builder) {
		super(builder);
		this.loginContext = builder.loginContext;
	}

	public LoginContext getLoginContext() {
		return this.loginContext;
	}

	@Override
	public Builder<?> toBuilder() {
		return new Builder<>(this);
	}

	/**
	 * A builder preserving the concrete {@link Authentication} type
	 *
	 * @since 7.0
	 */
	public static class Builder<B extends Builder<B>> extends UsernamePasswordAuthenticationToken.Builder<B> {

		private LoginContext loginContext;

		protected Builder(JaasAuthenticationToken token) {
			super(token);
			this.loginContext = token.getLoginContext();
		}

		/**
		 * Use this {@link LoginContext}
		 * @param loginContext the {@link LoginContext} to use
		 * @return the {@link Builder} for further configuration
		 */
		public B loginContext(LoginContext loginContext) {
			this.loginContext = loginContext;
			return (B) this;
		}

		@Override
		public JaasAuthenticationToken build() {
			Assert.notNull(this.principal, "principal cannot be null");
			return new JaasAuthenticationToken(this);
		}

	}

}
