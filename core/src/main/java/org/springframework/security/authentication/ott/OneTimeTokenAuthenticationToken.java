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
import java.util.Collections;

import org.jspecify.annotations.Nullable;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

/**
 * Represents a One-Time Token authentication that can be authenticated or not.
 *
 * @author Marcus da Coregio
 * @since 6.4
 */
public class OneTimeTokenAuthenticationToken extends AbstractAuthenticationToken {

	@Serial
	private static final long serialVersionUID = -8691636031126328365L;

	private @Nullable final Object principal;

	private @Nullable String tokenValue;

	/**
	 * @deprecated Please use constructor that takes a {@link String} instead
	 */
	@Deprecated(forRemoval = true, since = "7.0")
	public OneTimeTokenAuthenticationToken(@Nullable Object principal, String tokenValue) {
		super(Collections.emptyList());
		this.tokenValue = tokenValue;
		this.principal = principal;
	}

	public OneTimeTokenAuthenticationToken(String tokenValue) {
		this(null, tokenValue);
	}

	/**
	 * @deprecated Please use {@link OneTimeTokenAuthentication} instead
	 */
	@Deprecated(forRemoval = true, since = "7.0")
	public OneTimeTokenAuthenticationToken(Object principal, Collection<? extends GrantedAuthority> authorities) {
		super(authorities);
		this.principal = principal;
		setAuthenticated(true);
	}

	/**
	 * Creates an unauthenticated token
	 * @param tokenValue the one-time token value
	 * @return an unauthenticated {@link OneTimeTokenAuthenticationToken}
	 * @deprecated Please use constructor that takes a {@link String} instead
	 */
	@Deprecated(forRemoval = true, since = "7.0")
	public static OneTimeTokenAuthenticationToken unauthenticated(@Nullable String tokenValue) {
		return new OneTimeTokenAuthenticationToken(null, (tokenValue != null) ? tokenValue : "");
	}

	/**
	 * Creates an unauthenticated token
	 * @param principal the principal
	 * @param tokenValue the one-time token value
	 * @return an unauthenticated {@link OneTimeTokenAuthenticationToken}
	 * @deprecated Please use constructor that takes a {@link String} instead
	 */
	@Deprecated(forRemoval = true, since = "7.0")
	public static OneTimeTokenAuthenticationToken unauthenticated(Object principal, String tokenValue) {
		return new OneTimeTokenAuthenticationToken(principal, tokenValue);
	}

	/**
	 * Creates an unauthenticated token
	 * @param principal the principal
	 * @param authorities the principal authorities
	 * @return an authenticated {@link OneTimeTokenAuthenticationToken}
	 * @deprecated Please use {@link OneTimeTokenAuthentication} instead
	 */
	@Deprecated(forRemoval = true, since = "7.0")
	public static OneTimeTokenAuthenticationToken authenticated(Object principal,
			Collection<? extends GrantedAuthority> authorities) {
		return new OneTimeTokenAuthenticationToken(principal, authorities);
	}

	/**
	 * Returns the one-time token value
	 * @return
	 */
	public @Nullable String getTokenValue() {
		return this.tokenValue;
	}

	@Override
	public @Nullable Object getCredentials() {
		return this.tokenValue;
	}

	@Override
	public @Nullable Object getPrincipal() {
		return this.principal;
	}

}
