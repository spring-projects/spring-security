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

package org.springframework.security.authentication.apikey;

import java.io.Serial;
import java.util.Collection;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.Assert;

/**
 * Represents API key that successfully went through authentication process.
 *
 * @author Alexey Razinkov
 */
public final class AuthenticatedApiKeyToken extends AbstractAuthenticationToken {

	@Serial
	private static final long serialVersionUID = -931927237123550204L;

	private final ApiKey value;

	/**
	 * Creates a token with the supplied array of authorities.
	 * @param value API key
	 * @param authorities the collection of <tt>GrantedAuthority</tt>s for the principal
	 * represented by this authentication object.
	 */
	public AuthenticatedApiKeyToken(ApiKey value, @Nullable Collection<? extends GrantedAuthority> authorities,
			@Nullable Object details) {
		super(authorities);
		Assert.notNull(value, "API key must be provided");
		this.value = value;
		setAuthenticated(true);
		setDetails(details);
	}

	public ApiKey getValue() {
		return this.value;
	}

	@Override
	public @NonNull byte[] getCredentials() {
		return this.value.getSecret();
	}

	@Override
	public @NonNull String getPrincipal() {
		return this.value.getId();
	}

}
