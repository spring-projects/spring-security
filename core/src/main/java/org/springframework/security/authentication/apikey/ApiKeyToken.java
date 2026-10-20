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
 * Represents unauthenticated API token.
 *
 * @author Alexey Razinkov
 */
public final class ApiKeyToken extends AbstractAuthenticationToken {

	@Serial
	private static final long serialVersionUID = 4298132419326354292L;

	private final ApiKey value;

	private final Object details;

	public ApiKeyToken(ApiKey value, Object details) {
		super((Collection<? extends GrantedAuthority>) null);
		Assert.notNull(value, "API key must be provided");
		this.value = value;
		this.details = details;
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

	@Override
	public @Nullable Object getDetails() {
		return this.details;
	}

	@Override
	public void setDetails(@Nullable Object details) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setAuthenticated(boolean authenticated) {
		if (authenticated) {
			throw new IllegalArgumentException();
		}
	}

}
