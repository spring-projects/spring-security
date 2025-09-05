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

package org.springframework.security.oauth2.server.authorization.token;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.springframework.lang.Nullable;
import org.springframework.util.Assert;

/**
 * An {@link OAuth2TokenContext} implementation that provides access to the
 * {@link #getClaims() claims} of an OAuth 2.0 Token, allowing the ability to customize.
 *
 * @author Joe Grandja
 * @since 0.2.3
 * @see OAuth2TokenContext
 * @see OAuth2TokenClaimsSet.Builder
 */
public final class OAuth2TokenClaimsContext implements OAuth2TokenContext {

	private final Map<Object, Object> context;

	private OAuth2TokenClaimsContext(Map<Object, Object> context) {
		this.context = Collections.unmodifiableMap(new HashMap<>(context));
	}

	@SuppressWarnings("unchecked")
	@Nullable
	@Override
	public <V> V get(Object key) {
		return hasKey(key) ? (V) this.context.get(key) : null;
	}

	@Override
	public boolean hasKey(Object key) {
		Assert.notNull(key, "key cannot be null");
		return this.context.containsKey(key);
	}

	/**
	 * Returns the {@link OAuth2TokenClaimsSet.Builder claims} allowing the ability to
	 * add, replace, or remove.
	 * @return the {@link OAuth2TokenClaimsSet.Builder}
	 */
	public OAuth2TokenClaimsSet.Builder getClaims() {
		return get(OAuth2TokenClaimsSet.Builder.class);
	}

	/**
	 * Constructs a new {@link Builder} with the provided claims.
	 * @param claimsBuilder the claims to initialize the builder
	 * @return the {@link Builder}
	 */
	public static Builder with(OAuth2TokenClaimsSet.Builder claimsBuilder) {
		return new Builder(claimsBuilder);
	}

	/**
	 * A builder for {@link OAuth2TokenClaimsContext}.
	 */
	public static final class Builder extends AbstractBuilder<OAuth2TokenClaimsContext, Builder> {

		private Builder(OAuth2TokenClaimsSet.Builder claimsBuilder) {
			Assert.notNull(claimsBuilder, "claimsBuilder cannot be null");
			put(OAuth2TokenClaimsSet.Builder.class, claimsBuilder);
		}

		/**
		 * Builds a new {@link OAuth2TokenClaimsContext}.
		 * @return the {@link OAuth2TokenClaimsContext}
		 */
		@Override
		public OAuth2TokenClaimsContext build() {
			return new OAuth2TokenClaimsContext(getContext());
		}

	}

}
