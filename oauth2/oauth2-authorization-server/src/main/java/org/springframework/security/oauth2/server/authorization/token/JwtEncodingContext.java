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
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.util.Assert;

/**
 * An {@link OAuth2TokenContext} implementation used when encoding a {@link Jwt}.
 *
 * @author Joe Grandja
 * @since 0.1.0
 * @see OAuth2TokenContext
 * @see JwsHeader.Builder
 * @see JwtClaimsSet.Builder
 * @see JwtEncoder#encode(JwtEncoderParameters)
 */
public final class JwtEncodingContext implements OAuth2TokenContext {

	private final Map<Object, Object> context;

	private JwtEncodingContext(Map<Object, Object> context) {
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
	 * Returns the {@link JwsHeader.Builder JWS headers} allowing the ability to add,
	 * replace, or remove.
	 * @return the {@link JwsHeader.Builder}
	 */
	public JwsHeader.Builder getJwsHeader() {
		return get(JwsHeader.Builder.class);
	}

	/**
	 * Returns the {@link JwtClaimsSet.Builder claims} allowing the ability to add,
	 * replace, or remove.
	 * @return the {@link JwtClaimsSet.Builder}
	 */
	public JwtClaimsSet.Builder getClaims() {
		return get(JwtClaimsSet.Builder.class);
	}

	/**
	 * Constructs a new {@link Builder} with the provided JWS headers and claims.
	 * @param jwsHeaderBuilder the JWS headers to initialize the builder
	 * @param claimsBuilder the claims to initialize the builder
	 * @return the {@link Builder}
	 */
	public static Builder with(JwsHeader.Builder jwsHeaderBuilder, JwtClaimsSet.Builder claimsBuilder) {
		return new Builder(jwsHeaderBuilder, claimsBuilder);
	}

	/**
	 * A builder for {@link JwtEncodingContext}.
	 */
	public static final class Builder extends AbstractBuilder<JwtEncodingContext, Builder> {

		private Builder(JwsHeader.Builder jwsHeaderBuilder, JwtClaimsSet.Builder claimsBuilder) {
			Assert.notNull(jwsHeaderBuilder, "jwsHeaderBuilder cannot be null");
			Assert.notNull(claimsBuilder, "claimsBuilder cannot be null");
			put(JwsHeader.Builder.class, jwsHeaderBuilder);
			put(JwtClaimsSet.Builder.class, claimsBuilder);
		}

		/**
		 * Builds a new {@link JwtEncodingContext}.
		 * @return the {@link JwtEncodingContext}
		 */
		@Override
		public JwtEncodingContext build() {
			return new JwtEncodingContext(getContext());
		}

	}

}
