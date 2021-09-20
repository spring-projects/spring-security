/*
 * Copyright 2002-2021 the original author or authors.
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

package org.springframework.security.oauth2.jwt;

import org.springframework.lang.Nullable;
import org.springframework.util.Assert;

/**
 * A holder of parameters containing the JWS headers and JWT Claims Set.
 *
 * @author Joe Grandja
 * @since 5.6
 * @see JwsHeader
 * @see JwtClaimsSet
 * @see JwtEncoder
 */
public final class JwtEncoderParameters {

	private final JwsHeader jwsHeader;

	private final JwtClaimsSet claims;

	private JwtEncoderParameters(JwsHeader jwsHeader, JwtClaimsSet claims) {
		this.jwsHeader = jwsHeader;
		this.claims = claims;
	}

	/**
	 * Returns a new {@link JwtEncoderParameters}, initialized with the provided
	 * {@link JwtClaimsSet}.
	 * @param claims the {@link JwtClaimsSet}
	 * @return the {@link JwtEncoderParameters}
	 */
	public static JwtEncoderParameters from(JwtClaimsSet claims) {
		Assert.notNull(claims, "claims cannot be null");
		return new JwtEncoderParameters(null, claims);
	}

	/**
	 * Returns a new {@link JwtEncoderParameters}, initialized with the provided
	 * {@link JwsHeader} and {@link JwtClaimsSet}.
	 * @param jwsHeader the {@link JwsHeader}
	 * @param claims the {@link JwtClaimsSet}
	 * @return the {@link JwtEncoderParameters}
	 */
	public static JwtEncoderParameters from(JwsHeader jwsHeader, JwtClaimsSet claims) {
		Assert.notNull(jwsHeader, "jwsHeader cannot be null");
		Assert.notNull(claims, "claims cannot be null");
		return new JwtEncoderParameters(jwsHeader, claims);
	}

	/**
	 * Returns the {@link JwsHeader JWS headers}.
	 * @return the {@link JwsHeader}, or {@code null} if not specified
	 */
	@Nullable
	public JwsHeader getJwsHeader() {
		return this.jwsHeader;
	}

	/**
	 * Returns the {@link JwtClaimsSet claims}.
	 * @return the {@link JwtClaimsSet}
	 */
	public JwtClaimsSet getClaims() {
		return this.claims;
	}

}
