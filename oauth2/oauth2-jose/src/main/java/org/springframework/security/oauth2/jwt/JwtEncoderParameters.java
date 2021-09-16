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

import org.springframework.util.Assert;

/**
 * A holder of parameters containing the JOSE header and JWT Claims Set.
 *
 * @author Joe Grandja
 * @since 5.6
 * @see JwtEncoder
 */
public final class JwtEncoderParameters {

	private final JoseHeader headers;

	private final JwtClaimsSet claims;

	private JwtEncoderParameters(JoseHeader headers, JwtClaimsSet claims) {
		Assert.notNull(headers, "headers cannot be null");
		Assert.notNull(claims, "claims cannot be null");
		this.headers = headers;
		this.claims = claims;
	}

	/**
	 * Returns a new {@link JwtEncoderParameters}, initialized with the provided
	 * {@link JoseHeader} and {@link JwtClaimsSet}.
	 * @param headers the {@link JoseHeader}
	 * @param claims the {@link JwtClaimsSet}
	 * @return the {@link JwtEncoderParameters}
	 */
	public static JwtEncoderParameters with(JoseHeader headers, JwtClaimsSet claims) {
		return new JwtEncoderParameters(headers, claims);
	}

	/**
	 * Returns the {@link JoseHeader headers}.
	 * @return the {@link JoseHeader}
	 */
	public JoseHeader getHeaders() {
		return this.headers;
	}

	/**
	 * Returns the {@link JwtClaimsSet claims}.
	 * @return the {@link JwtClaimsSet}
	 */
	public JwtClaimsSet getClaims() {
		return this.claims;
	}

}
