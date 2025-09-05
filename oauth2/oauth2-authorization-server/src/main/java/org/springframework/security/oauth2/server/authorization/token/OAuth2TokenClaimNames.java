/*
 * Copyright 2020-2022 the original author or authors.
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

import org.springframework.security.oauth2.core.OAuth2Token;

/**
 * The names of the "claims" that may be contained in an {@link OAuth2TokenClaimsSet} and
 * are associated to an {@link OAuth2Token}.
 *
 * @author Joe Grandja
 * @since 0.2.3
 * @see OAuth2TokenClaimAccessor
 * @see OAuth2TokenClaimsSet
 * @see OAuth2Token
 */
public final class OAuth2TokenClaimNames {

	/**
	 * {@code iss} - the Issuer claim identifies the principal that issued the OAuth 2.0
	 * Token
	 */
	public static final String ISS = "iss";

	/**
	 * {@code sub} - the Subject claim identifies the principal that is the subject of the
	 * OAuth 2.0 Token
	 */
	public static final String SUB = "sub";

	/**
	 * {@code aud} - the Audience claim identifies the recipient(s) that the OAuth 2.0
	 * Token is intended for
	 */
	public static final String AUD = "aud";

	/**
	 * {@code exp} - the Expiration time claim identifies the expiration time on or after
	 * which the OAuth 2.0 Token MUST NOT be accepted for processing
	 */
	public static final String EXP = "exp";

	/**
	 * {@code nbf} - the Not Before claim identifies the time before which the OAuth 2.0
	 * Token MUST NOT be accepted for processing
	 */
	public static final String NBF = "nbf";

	/**
	 * {@code iat} - The Issued at claim identifies the time at which the OAuth 2.0 Token
	 * was issued
	 */
	public static final String IAT = "iat";

	/**
	 * {@code jti} - The ID claim provides a unique identifier for the OAuth 2.0 Token
	 */
	public static final String JTI = "jti";

	private OAuth2TokenClaimNames() {
	}

}
