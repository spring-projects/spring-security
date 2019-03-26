/*
 * Copyright 2002-2017 the original author or authors.
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
package org.springframework.security.oauth2.core.oidc;

/**
 * The names of the &quot;claims&quot; defined by the OpenID Connect Core 1.0 specification
 * that can be returned in the ID Token.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see OidcIdToken
 * @see <a target="_blank" href="https://openid.net/specs/openid-connect-core-1_0.html#IDToken">ID Token</a>
 */

public interface IdTokenClaimNames {

	/**
	 * {@code iss} - the Issuer identifier
	 */
	String ISS = "iss";

	/**
	 * {@code sub} - the Subject identifier
	 */
	String SUB = "sub";

	/**
	 * {@code aud} - the Audience(s) that the ID Token is intended for
	 */
	String AUD = "aud";

	/**
	 * {@code exp} - the Expiration time on or after which the ID Token MUST NOT be accepted
	 */
	String EXP = "exp";

	/**
	 * {@code iat} - the time at which the ID Token was issued
	 */
	String IAT = "iat";

	/**
	 * {@code auth_time} - the time when the End-User authentication occurred
	 */
	String AUTH_TIME = "auth_time";

	/**
	 * {@code nonce} - a {@code String} value used to associate a Client session with an ID Token,
	 * and to mitigate replay attacks.
	 */
	String NONCE = "nonce";

	/**
	 * {@code acr} - the Authentication Context Class Reference
	 */
	String ACR = "acr";

	/**
	 * {@code amr} - the Authentication Methods References
	 */
	String AMR = "amr";

	/**
	 * {@code azp} - the Authorized party to which the ID Token was issued
	 */
	String AZP = "azp";

	/**
	 * {@code at_hash} - the Access Token hash value
	 */
	String AT_HASH = "at_hash";

	/**
	 * {@code c_hash} - the Authorization Code hash value
	 */
	String C_HASH = "c_hash";

}
