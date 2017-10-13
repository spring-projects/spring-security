/*
 * Copyright 2012-2017 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.jwt;

import org.springframework.security.oauth2.core.SecurityToken;
import org.springframework.util.Assert;

import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * An implementation of a {@link SecurityToken} representing a <i>JSON Web Token (JWT)</i>.
 *
 * <p>
 * JWTs represent a set of &quot;Claims&quot; as a JSON object that may be encoded in a
 * <i>JSON Web Signature (JWS)</i> and/or <i>JSON Web Encryption (JWE)</i> structure.
 * The JSON object, also known as the <i>JWT Claims Set</i>, consists of one or more Claim Name/Claim Value pairs.
 * The Claim Name is a <code>String</code> and the Claim Value is an arbitrary JSON object.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see SecurityToken
 * @see JwtClaimAccessor
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7519">JSON Web Token (JWT)</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7515">JSON Web Signature (JWS)</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7516">JSON Web Encryption (JWE)</a>
 */
public class Jwt extends SecurityToken implements JwtClaimAccessor {
	private final Map<String, Object> headers;
	private final Map<String, Object> claims;

	public Jwt(String tokenValue, Instant issuedAt, Instant expiresAt,
				Map<String, Object> headers, Map<String, Object> claims) {
		super(tokenValue, issuedAt, expiresAt);
		Assert.notEmpty(headers, "headers cannot be empty");
		Assert.notEmpty(claims, "claims cannot be empty");
		this.headers = Collections.unmodifiableMap(new LinkedHashMap<>(headers));
		this.claims = Collections.unmodifiableMap(new LinkedHashMap<>(claims));
	}

	public Map<String, Object> getHeaders() {
		return this.headers;
	}

	@Override
	public Map<String, Object> getClaims() {
		return this.claims;
	}
}
