/*
 * Copyright 2002-2019 the original author or authors.
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
package org.springframework.security.oauth2.jose.jws;

/**
 * An enumeration of the cryptographic algorithms defined by the JSON Web Algorithms (JWA)
 * specification and used by JSON Web Signature (JWS) to create a MAC of the contents of
 * the JWS Protected Header and JWS Payload.
 *
 * @author Joe Grandja
 * @since 5.2
 * @see JwsAlgorithm
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7518">JSON Web Algorithms
 * (JWA)</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7515">JSON Web Signature
 * (JWS)</a>
 * @see <a target="_blank" href=
 * "https://tools.ietf.org/html/rfc7518#section-3">Cryptographic Algorithms for Digital
 * Signatures and MACs</a>
 */
public enum MacAlgorithm implements JwsAlgorithm {

	/**
	 * HMAC using SHA-256 (Required)
	 */
	HS256(JwsAlgorithms.HS256),

	/**
	 * HMAC using SHA-384 (Optional)
	 */
	HS384(JwsAlgorithms.HS384),

	/**
	 * HMAC using SHA-512 (Optional)
	 */
	HS512(JwsAlgorithms.HS512);

	private final String name;

	MacAlgorithm(String name) {
		this.name = name;
	}

	/**
	 * Attempt to resolve the provided algorithm name to a {@code MacAlgorithm}.
	 * @param name the algorithm name
	 * @return the resolved {@code MacAlgorithm}, or {@code null} if not found
	 */
	public static MacAlgorithm from(String name) {
		for (MacAlgorithm algorithm : values()) {
			if (algorithm.getName().equals(name)) {
				return algorithm;
			}
		}
		return null;
	}

	/**
	 * Returns the algorithm name.
	 * @return the algorithm name
	 */
	@Override
	public String getName() {
		return this.name;
	}

}
