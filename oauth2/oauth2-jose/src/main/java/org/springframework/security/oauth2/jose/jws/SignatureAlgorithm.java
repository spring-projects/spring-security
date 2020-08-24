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
 * specification and used by JSON Web Signature (JWS) to digitally sign the contents of
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
public enum SignatureAlgorithm implements JwsAlgorithm {

	/**
	 * RSASSA-PKCS1-v1_5 using SHA-256 (Recommended)
	 */
	RS256(JwsAlgorithms.RS256),

	/**
	 * RSASSA-PKCS1-v1_5 using SHA-384 (Optional)
	 */
	RS384(JwsAlgorithms.RS384),

	/**
	 * RSASSA-PKCS1-v1_5 using SHA-512 (Optional)
	 */
	RS512(JwsAlgorithms.RS512),

	/**
	 * ECDSA using P-256 and SHA-256 (Recommended+)
	 */
	ES256(JwsAlgorithms.ES256),

	/**
	 * ECDSA using P-384 and SHA-384 (Optional)
	 */
	ES384(JwsAlgorithms.ES384),

	/**
	 * ECDSA using P-521 and SHA-512 (Optional)
	 */
	ES512(JwsAlgorithms.ES512),

	/**
	 * RSASSA-PSS using SHA-256 and MGF1 with SHA-256 (Optional)
	 */
	PS256(JwsAlgorithms.PS256),

	/**
	 * RSASSA-PSS using SHA-384 and MGF1 with SHA-384 (Optional)
	 */
	PS384(JwsAlgorithms.PS384),

	/**
	 * RSASSA-PSS using SHA-512 and MGF1 with SHA-512 (Optional)
	 */
	PS512(JwsAlgorithms.PS512);

	private final String name;

	SignatureAlgorithm(String name) {
		this.name = name;
	}

	/**
	 * Returns the algorithm name.
	 * @return the algorithm name
	 */
	@Override
	public String getName() {
		return this.name;
	}

	/**
	 * Attempt to resolve the provided algorithm name to a {@code SignatureAlgorithm}.
	 * @param name the algorithm name
	 * @return the resolved {@code SignatureAlgorithm}, or {@code null} if not found
	 */
	public static SignatureAlgorithm from(String name) {
		for (SignatureAlgorithm value : values()) {
			if (value.getName().equals(name)) {
				return value;
			}
		}
		return null;
	}

}
