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
package org.springframework.security.oauth2.jose.jws;

/**
 * The cryptographic algorithms defined by the JSON Web Algorithms (JWA) specification and
 * used by JSON Web Signature (JWS) to digitally sign or create a MAC of the contents of
 * the JWS Protected Header and JWS Payload.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7518">JSON Web Algorithms
 * (JWA)</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7515">JSON Web Signature
 * (JWS)</a>
 * @see <a target="_blank" href=
 * "https://tools.ietf.org/html/rfc7518#section-3">Cryptographic Algorithms for Digital
 * Signatures and MACs</a>
 */
public interface JwsAlgorithms {

	/**
	 * HMAC using SHA-256 (Required)
	 */
	String HS256 = "HS256";

	/**
	 * HMAC using SHA-384 (Optional)
	 */
	String HS384 = "HS384";

	/**
	 * HMAC using SHA-512 (Optional)
	 */
	String HS512 = "HS512";

	/**
	 * RSASSA-PKCS1-v1_5 using SHA-256 (Recommended)
	 */
	String RS256 = "RS256";

	/**
	 * RSASSA-PKCS1-v1_5 using SHA-384 (Optional)
	 */
	String RS384 = "RS384";

	/**
	 * RSASSA-PKCS1-v1_5 using SHA-512 (Optional)
	 */
	String RS512 = "RS512";

	/**
	 * ECDSA using P-256 and SHA-256 (Recommended+)
	 */
	String ES256 = "ES256";

	/**
	 * ECDSA using P-384 and SHA-384 (Optional)
	 */
	String ES384 = "ES384";

	/**
	 * ECDSA using P-521 and SHA-512 (Optional)
	 */
	String ES512 = "ES512";

	/**
	 * RSASSA-PSS using SHA-256 and MGF1 with SHA-256 (Optional)
	 */
	String PS256 = "PS256";

	/**
	 * RSASSA-PSS using SHA-384 and MGF1 with SHA-384 (Optional)
	 */
	String PS384 = "PS384";

	/**
	 * RSASSA-PSS using SHA-512 and MGF1 with SHA-512 (Optional)
	 */
	String PS512 = "PS512";

}
