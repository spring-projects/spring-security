/*
 * Copyright 2002-2025 the original author or authors.
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

/**
 * The Registered Header Parameter Names defined by the JSON Web Token (JWT), JSON Web
 * Signature (JWS) and JSON Web Encryption (JWE) specifications that may be contained in
 * the JOSE Header of a JWT.
 *
 * @author Anoop Garlapati
 * @author Joe Grandja
 * @since 5.6
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7519#section-5">JWT JOSE
 * Header</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7515#section-4">JWS JOSE
 * Header</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7516#section-4">JWE JOSE
 * Header</a>
 */
public final class JoseHeaderNames {

	/**
	 * {@code alg} - the algorithm header identifies the cryptographic algorithm used to
	 * secure a JWS or JWE
	 */
	public static final String ALG = "alg";

	/**
	 * {@code jku} - the JWK Set URL header is a URI that refers to a resource for a set
	 * of JSON-encoded public keys, one of which corresponds to the key used to digitally
	 * sign a JWS or encrypt a JWE
	 */
	public static final String JKU = "jku";

	/**
	 * {@code jwk} - the JSON Web Key header is the public key that corresponds to the key
	 * used to digitally sign a JWS or encrypt a JWE
	 */
	public static final String JWK = "jwk";

	/**
	 * {@code kid} - the key ID header is a hint indicating which key was used to secure a
	 * JWS or JWE
	 */
	public static final String KID = "kid";

	/**
	 * {@code x5u} - the X.509 URL header is a URI that refers to a resource for the X.509
	 * public key certificate or certificate chain corresponding to the key used to
	 * digitally sign a JWS or encrypt a JWE
	 */
	public static final String X5U = "x5u";

	/**
	 * {@code x5c} - the X.509 certificate chain header contains the X.509 public key
	 * certificate or certificate chain corresponding to the key used to digitally sign a
	 * JWS or encrypt a JWE
	 */
	public static final String X5C = "x5c";

	/**
	 * {@code x5t} - the X.509 certificate SHA-1 thumbprint header is a base64url-encoded
	 * SHA-1 thumbprint (a.k.a. digest) of the DER encoding of the X.509 certificate
	 * corresponding to the key used to digitally sign a JWS or encrypt a JWE
	 * @deprecated The SHA-1 algorithm has been proven to be vulnerable to collision
	 * attacks and should not be used. See the <a target="_blank" href=
	 * "https://security.googleblog.com/2017/02/announcing-first-sha1-collision.html">Google
	 * Security Blog</a> for more info.
	 * @see <a target="_blank" href=
	 * "https://security.googleblog.com/2017/02/announcing-first-sha1-collision.html">Announcing
	 * the first SHA1 collision</a>
	 */
	@Deprecated
	public static final String X5T = "x5t";

	/**
	 * {@code x5t#S256} - the X.509 certificate SHA-256 thumbprint header is a
	 * base64url-encoded SHA-256 thumbprint (a.k.a. digest) of the DER encoding of the
	 * X.509 certificate corresponding to the key used to digitally sign a JWS or encrypt
	 * a JWE
	 */
	public static final String X5T_S256 = "x5t#S256";

	/**
	 * {@code typ} - the type header is used by JWS/JWE applications to declare the media
	 * type of a JWS/JWE
	 */
	public static final String TYP = "typ";

	/**
	 * {@code cty} - the content type header is used by JWS/JWE applications to declare
	 * the media type of the secured content (the payload)
	 */
	public static final String CTY = "cty";

	/**
	 * {@code crit} - the critical header indicates that extensions to the JWS/JWE/JWA
	 * specifications are being used that MUST be understood and processed
	 */
	public static final String CRIT = "crit";

	private JoseHeaderNames() {
	}

}
