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

/**
 * Implementations of this interface are responsible for encoding a JSON Web Token (JWT)
 * to it's compact claims representation format.
 *
 * <p>
 * JWTs may be represented using the JWS Compact Serialization format for a JSON Web
 * Signature (JWS) structure or JWE Compact Serialization format for a JSON Web Encryption
 * (JWE) structure. Therefore, implementors are responsible for signing a JWS and/or
 * encrypting a JWE.
 *
 * @author Anoop Garlapati
 * @author Joe Grandja
 * @since 5.6
 * @see Jwt
 * @see JwtEncoderParameters
 * @see JwtDecoder
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7519">JSON Web Token
 * (JWT)</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7515">JSON Web Signature
 * (JWS)</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7516">JSON Web Encryption
 * (JWE)</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7515#section-3.1">JWS
 * Compact Serialization</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7516#section-3.1">JWE
 * Compact Serialization</a>
 */
@FunctionalInterface
public interface JwtEncoder {

	/**
	 * Encode the JWT to it's compact claims representation format.
	 * @param parameters the parameters containing the JOSE header and JWT Claims Set
	 * @return a {@link Jwt}
	 * @throws JwtEncodingException if an error occurs while attempting to encode the JWT
	 */
	Jwt encode(JwtEncoderParameters parameters) throws JwtEncodingException;

}
