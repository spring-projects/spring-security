/*
 * Copyright 2002-2020 the original author or authors.
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

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.lang.Nullable;
import org.springframework.util.Assert;

import java.util.HashMap;
import java.util.Map;

/**
 * A low-level Nimbus implementation of {@link JwtEncoder} which takes a raw Nimbus configuration.
 *
 * <p>
 * This class currently supports signing JWTs according to the JSON Web Signature (JWS) specification
 * and encoding them in the JWS Compact Serialization format.
 *
 * @author Gergely Krajcsovszki
 * @since TODO
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7515">JSON Web Signature (JWS)</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7515#section-3.1">JWS Compact Serialization</a>
 */
public final class NimbusJwtEncoder implements JwtEncoder {
	private static final String ENCODING_ERROR_MESSAGE_TEMPLATE =
			"An error occurred while attempting to encode the Jwt: %s";

	private final JWSSigner jwsSigner;

	private final JWSAlgorithm jwsAlgorithm;

	/**
	 * Configures a {@link NimbusJwtEncoder} with the given parameters
	 *
	 * @param jwsSigner the {@link JWSSigner} to use
	 * @param preferredJwsAlgorithm the {@link JWSAlgorithm} to use if the token to encode doesn't specify.
	 * If left null, the first one returned by {@link JWSSigner#supportedJWSAlgorithms()} will be used.
	 * Must be compatible with the keys set in the {@link JWSSigner}.
	 */
	public NimbusJwtEncoder(JWSSigner jwsSigner, @Nullable JWSAlgorithm preferredJwsAlgorithm) {
		Assert.notNull(jwsSigner, "jwsSigner cannot be null");
		this.jwsSigner = jwsSigner;
		this.jwsAlgorithm =
				(preferredJwsAlgorithm != null
						? preferredJwsAlgorithm
						: jwsSigner.supportedJWSAlgorithms().iterator().next());
	}

	@Override
	public Jwt encode(Map<String, Object> claims) throws JwtException {
		JWSHeader header = createHeader();
		JWTClaimsSet claimsSet = createClaims(claims);
		SignedJWT signedJWT = new SignedJWT(header, claimsSet);
		try {
			signedJWT.sign(jwsSigner);
		} catch (JOSEException ex) {
			throw new BadJwtException(String.format(ENCODING_ERROR_MESSAGE_TEMPLATE, ex.getMessage()), ex);
		}
		return createJwt(signedJWT);
	}

	private JWTClaimsSet createClaims(Map<String, Object> claims) {
		JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();
		claims.forEach(builder::claim);
		return builder.build();
	}

	private JWSHeader createHeader() {
		JWSHeader.Builder builder = new JWSHeader.Builder(jwsAlgorithm);

		// TODO: add other headers

		return builder.build();
	}

	private Jwt createJwt(SignedJWT nimbusJwt) {
		try {
			HashMap<String, Object> headers = nimbusJwt.getHeader().toJSONObject();
			Map<String, Object> claims = nimbusJwt.getJWTClaimsSet().getClaims();
			return Jwt.withTokenValue(nimbusJwt.serialize())
					.headers(h -> h.putAll(headers))
					.claims(c -> c.putAll(claims))
					.build();
		} catch (Exception ex) {
			throw new BadJwtException(String.format(ENCODING_ERROR_MESSAGE_TEMPLATE, ex.getMessage()), ex);
		}
	}


	// TODO builders (like in NimbusJwtDecoder)
	// check com.nimbusds.jose.crypto.factories.DefaultJWSSignerFactory for creating the signer


}
