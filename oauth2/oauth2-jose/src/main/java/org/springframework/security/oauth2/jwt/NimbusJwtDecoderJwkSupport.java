/*
 * Copyright 2002-2017 the original author or authors.
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
package org.springframework.security.oauth2.jwt;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.DefaultResourceRetriever;
import com.nimbusds.jose.util.ResourceRetriever;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithms;
import org.springframework.util.Assert;

import java.net.MalformedURLException;
import java.net.URL;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * An implementation of a {@link JwtDecoder} that &quot;decodes&quot; a
 * <i>JSON Web Token (JWT)</i> and additionally verifies it's digital signature if the JWT is a
 * <i>JSON Web Signature (JWS)</i>. The public key used for verification is obtained from the
 * <i>JSON Web Key (JWK)</i> Set <code>URL</code> which is supplied via the constructor.
 *
 * <p>
 * <b>NOTE:</b> This implementation uses the <b>Nimbus JOSE + JWT SDK</b> internally.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see JwtDecoder
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7519">JSON Web Token (JWT)</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7515">JSON Web Signature (JWS)</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7517">JSON Web Key (JWK)</a>
 * @see <a target="_blank" href="https://connect2id.com/products/nimbus-jose-jwt">Nimbus JOSE + JWT SDK</a>
 */
public final class NimbusJwtDecoderJwkSupport implements JwtDecoder {
	private final URL jwkSetUrl;
	private final JWSAlgorithm jwsAlgorithm;
	private final ConfigurableJWTProcessor<SecurityContext> jwtProcessor;

	public NimbusJwtDecoderJwkSupport(String jwkSetUrl) {
		this(jwkSetUrl, JwsAlgorithms.RS256);
	}

	public NimbusJwtDecoderJwkSupport(String jwkSetUrl, String jwsAlgorithm) {
		Assert.hasText(jwkSetUrl, "jwkSetUrl cannot be empty");
		Assert.hasText(jwsAlgorithm, "jwsAlgorithm cannot be empty");
		try {
			this.jwkSetUrl = new URL(jwkSetUrl);
		} catch (MalformedURLException ex) {
			throw new IllegalArgumentException("Invalid JWK Set URL " + jwkSetUrl + " : " + ex.getMessage(), ex);
		}
		this.jwsAlgorithm = JWSAlgorithm.parse(jwsAlgorithm);

		ResourceRetriever jwkSetRetriever = new DefaultResourceRetriever(30000, 30000);
		JWKSource jwkSource = new RemoteJWKSet(this.jwkSetUrl, jwkSetRetriever);
		JWSKeySelector<SecurityContext> jwsKeySelector =
			new JWSVerificationKeySelector<SecurityContext>(this.jwsAlgorithm, jwkSource);

		this.jwtProcessor = new DefaultJWTProcessor<>();
		this.jwtProcessor.setJWSKeySelector(jwsKeySelector);
	}

	@Override
	public Jwt decode(String token) throws JwtException {
		Jwt jwt;

		try {
			JWT parsedJwt = JWTParser.parse(token);

			// Verify the signature
			JWTClaimsSet jwtClaimsSet = this.jwtProcessor.process(parsedJwt, null);

			Instant expiresAt = jwtClaimsSet.getExpirationTime().toInstant();
			Instant issuedAt;
			if (jwtClaimsSet.getIssueTime() != null) {
				issuedAt = jwtClaimsSet.getIssueTime().toInstant();
			} else {
				// issuedAt is required in AbstractOAuth2Token so let's default to expiresAt - 1 second
				issuedAt = Instant.from(expiresAt).minusSeconds(1);
			}

			Map<String, Object> headers = new LinkedHashMap<>(parsedJwt.getHeader().toJSONObject());

			jwt = new Jwt(token, issuedAt, expiresAt, headers, jwtClaimsSet.getClaims());

		} catch (Exception ex) {
			throw new JwtException("An error occurred while attempting to decode the Jwt: " + ex.getMessage(), ex);
		}

		return jwt;
	}
}
