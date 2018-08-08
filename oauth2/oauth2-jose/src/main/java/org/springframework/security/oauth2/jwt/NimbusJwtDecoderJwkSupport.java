/*
 * Copyright 2002-2018 the original author or authors.
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
import com.nimbusds.jose.RemoteKeySourceException;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.Resource;
import com.nimbusds.jose.util.ResourceRetriever;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithms;
import org.springframework.util.Assert;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.text.ParseException;
import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * An implementation of a {@link JwtDecoder} that "decodes" a
 * JSON Web Token (JWT) and additionally verifies it's digital signature if the JWT is a
 * JSON Web Signature (JWS). The public key used for verification is obtained from the
 * JSON Web Key (JWK) Set {@code URL} supplied via the constructor.
 *
 * <p>
 * <b>NOTE:</b> This implementation uses the Nimbus JOSE + JWT SDK internally.
 *
 * @author Joe Grandja
 * @author Josh Cummings
 * @since 5.0
 * @see JwtDecoder
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7519">JSON Web Token (JWT)</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7515">JSON Web Signature (JWS)</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7517">JSON Web Key (JWK)</a>
 * @see <a target="_blank" href="https://connect2id.com/products/nimbus-jose-jwt">Nimbus JOSE + JWT SDK</a>
 */
public final class NimbusJwtDecoderJwkSupport implements JwtDecoder {
	private static final String DECODING_ERROR_MESSAGE_TEMPLATE =
			"An error occurred while attempting to decode the Jwt: %s";

	private final JWSAlgorithm jwsAlgorithm;
	private final ConfigurableJWTProcessor<SecurityContext> jwtProcessor;
	private final RestOperationsResourceRetriever jwkSetRetriever = new RestOperationsResourceRetriever();

	/**
	 * Constructs a {@code NimbusJwtDecoderJwkSupport} using the provided parameters.
	 *
	 * @param jwkSetUrl the JSON Web Key (JWK) Set {@code URL}
	 */
	public NimbusJwtDecoderJwkSupport(String jwkSetUrl) {
		this(jwkSetUrl, JwsAlgorithms.RS256);
	}

	/**
	 * Constructs a {@code NimbusJwtDecoderJwkSupport} using the provided parameters.
	 *
	 * @param jwkSetUrl the JSON Web Key (JWK) Set {@code URL}
	 * @param jwsAlgorithm the JSON Web Algorithm (JWA) used for verifying the digital signatures
	 */
	public NimbusJwtDecoderJwkSupport(String jwkSetUrl, String jwsAlgorithm) {
		Assert.hasText(jwkSetUrl, "jwkSetUrl cannot be empty");
		Assert.hasText(jwsAlgorithm, "jwsAlgorithm cannot be empty");
		JWKSource jwkSource;
		try {
			jwkSource = new RemoteJWKSet(new URL(jwkSetUrl), this.jwkSetRetriever);
		} catch (MalformedURLException ex) {
			throw new IllegalArgumentException("Invalid JWK Set URL \"" + jwkSetUrl + "\" : " + ex.getMessage(), ex);
		}
		this.jwsAlgorithm = JWSAlgorithm.parse(jwsAlgorithm);
		JWSKeySelector<SecurityContext> jwsKeySelector =
			new JWSVerificationKeySelector<>(this.jwsAlgorithm, jwkSource);
		this.jwtProcessor = new DefaultJWTProcessor<>();
		this.jwtProcessor.setJWSKeySelector(jwsKeySelector);
	}

	@Override
	public Jwt decode(String token) throws JwtException {
		JWT jwt = this.parse(token);
		if (jwt instanceof SignedJWT) {
			return this.createJwt(token, jwt);
		}
		throw new JwtException("Unsupported algorithm of " + jwt.getHeader().getAlgorithm());
	}

	private JWT parse(String token) {
		try {
			return JWTParser.parse(token);
		} catch (Exception ex) {
			throw new JwtException(String.format(DECODING_ERROR_MESSAGE_TEMPLATE, ex.getMessage()), ex);
		}
	}

	private Jwt createJwt(String token, JWT parsedJwt) {
		Jwt jwt;

		try {
			// Verify the signature
			JWTClaimsSet jwtClaimsSet = this.jwtProcessor.process(parsedJwt, null);

			Instant expiresAt = null;
			if (jwtClaimsSet.getExpirationTime() != null) {
				expiresAt = jwtClaimsSet.getExpirationTime().toInstant();
			}
			Instant issuedAt = null;
			if (jwtClaimsSet.getIssueTime() != null) {
				issuedAt = jwtClaimsSet.getIssueTime().toInstant();
			} else if (expiresAt != null) {
				// Default to expiresAt - 1 second
				issuedAt = Instant.from(expiresAt).minusSeconds(1);
			}

			Map<String, Object> headers = new LinkedHashMap<>(parsedJwt.getHeader().toJSONObject());

			jwt = new Jwt(token, issuedAt, expiresAt, headers, jwtClaimsSet.getClaims());

		} catch (RemoteKeySourceException ex) {
			if (ex.getCause() instanceof ParseException) {
				throw new JwtException(String.format(DECODING_ERROR_MESSAGE_TEMPLATE, "Malformed Jwk set"));
			} else {
				throw new JwtException(String.format(DECODING_ERROR_MESSAGE_TEMPLATE, ex.getMessage()), ex);
			}
		} catch (Exception ex) {
			if (ex.getCause() instanceof ParseException) {
				throw new JwtException(String.format(DECODING_ERROR_MESSAGE_TEMPLATE, "Malformed payload"));
			} else {
				throw new JwtException(String.format(DECODING_ERROR_MESSAGE_TEMPLATE, ex.getMessage()), ex);
			}
		}

		return jwt;
	}

	/**
	 * Sets the {@link RestOperations} used when requesting the JSON Web Key (JWK) Set.
	 *
	 * @since 5.1
	 * @param restOperations the {@link RestOperations} used when requesting the JSON Web Key (JWK) Set
	 */
	public final void setRestOperations(RestOperations restOperations) {
		Assert.notNull(restOperations, "restOperations cannot be null");
		this.jwkSetRetriever.restOperations = restOperations;
	}

	private static class RestOperationsResourceRetriever implements ResourceRetriever {
		private RestOperations restOperations = new RestTemplate();

		@Override
		public Resource retrieveResource(URL url) throws IOException {
			HttpHeaders headers = new HttpHeaders();
			headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON_UTF8));

			ResponseEntity<String> response;
			try {
				RequestEntity<Void> request = new RequestEntity<>(headers, HttpMethod.GET, url.toURI());
				response = this.restOperations.exchange(request, String.class);
			} catch (Exception ex) {
				throw new IOException(ex);
			}

			if (response.getStatusCodeValue() != 200) {
				throw new IOException(response.toString());
			}

			return new Resource(response.getBody(), "UTF-8");
		}
	}
}
