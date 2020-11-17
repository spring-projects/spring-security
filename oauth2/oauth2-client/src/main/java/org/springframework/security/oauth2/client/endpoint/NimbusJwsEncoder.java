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

package org.springframework.security.oauth2.client.endpoint;

import java.net.URI;
import java.net.URL;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.factories.DefaultJWSSignerFactory;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.produce.JWSSignerFactory;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

/*
 * NOTE:
 * This originated in gh-9208 (JwtEncoder),
 * which is required to realize the feature in gh-8175 (JWT Client Authentication).
 * However, we decided not to merge gh-9208 as part of the 5.5.0 release
 * and instead packaged it up privately with the gh-8175 feature.
 * We MAY merge gh-9208 in a later release but that is yet to be determined.
 *
 * gh-9208 Introduce JwtEncoder
 * https://github.com/spring-projects/spring-security/pull/9208
 *
 * gh-8175 Support JWT for Client Authentication
 * https://github.com/spring-projects/spring-security/issues/8175
 */

/**
 * A JWT encoder that encodes a JSON Web Token (JWT) using the JSON Web Signature (JWS)
 * Compact Serialization format. The private/secret key used for signing the JWS is
 * supplied by the {@code com.nimbusds.jose.jwk.source.JWKSource} provided via the
 * constructor.
 *
 * <p>
 * <b>NOTE:</b> This implementation uses the Nimbus JOSE + JWT SDK.
 *
 * @author Joe Grandja
 * @since 5.5
 * @see com.nimbusds.jose.jwk.source.JWKSource
 * @see com.nimbusds.jose.jwk.JWK
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7519">JSON Web Token
 * (JWT)</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7515">JSON Web Signature
 * (JWS)</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7515#section-3.1">JWS
 * Compact Serialization</a>
 * @see <a target="_blank" href="https://connect2id.com/products/nimbus-jose-jwt">Nimbus
 * JOSE + JWT SDK</a>
 */
final class NimbusJwsEncoder {

	private static final String ENCODING_ERROR_MESSAGE_TEMPLATE = "An error occurred while attempting to encode the Jwt: %s";

	private static final JWSSignerFactory JWS_SIGNER_FACTORY = new DefaultJWSSignerFactory();

	private final Map<JWK, JWSSigner> jwsSigners = new ConcurrentHashMap<>();

	private final JWKSource<SecurityContext> jwkSource;

	/**
	 * Constructs a {@code NimbusJwsEncoder} using the provided parameters.
	 * @param jwkSource the {@code com.nimbusds.jose.jwk.source.JWKSource}
	 */
	NimbusJwsEncoder(JWKSource<SecurityContext> jwkSource) {
		Assert.notNull(jwkSource, "jwkSource cannot be null");
		this.jwkSource = jwkSource;
	}

	Jwt encode(JoseHeader headers, JwtClaimsSet claims) throws JwtEncodingException {
		Assert.notNull(headers, "headers cannot be null");
		Assert.notNull(claims, "claims cannot be null");

		JWK jwk = selectJwk(headers);
		headers = addKeyIdentifierHeadersIfNecessary(headers, jwk);

		String jws = serialize(headers, claims, jwk);

		return new Jwt(jws, claims.getIssuedAt(), claims.getExpiresAt(), headers.getHeaders(), claims.getClaims());
	}

	private JWK selectJwk(JoseHeader headers) {
		List<JWK> jwks;
		try {
			JWKSelector jwkSelector = new JWKSelector(createJwkMatcher(headers));
			jwks = this.jwkSource.get(jwkSelector, null);
		}
		catch (Exception ex) {
			throw new JwtEncodingException(String.format(ENCODING_ERROR_MESSAGE_TEMPLATE,
					"Failed to select a JWK signing key -> " + ex.getMessage()), ex);
		}

		if (jwks.size() > 1) {
			throw new JwtEncodingException(String.format(ENCODING_ERROR_MESSAGE_TEMPLATE,
					"Found multiple JWK signing keys for algorithm '" + headers.getAlgorithm().getName() + "'"));
		}

		if (jwks.isEmpty()) {
			throw new JwtEncodingException(
					String.format(ENCODING_ERROR_MESSAGE_TEMPLATE, "Failed to select a JWK signing key"));
		}

		return jwks.get(0);
	}

	private String serialize(JoseHeader headers, JwtClaimsSet claims, JWK jwk) {
		JWSHeader jwsHeader = convert(headers);
		JWTClaimsSet jwtClaimsSet = convert(claims);

		JWSSigner jwsSigner = this.jwsSigners.computeIfAbsent(jwk, NimbusJwsEncoder::createSigner);

		SignedJWT signedJwt = new SignedJWT(jwsHeader, jwtClaimsSet);
		try {
			signedJwt.sign(jwsSigner);
		}
		catch (JOSEException ex) {
			throw new JwtEncodingException(
					String.format(ENCODING_ERROR_MESSAGE_TEMPLATE, "Failed to sign the JWT -> " + ex.getMessage()), ex);
		}
		return signedJwt.serialize();
	}

	private static JWKMatcher createJwkMatcher(JoseHeader headers) {
		JWSAlgorithm jwsAlgorithm = JWSAlgorithm.parse(headers.getAlgorithm().getName());

		if (JWSAlgorithm.Family.RSA.contains(jwsAlgorithm) || JWSAlgorithm.Family.EC.contains(jwsAlgorithm)) {
			// @formatter:off
			return new JWKMatcher.Builder()
					.keyType(KeyType.forAlgorithm(jwsAlgorithm))
					.keyID(headers.getKeyId())
					.keyUses(KeyUse.SIGNATURE, null)
					.algorithms(jwsAlgorithm, null)
					.x509CertSHA256Thumbprint(Base64URL.from(headers.getX509SHA256Thumbprint()))
					.build();
			// @formatter:on
		}
		else if (JWSAlgorithm.Family.HMAC_SHA.contains(jwsAlgorithm)) {
			// @formatter:off
			return new JWKMatcher.Builder()
					.keyType(KeyType.forAlgorithm(jwsAlgorithm))
					.keyID(headers.getKeyId())
					.privateOnly(true)
					.algorithms(jwsAlgorithm, null)
					.build();
			// @formatter:on
		}

		return null;
	}

	private static JoseHeader addKeyIdentifierHeadersIfNecessary(JoseHeader headers, JWK jwk) {
		// Check if headers have already been added
		if (StringUtils.hasText(headers.getKeyId()) && StringUtils.hasText(headers.getX509SHA256Thumbprint())) {
			return headers;
		}
		// Check if headers can be added from JWK
		if (!StringUtils.hasText(jwk.getKeyID()) && jwk.getX509CertSHA256Thumbprint() == null) {
			return headers;
		}

		JoseHeader.Builder headersBuilder = JoseHeader.from(headers);
		if (!StringUtils.hasText(headers.getKeyId()) && StringUtils.hasText(jwk.getKeyID())) {
			headersBuilder.keyId(jwk.getKeyID());
		}
		if (!StringUtils.hasText(headers.getX509SHA256Thumbprint()) && jwk.getX509CertSHA256Thumbprint() != null) {
			headersBuilder.x509SHA256Thumbprint(jwk.getX509CertSHA256Thumbprint().toString());
		}

		return headersBuilder.build();
	}

	private static JWSSigner createSigner(JWK jwk) {
		try {
			return JWS_SIGNER_FACTORY.createJWSSigner(jwk);
		}
		catch (JOSEException ex) {
			throw new JwtEncodingException(String.format(ENCODING_ERROR_MESSAGE_TEMPLATE,
					"Failed to create a JWS Signer -> " + ex.getMessage()), ex);
		}
	}

	private static JWSHeader convert(JoseHeader headers) {
		JWSHeader.Builder builder = new JWSHeader.Builder(JWSAlgorithm.parse(headers.getAlgorithm().getName()));

		if (headers.getJwkSetUrl() != null) {
			builder.jwkURL(convertAsURI(JoseHeaderNames.JKU, headers.getJwkSetUrl()));
		}

		Map<String, Object> jwk = headers.getJwk();
		if (!CollectionUtils.isEmpty(jwk)) {
			try {
				builder.jwk(JWK.parse(jwk));
			}
			catch (Exception ex) {
				throw new JwtEncodingException(String.format(ENCODING_ERROR_MESSAGE_TEMPLATE,
						"Unable to convert '" + JoseHeaderNames.JWK + "' JOSE header"), ex);
			}
		}

		String keyId = headers.getKeyId();
		if (StringUtils.hasText(keyId)) {
			builder.keyID(keyId);
		}

		if (headers.getX509Url() != null) {
			builder.x509CertURL(convertAsURI(JoseHeaderNames.X5U, headers.getX509Url()));
		}

		List<String> x509CertificateChain = headers.getX509CertificateChain();
		if (!CollectionUtils.isEmpty(x509CertificateChain)) {
			List<Base64> x5cList = new ArrayList<>();
			x509CertificateChain.forEach((x5c) -> x5cList.add(new Base64(x5c)));
			if (!x5cList.isEmpty()) {
				builder.x509CertChain(x5cList);
			}
		}

		String x509SHA1Thumbprint = headers.getX509SHA1Thumbprint();
		if (StringUtils.hasText(x509SHA1Thumbprint)) {
			builder.x509CertThumbprint(new Base64URL(x509SHA1Thumbprint));
		}

		String x509SHA256Thumbprint = headers.getX509SHA256Thumbprint();
		if (StringUtils.hasText(x509SHA256Thumbprint)) {
			builder.x509CertSHA256Thumbprint(new Base64URL(x509SHA256Thumbprint));
		}

		String type = headers.getType();
		if (StringUtils.hasText(type)) {
			builder.type(new JOSEObjectType(type));
		}

		String contentType = headers.getContentType();
		if (StringUtils.hasText(contentType)) {
			builder.contentType(contentType);
		}

		Set<String> critical = headers.getCritical();
		if (!CollectionUtils.isEmpty(critical)) {
			builder.criticalParams(critical);
		}

		Map<String, Object> customHeaders = new HashMap<>();
		headers.getHeaders().forEach((name, value) -> {
			if (!JWSHeader.getRegisteredParameterNames().contains(name)) {
				customHeaders.put(name, value);
			}
		});
		if (!customHeaders.isEmpty()) {
			builder.customParams(customHeaders);
		}

		return builder.build();
	}

	private static JWTClaimsSet convert(JwtClaimsSet claims) {
		JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();

		// NOTE: The value of the 'iss' claim is a String or URL (StringOrURI).
		Object issuer = claims.getClaim(JwtClaimNames.ISS);
		if (issuer != null) {
			builder.issuer(issuer.toString());
		}

		String subject = claims.getSubject();
		if (StringUtils.hasText(subject)) {
			builder.subject(subject);
		}

		List<String> audience = claims.getAudience();
		if (!CollectionUtils.isEmpty(audience)) {
			builder.audience(audience);
		}

		Instant expiresAt = claims.getExpiresAt();
		if (expiresAt != null) {
			builder.expirationTime(Date.from(expiresAt));
		}

		Instant notBefore = claims.getNotBefore();
		if (notBefore != null) {
			builder.notBeforeTime(Date.from(notBefore));
		}

		Instant issuedAt = claims.getIssuedAt();
		if (issuedAt != null) {
			builder.issueTime(Date.from(issuedAt));
		}

		String jwtId = claims.getId();
		if (StringUtils.hasText(jwtId)) {
			builder.jwtID(jwtId);
		}

		Map<String, Object> customClaims = new HashMap<>();
		claims.getClaims().forEach((name, value) -> {
			if (!JWTClaimsSet.getRegisteredNames().contains(name)) {
				customClaims.put(name, value);
			}
		});
		if (!customClaims.isEmpty()) {
			customClaims.forEach(builder::claim);
		}

		return builder.build();
	}

	private static URI convertAsURI(String header, URL url) {
		try {
			return url.toURI();
		}
		catch (Exception ex) {
			throw new JwtEncodingException(String.format(ENCODING_ERROR_MESSAGE_TEMPLATE,
					"Unable to convert '" + header + "' JOSE header to a URI"), ex);
		}
	}

}
