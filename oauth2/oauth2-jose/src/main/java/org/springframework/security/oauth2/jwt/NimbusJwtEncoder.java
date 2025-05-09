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

import java.net.URI;
import java.net.URL;
import java.security.KeyPair;
import java.security.interfaces.ECPublicKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import javax.crypto.SecretKey;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.factories.DefaultJWSSignerFactory;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.produce.JWSSignerFactory;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

/**
 * An implementation of a {@link JwtEncoder} that encodes a JSON Web Token (JWT) using the
 * JSON Web Signature (JWS) Compact Serialization format. The private/secret key used for
 * signing the JWS is supplied by the {@code com.nimbusds.jose.jwk.source.JWKSource}
 * provided via the constructor.
 *
 * <p>
 * <b>NOTE:</b> This implementation uses the Nimbus JOSE + JWT SDK.
 *
 * @author Joe Grandja
 * @since 5.6
 * @see JwtEncoder
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
public final class NimbusJwtEncoder implements JwtEncoder {

	private static final String ENCODING_ERROR_MESSAGE_TEMPLATE = "An error occurred while attempting to encode the Jwt: %s";

	private static final JwsHeader DEFAULT_JWS_HEADER = JwsHeader.with(SignatureAlgorithm.RS256).build();

	private static final JWSSignerFactory JWS_SIGNER_FACTORY = new DefaultJWSSignerFactory();

	private JwsHeader jwsHeader;

	private final Map<JWK, JWSSigner> jwsSigners = new ConcurrentHashMap<>();

	private final JWKSource<SecurityContext> jwkSource;

	private Converter<List<JWK>, JWK> jwkSelector = (jwks) -> {
		throw new JwtEncodingException(
				String.format(
						"Failed to select a key since there are multiple for the signing algorithm [%s]; "
								+ "please specify a selector in NimbusJwsEncoder#setJwkSelector",
						jwks.get(0).getAlgorithm()));
	};

	/**
	 * Constructs a {@code NimbusJwtEncoder} using the provided parameters.
	 * @param jwkSource the {@code com.nimbusds.jose.jwk.source.JWKSource}
	 */
	public NimbusJwtEncoder(JWKSource<SecurityContext> jwkSource) {
		Assert.notNull(jwkSource, "jwkSource cannot be null");
		this.jwkSource = jwkSource;
	}

	/**
	 * Use this strategy to reduce the list of matching JWKs when there is more than one.
	 * <p>
	 * For example, you can call {@code setJwkSelector(List::getFirst)} in order to have
	 * this encoder select the first match.
	 *
	 * <p>
	 * By default, the class with throw an exception.
	 * @since 6.5
	 */
	public void setJwkSelector(Converter<List<JWK>, JWK> jwkSelector) {
		Assert.notNull(jwkSelector, "jwkSelector cannot be null");
		this.jwkSelector = jwkSelector;
	}

	public void setJwsHeader(JwsHeader jwsHeader) {
		this.jwsHeader = jwsHeader;
	}

	@Override
	public Jwt encode(JwtEncoderParameters parameters) throws JwtEncodingException {
		Assert.notNull(parameters, "parameters cannot be null");

		JwsHeader headers = parameters.getJwsHeader();
		headers = (headers != null) ? headers : (this.jwsHeader != null) ? this.jwsHeader : DEFAULT_JWS_HEADER;
		JwtClaimsSet claims = parameters.getClaims();

		JWK jwk = selectJwk(headers);
		headers = addKeyIdentifierHeadersIfNecessary(headers, jwk);

		String jws = serialize(headers, claims, jwk);

		return new Jwt(jws, claims.getIssuedAt(), claims.getExpiresAt(), headers.getHeaders(), claims.getClaims());
	}

	private JWK selectJwk(JwsHeader headers) {
		List<JWK> jwks;
		try {
			JWKSelector jwkSelector = new JWKSelector(createJwkMatcher(headers));
			jwks = this.jwkSource.get(jwkSelector, null);
		}
		catch (Exception ex) {
			throw new JwtEncodingException(String.format(ENCODING_ERROR_MESSAGE_TEMPLATE,
					"Failed to select a JWK signing key -> " + ex.getMessage()), ex);
		}
		if (jwks.isEmpty()) {
			throw new JwtEncodingException(
					String.format(ENCODING_ERROR_MESSAGE_TEMPLATE, "Failed to select a JWK signing key"));
		}
		if (jwks.size() == 1) {
			return jwks.get(0);
		}
		return this.jwkSelector.convert(jwks);
	}

	private String serialize(JwsHeader headers, JwtClaimsSet claims, JWK jwk) {
		JWSHeader jwsHeader = convert(headers);
		JWTClaimsSet jwtClaimsSet = convert(claims);

		JWSSigner jwsSigner = this.jwsSigners.computeIfAbsent(jwk, NimbusJwtEncoder::createSigner);

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

	private static JWKMatcher createJwkMatcher(JwsHeader headers) {
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

	private static JwsHeader addKeyIdentifierHeadersIfNecessary(JwsHeader headers, JWK jwk) {
		// Check if headers have already been added
		if (StringUtils.hasText(headers.getKeyId()) && StringUtils.hasText(headers.getX509SHA256Thumbprint())) {
			return headers;
		}
		// Check if headers can be added from JWK
		if (!StringUtils.hasText(jwk.getKeyID()) && jwk.getX509CertSHA256Thumbprint() == null) {
			return headers;
		}

		JwsHeader.Builder headersBuilder = JwsHeader.from(headers);
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

	private static JWSHeader convert(JwsHeader headers) {
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

	/**
	 * Creates a builder for constructing a {@link NimbusJwtEncoder} using the provided
	 * {@link SecretKey}.
	 * @param secretKey the {@link SecretKey} to use for signing JWTs
	 * @return a {@link SecretKeyJwtEncoderBuilder} for further configuration
	 * @since 7.0
	 */
	public static SecretKeyJwtEncoderBuilder withSecretKey(SecretKey secretKey) {
		Assert.notNull(secretKey, "secretKey cannot be null");
		return new SecretKeyJwtEncoderBuilder(secretKey);
	}

	/**
	 * Creates a builder for constructing a {@link NimbusJwtEncoder} using the provided
	 * {@link KeyPair}. The key pair must contain either an {@link RSAKey} or an
	 * {@link ECKey}.
	 * @param keyPair the {@link KeyPair} to use for signing JWTs
	 * @return a {@link KeyPairJwtEncoderBuilder} for further configuration
	 * @since 7.0
	 */
	public static KeyPairJwtEncoderBuilder withKeyPair(KeyPair keyPair) {
		Assert.isTrue(keyPair != null && keyPair.getPrivate() != null && keyPair.getPublic() != null,
				"keyPair, its private key, and public key must not be null");
		Assert.isTrue(
				keyPair.getPrivate() instanceof java.security.interfaces.RSAKey
						|| keyPair.getPrivate() instanceof java.security.interfaces.ECKey,
				"keyPair must be an RSAKey or an ECKey");
		if (keyPair.getPrivate() instanceof java.security.interfaces.RSAKey) {
			return new RsaKeyPairJwtEncoderBuilder(keyPair);
		}
		if (keyPair.getPrivate() instanceof java.security.interfaces.ECKey) {
			return new EcKeyPairJwtEncoderBuilder(keyPair);
		}
		throw new IllegalArgumentException("keyPair must be an RSAKey or an ECKey");
	}

	/**
	 * A builder for creating {@link NimbusJwtEncoder} instances configured with a
	 * {@link SecretKey}.
	 *
	 * @since 7.0
	 */
	public static final class SecretKeyJwtEncoderBuilder {

		private final SecretKey secretKey;

		private String keyId;

		private JWSAlgorithm jwsAlgorithm = JWSAlgorithm.HS256;

		private SecretKeyJwtEncoderBuilder(SecretKey secretKey) {
			this.secretKey = secretKey;
		}

		/**
		 * Sets the JWS algorithm to use for signing. Defaults to
		 * {@link JWSAlgorithm#HS256}. Must be an HMAC-based algorithm (HS256, HS384, or
		 * HS512).
		 * @param macAlgorithm the {@link MacAlgorithm} to use
		 * @return this builder instance for method chaining
		 */
		public SecretKeyJwtEncoderBuilder macAlgorithm(MacAlgorithm macAlgorithm) {
			Assert.notNull(macAlgorithm, "macAlgorithm cannot be null");
			Assert.state(JWSAlgorithm.Family.HMAC_SHA.contains(this.jwsAlgorithm),
					() -> "The algorithm '" + this.jwsAlgorithm + "' is not compatible with a SecretKey. "
							+ "Please use one of the HS256, HS384, or HS512 algorithms.");

			this.jwsAlgorithm = JWSAlgorithm.parse(macAlgorithm.getName());
			return this;
		}

		/**
		 * Sets the key ID ({@code kid}) to be included in the JWK and potentially the JWS
		 * header.
		 * @param keyId the key identifier
		 * @return this builder instance for method chaining
		 */
		public SecretKeyJwtEncoderBuilder keyId(String keyId) {
			this.keyId = keyId;
			return this;
		}

		/**
		 * Builds the {@link NimbusJwtEncoder} instance.
		 * @return the configured {@link NimbusJwtEncoder}
		 * @throws IllegalStateException if the configured JWS algorithm is not compatible
		 * with a {@link SecretKey}.
		 */
		public NimbusJwtEncoder build() {
			this.jwsAlgorithm = (this.jwsAlgorithm != null) ? this.jwsAlgorithm : JWSAlgorithm.HS256;

			OctetSequenceKey.Builder builder = new OctetSequenceKey.Builder(this.secretKey).keyUse(KeyUse.SIGNATURE)
				.algorithm(this.jwsAlgorithm)
				.keyID(this.keyId);

			OctetSequenceKey jwk = builder.build();
			JWKSource<SecurityContext> jwkSource = new ImmutableJWKSet<>(new JWKSet(jwk));
			NimbusJwtEncoder encoder = new NimbusJwtEncoder(jwkSource);
			encoder.setJwsHeader(JwsHeader.with(MacAlgorithm.from(this.jwsAlgorithm.getName())).build());
			return encoder;
		}

	}

	/**
	 * A builder for creating {@link NimbusJwtEncoder} instances configured with a
	 * {@link KeyPair}.
	 *
	 * @since 7.0
	 */
	public abstract static class KeyPairJwtEncoderBuilder {

		private final KeyPair keyPair;

		private String keyId;

		private JWSAlgorithm jwsAlgorithm;

		private KeyPairJwtEncoderBuilder(KeyPair keyPair) {
			this.keyPair = keyPair;
		}

		/**
		 * Sets the JWS algorithm to use for signing. Must be compatible with the key type
		 * (RSA or EC). If not set, a default algorithm will be chosen based on the key
		 * type (e.g., RS256 for RSA, ES256 for EC).
		 * @param signatureAlgorithm the {@link SignatureAlgorithm} to use
		 * @return this builder instance for method chaining
		 */
		public KeyPairJwtEncoderBuilder signatureAlgorithm(SignatureAlgorithm signatureAlgorithm) {
			Assert.notNull(signatureAlgorithm, "signatureAlgorithm cannot be null");
			this.jwsAlgorithm = JWSAlgorithm.parse(signatureAlgorithm.getName());
			return this;
		}

		/**
		 * Sets the key ID ({@code kid}) to be included in the JWK and potentially the JWS
		 * header.
		 * @param keyId the key identifier
		 * @return this builder instance for method chaining
		 */
		public KeyPairJwtEncoderBuilder keyId(String keyId) {
			this.keyId = keyId;
			return this;
		}

		/**
		 * Builds the {@link NimbusJwtEncoder} instance.
		 * @return the configured {@link NimbusJwtEncoder}
		 * @throws IllegalStateException if the key type is unsupported or the configured
		 * JWS algorithm is not compatible with the key type.
		 * @throws JwtEncodingException if the key is invalid (e.g., EC key with unknown
		 * curve)
		 */
		public NimbusJwtEncoder build() {
			this.keyId = (this.keyId != null) ? this.keyId : UUID.randomUUID().toString();
			JWK jwk = buildJwk();
			JWKSource<SecurityContext> jwkSource = new ImmutableJWKSet<>(new JWKSet(jwk));
			NimbusJwtEncoder encoder = new NimbusJwtEncoder(jwkSource);
			JwsHeader jwsHeader = JwsHeader.with(SignatureAlgorithm.from(this.jwsAlgorithm.getName()))
				.keyId(jwk.getKeyID())
				.build();
			encoder.setJwsHeader(jwsHeader);
			return encoder;
		}

		protected abstract JWK buildJwk();

	}

	/**
	 * A builder for creating {@link NimbusJwtEncoder} instances configured with a
	 * {@link KeyPair}.
	 *
	 * @since 7.0
	 */
	public static final class RsaKeyPairJwtEncoderBuilder extends KeyPairJwtEncoderBuilder {

		private RsaKeyPairJwtEncoderBuilder(KeyPair keyPair) {
			super(keyPair);
		}

		@Override
		protected JWK buildJwk() {
			if (super.jwsAlgorithm == null) {
				super.jwsAlgorithm = JWSAlgorithm.RS256;
			}
			Assert.state(JWSAlgorithm.Family.RSA.contains(super.jwsAlgorithm),
					() -> "The algorithm '" + super.jwsAlgorithm + "' is not compatible with an RSAKey. "
							+ "Please use one of the RS256, RS384, RS512, PS256, PS384, or PS512 algorithms.");

			RSAKey.Builder builder = new RSAKey.Builder(
					(java.security.interfaces.RSAPublicKey) super.keyPair.getPublic())
				.privateKey(super.keyPair.getPrivate())
				.keyID(super.keyId)
				.keyUse(KeyUse.SIGNATURE)
				.algorithm(super.jwsAlgorithm);
			return builder.build();
		}

	}

	/**
	 * A builder for creating {@link NimbusJwtEncoder} instances configured with a
	 * {@link KeyPair}.
	 *
	 * @since 7.0
	 */
	public static final class EcKeyPairJwtEncoderBuilder extends KeyPairJwtEncoderBuilder {

		private EcKeyPairJwtEncoderBuilder(KeyPair keyPair) {
			super(keyPair);
		}

		@Override
		protected JWK buildJwk() {
			if (super.jwsAlgorithm == null) {
				super.jwsAlgorithm = JWSAlgorithm.ES256;
			}
			Assert.state(JWSAlgorithm.Family.EC.contains(super.jwsAlgorithm),
					() -> "The algorithm '" + super.jwsAlgorithm + "' is not compatible with an ECKey. "
							+ "Please use one of the ES256, ES384, or ES512 algorithms.");

			ECPublicKey publicKey = (ECPublicKey) super.keyPair.getPublic();
			Curve curve = Curve.forECParameterSpec(publicKey.getParams());
			if (curve == null) {
				throw new JwtEncodingException("Unable to determine Curve for EC public key.");
			}

			com.nimbusds.jose.jwk.ECKey.Builder builder = new com.nimbusds.jose.jwk.ECKey.Builder(curve, publicKey)
				.privateKey(super.keyPair.getPrivate())
				.keyUse(KeyUse.SIGNATURE)
				.keyID(super.keyId)
				.algorithm(super.jwsAlgorithm);

			try {
				return builder.build();
			}
			catch (IllegalStateException ex) {
				throw new IllegalArgumentException("Failed to build ECKey: " + ex.getMessage(), ex);
			}
		}

	}

}
