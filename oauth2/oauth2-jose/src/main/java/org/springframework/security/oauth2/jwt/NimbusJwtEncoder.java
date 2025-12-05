/*
 * Copyright 2004-present the original author or authors.
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
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;

import javax.crypto.SecretKey;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.MACSigner;
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
import org.springframework.security.oauth2.jose.jws.JwsAlgorithm;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;
import org.springframework.util.function.ThrowingBiFunction;
import org.springframework.util.function.ThrowingFunction;

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
 * @author Josh Cummings
 * @author Suraj Bhadrike
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

	private final JwsHeader defaultJwsHeader;

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
		this.defaultJwsHeader = DEFAULT_JWS_HEADER;
		Assert.notNull(jwkSource, "jwkSource cannot be null");
		this.jwkSource = jwkSource;
	}

	private NimbusJwtEncoder(JWK jwk) {
		Assert.notNull(jwk, "jwk cannot be null");
		this.jwkSource = new ImmutableJWKSet<>(new JWKSet(jwk));
		JwsAlgorithm algorithm = SignatureAlgorithm.from(jwk.getAlgorithm().getName());
		if (algorithm == null) {
			algorithm = MacAlgorithm.from(jwk.getAlgorithm().getName());
		}
		Assert.notNull(algorithm, "Failed to derive supported algorithm from " + jwk.getAlgorithm());
		JwsHeader.Builder builder = JwsHeader.with(algorithm).type("JWT").keyId(jwk.getKeyID());
		URI x509Url = jwk.getX509CertURL();
		if (x509Url != null) {
			builder.x509Url(jwk.getX509CertURL().toASCIIString());
		}
		List<Base64> certs = jwk.getX509CertChain();
		if (certs != null) {
			builder.x509CertificateChain(certs.stream().map(Base64::toString).toList());
		}
		Base64URL thumbprint = jwk.getX509CertSHA256Thumbprint();
		if (thumbprint != null) {
			builder.x509SHA256Thumbprint(thumbprint.toString());
		}
		this.defaultJwsHeader = builder.build();
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

	@Override
	public Jwt encode(JwtEncoderParameters parameters) throws JwtEncodingException {
		Assert.notNull(parameters, "parameters cannot be null");

		JwsHeader headers = parameters.getJwsHeader();
		if (headers == null) {
			headers = this.defaultJwsHeader;
		}

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
	 * @param publicKey the {@link RSAPublicKey} and @Param privateKey the
	 * {@link RSAPrivateKey} to use for signing JWTs
	 * @return a {@link RsaKeyPairJwtEncoderBuilder}
	 * @since 7.0
	 */
	public static RsaKeyPairJwtEncoderBuilder withKeyPair(RSAPublicKey publicKey, RSAPrivateKey privateKey) {
		return new RsaKeyPairJwtEncoderBuilder(publicKey, privateKey);
	}

	/**
	 * Creates a builder for constructing a {@link NimbusJwtEncoder} using the provided
	 * @param publicKey the {@link ECPublicKey} and @param privateKey the
	 * {@link ECPrivateKey} to use for signing JWTs
	 * @return a {@link EcKeyPairJwtEncoderBuilder}
	 * @since 7.0
	 */
	public static EcKeyPairJwtEncoderBuilder withKeyPair(ECPublicKey publicKey, ECPrivateKey privateKey) {
		return new EcKeyPairJwtEncoderBuilder(publicKey, privateKey);
	}

	/**
	 * Creates a builder for constructing a {@link NimbusJwtEncoder} using the provided
	 * @param secretKey
	 * @return a {@link SecretKeyJwtEncoderBuilder} for configuring the {@link JWK}
	 * @since 7.0
	 */
	public static SecretKeyJwtEncoderBuilder withSecretKey(SecretKey secretKey) {
		return new SecretKeyJwtEncoderBuilder(secretKey);
	}

	/**
	 * A builder for creating {@link NimbusJwtEncoder} instances configured with a
	 * {@link SecretKey}.
	 *
	 * @since 7.0
	 */
	public static final class SecretKeyJwtEncoderBuilder {

		private static final ThrowingFunction<SecretKey, OctetSequenceKey.Builder> defaultJwk = JWKS::signing;

		private final OctetSequenceKey.Builder builder;

		private final Set<JWSAlgorithm> allowedAlgorithms;

		private SecretKeyJwtEncoderBuilder(SecretKey secretKey) {
			Assert.notNull(secretKey, "secretKey cannot be null");
			Set<JWSAlgorithm> allowedAlgorithms = computeAllowedAlgorithms(secretKey);
			Assert.notEmpty(allowedAlgorithms,
					"This key is too small for any standard JWK symmetric signing algorithm");
			this.allowedAlgorithms = allowedAlgorithms;
			this.builder = defaultJwk.apply(secretKey, IllegalArgumentException::new)
				.algorithm(this.allowedAlgorithms.iterator().next());
		}

		private Set<JWSAlgorithm> computeAllowedAlgorithms(SecretKey secretKey) {
			try {
				return new MACSigner(secretKey).supportedJWSAlgorithms();
			}
			catch (JOSEException ex) {
				throw new IllegalArgumentException(ex);
			}
		}

		/**
		 * Sets the JWS algorithm to use for signing. Defaults to
		 * {@link JWSAlgorithm#HS256}. Must be an HMAC-based algorithm (HS256, HS384, or
		 * HS512).
		 * @param macAlgorithm the {@link MacAlgorithm} to use
		 * @return this builder instance for method chaining
		 */
		public SecretKeyJwtEncoderBuilder algorithm(MacAlgorithm macAlgorithm) {
			Assert.notNull(macAlgorithm, "macAlgorithm cannot be null");
			JWSAlgorithm jws = JWSAlgorithm.parse(macAlgorithm.getName());
			Assert.isTrue(this.allowedAlgorithms.contains(jws), String
				.format("This key can only support " + "the following algorithms: [%s]", this.allowedAlgorithms));
			this.builder.algorithm(JWSAlgorithm.parse(macAlgorithm.getName()));
			return this;
		}

		/**
		 * Post-process the {@link JWK} using the given {@link Consumer}. For example, you
		 * may use this to override the default {@code kid}
		 * @param jwkPostProcessor the post-processor to use
		 * @return this builder instance for method chaining
		 */
		public SecretKeyJwtEncoderBuilder jwkPostProcessor(Consumer<OctetSequenceKey.Builder> jwkPostProcessor) {
			Assert.notNull(jwkPostProcessor, "jwkPostProcessor cannot be null");
			jwkPostProcessor.accept(this.builder);
			return this;
		}

		/**
		 * Builds the {@link NimbusJwtEncoder} instance.
		 * @return the configured {@link NimbusJwtEncoder}
		 * @throws IllegalStateException if the configured JWS algorithm is not compatible
		 * with a {@link SecretKey}.
		 */
		public NimbusJwtEncoder build() {
			return new NimbusJwtEncoder(this.builder.build());
		}

	}

	/**
	 * A builder for creating {@link NimbusJwtEncoder} instances configured with a
	 * {@link KeyPair}.
	 *
	 * @since 7.0
	 */
	public static final class RsaKeyPairJwtEncoderBuilder {

		private static final ThrowingBiFunction<RSAPublicKey, RSAPrivateKey, RSAKey.Builder> defaultKid = JWKS::signingWithRsa;

		private final RSAKey.Builder builder;

		private RsaKeyPairJwtEncoderBuilder(RSAPublicKey publicKey, RSAPrivateKey privateKey) {
			Assert.notNull(publicKey, "publicKey cannot be null");
			Assert.notNull(privateKey, "privateKey cannot be null");
			this.builder = defaultKid.apply(publicKey, privateKey);
		}

		/**
		 * Sets the JWS algorithm to use for signing. Defaults to
		 * {@link SignatureAlgorithm#RS256}. Must be an RSA-based algorithm
		 * @param signatureAlgorithm the {@link SignatureAlgorithm} to use
		 * @return this builder instance for method chaining
		 */
		public RsaKeyPairJwtEncoderBuilder algorithm(SignatureAlgorithm signatureAlgorithm) {
			Assert.notNull(signatureAlgorithm, "signatureAlgorithm cannot be null");
			this.builder.algorithm(JWSAlgorithm.parse(signatureAlgorithm.getName()));
			return this;
		}

		/**
		 * Add commentMore actions Post-process the {@link JWK} using the given
		 * {@link Consumer}. For example, you may use this to override the default
		 * {@code kid}
		 * @param jwkPostProcessor the post-processor to use
		 * @return this builder instance for method chaining
		 */
		public RsaKeyPairJwtEncoderBuilder jwkPostProcessor(Consumer<RSAKey.Builder> jwkPostProcessor) {
			Assert.notNull(jwkPostProcessor, "jwkPostProcessor cannot be null");
			jwkPostProcessor.accept(this.builder);
			return this;
		}

		/**
		 * Builds the {@link NimbusJwtEncoder} instance.
		 * @return the configured {@link NimbusJwtEncoder}
		 */
		public NimbusJwtEncoder build() {
			return new NimbusJwtEncoder(this.builder.build());
		}

	}

	/**
	 * A builder for creating {@link NimbusJwtEncoder} instances configured with a
	 * {@link ECPublicKey} and {@link ECPrivateKey}.
	 * <p>
	 * This builder is used to create a {@link NimbusJwtEncoder}
	 *
	 * @since 7.0
	 */
	public static final class EcKeyPairJwtEncoderBuilder {

		private static final ThrowingBiFunction<ECPublicKey, ECPrivateKey, ECKey.Builder> defaultKid = JWKS::signingWithEc;

		private final ECKey.Builder builder;

		private EcKeyPairJwtEncoderBuilder(ECPublicKey publicKey, ECPrivateKey privateKey) {
			Assert.notNull(publicKey, "publicKey cannot be null");
			Assert.notNull(privateKey, "privateKey cannot be null");
			Curve curve = Curve.forECParameterSpec(publicKey.getParams());
			Assert.notNull(curve, "Unable to determine Curve for EC public key.");
			this.builder = defaultKid.apply(publicKey, privateKey);
		}

		/**
		 * Post-process the {@link JWK} using the given {@link Consumer}. For example, you
		 * may use this to override the default {@code kid}
		 * @param jwkPostProcessor the post-processor to use
		 * @return this builder instance for method chaining
		 */
		public EcKeyPairJwtEncoderBuilder jwkPostProcessor(Consumer<ECKey.Builder> jwkPostProcessor) {
			Assert.notNull(jwkPostProcessor, "jwkPostProcessor cannot be null");
			jwkPostProcessor.accept(this.builder);
			return this;
		}

		/**
		 * Builds the {@link NimbusJwtEncoder} instance.
		 * @return the configured {@link NimbusJwtEncoder}
		 */
		public NimbusJwtEncoder build() {
			return new NimbusJwtEncoder(this.builder.build());
		}

	}

}
