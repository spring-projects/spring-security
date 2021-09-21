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

import java.net.URL;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;
import java.util.stream.Collectors;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.oauth2.jose.JwaAlgorithm;
import org.springframework.security.oauth2.jose.TestJwks;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for proofing out future support of JWE.
 *
 * @author Joe Grandja
 */
public class NimbusJweEncoderTests {

	// @formatter:off
	private static final JweHeader DEFAULT_JWE_HEADER =
			JweHeader.with(JweAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM.getName()).build();
	// @formatter:on

	private List<JWK> jwkList;

	private JWKSource<SecurityContext> jwkSource;

	private NimbusJweEncoder jweEncoder;

	@BeforeEach
	public void setUp() {
		this.jwkList = new ArrayList<>();
		this.jwkSource = (jwkSelector, securityContext) -> jwkSelector.select(new JWKSet(this.jwkList));
		this.jweEncoder = new NimbusJweEncoder(this.jwkSource);
	}

	@Test
	public void encodeWhenJwtClaimsSetThenEncodes() {
		RSAKey rsaJwk = TestJwks.DEFAULT_RSA_JWK;
		this.jwkList.add(rsaJwk);

		JwtClaimsSet jwtClaimsSet = TestJwtClaimsSets.jwtClaimsSet().build();

		// @formatter:off
		// **********************
		// Assume future API:
		// 		JwtEncoderParameters.with(JweHeader jweHeader, JwtClaimsSet claims)
		// **********************
		// @formatter:on
		Jwt encodedJwe = this.jweEncoder.encode(JwtEncoderParameters.from(jwtClaimsSet));

		assertThat(encodedJwe.getHeaders().get(JoseHeaderNames.ALG)).isEqualTo(DEFAULT_JWE_HEADER.getAlgorithm());
		assertThat(encodedJwe.getHeaders().get("enc")).isEqualTo(DEFAULT_JWE_HEADER.<String>getHeader("enc"));
		assertThat(encodedJwe.getHeaders().get(JoseHeaderNames.JKU)).isNull();
		assertThat(encodedJwe.getHeaders().get(JoseHeaderNames.JWK)).isNull();
		assertThat(encodedJwe.getHeaders().get(JoseHeaderNames.KID)).isEqualTo(rsaJwk.getKeyID());
		assertThat(encodedJwe.getHeaders().get(JoseHeaderNames.X5U)).isNull();
		assertThat(encodedJwe.getHeaders().get(JoseHeaderNames.X5C)).isNull();
		assertThat(encodedJwe.getHeaders().get(JoseHeaderNames.X5T)).isNull();
		assertThat(encodedJwe.getHeaders().get(JoseHeaderNames.X5T_S256)).isNull();
		assertThat(encodedJwe.getHeaders().get(JoseHeaderNames.TYP)).isNull();
		assertThat(encodedJwe.getHeaders().get(JoseHeaderNames.CTY)).isNull();
		assertThat(encodedJwe.getHeaders().get(JoseHeaderNames.CRIT)).isNull();

		assertThat(encodedJwe.getIssuer()).isEqualTo(jwtClaimsSet.getIssuer());
		assertThat(encodedJwe.getSubject()).isEqualTo(jwtClaimsSet.getSubject());
		assertThat(encodedJwe.getAudience()).isEqualTo(jwtClaimsSet.getAudience());
		assertThat(encodedJwe.getExpiresAt()).isEqualTo(jwtClaimsSet.getExpiresAt());
		assertThat(encodedJwe.getNotBefore()).isEqualTo(jwtClaimsSet.getNotBefore());
		assertThat(encodedJwe.getIssuedAt()).isEqualTo(jwtClaimsSet.getIssuedAt());
		assertThat(encodedJwe.getId()).isEqualTo(jwtClaimsSet.getId());
		assertThat(encodedJwe.<String>getClaim("custom-claim-name")).isEqualTo("custom-claim-value");

		assertThat(encodedJwe.getTokenValue()).isNotNull();
	}

	@Test
	public void encodeWhenNestedJwsThenEncodes() {
		// See Nimbus example -> Nested signed and encrypted JWT
		// https://connect2id.com/products/nimbus-jose-jwt/examples/signed-and-encrypted-jwt

		RSAKey rsaJwk = TestJwks.DEFAULT_RSA_JWK;
		this.jwkList.add(rsaJwk);

		JwsHeader jwsHeader = JwsHeader.with(SignatureAlgorithm.RS256).build();
		JwtClaimsSet jwtClaimsSet = TestJwtClaimsSets.jwtClaimsSet().build();

		// @formatter:off
		// **********************
		// Assume future API:
		// 		JwtEncoderParameters.with(JwsHeader jwsHeader, JweHeader jweHeader, JwtClaimsSet claims)
		// **********************
		// @formatter:on
		Jwt encodedJweNestedJws = this.jweEncoder.encode(JwtEncoderParameters.from(jwsHeader, jwtClaimsSet));

		assertThat(encodedJweNestedJws.getHeaders().get(JoseHeaderNames.ALG))
				.isEqualTo(DEFAULT_JWE_HEADER.getAlgorithm());
		assertThat(encodedJweNestedJws.getHeaders().get("enc")).isEqualTo(DEFAULT_JWE_HEADER.<String>getHeader("enc"));
		assertThat(encodedJweNestedJws.getHeaders().get(JoseHeaderNames.JKU)).isNull();
		assertThat(encodedJweNestedJws.getHeaders().get(JoseHeaderNames.JWK)).isNull();
		assertThat(encodedJweNestedJws.getHeaders().get(JoseHeaderNames.KID)).isEqualTo(rsaJwk.getKeyID());
		assertThat(encodedJweNestedJws.getHeaders().get(JoseHeaderNames.X5U)).isNull();
		assertThat(encodedJweNestedJws.getHeaders().get(JoseHeaderNames.X5C)).isNull();
		assertThat(encodedJweNestedJws.getHeaders().get(JoseHeaderNames.X5T)).isNull();
		assertThat(encodedJweNestedJws.getHeaders().get(JoseHeaderNames.X5T_S256)).isNull();
		assertThat(encodedJweNestedJws.getHeaders().get(JoseHeaderNames.TYP)).isNull();
		assertThat(encodedJweNestedJws.getHeaders().get(JoseHeaderNames.CTY)).isEqualTo("JWT");
		assertThat(encodedJweNestedJws.getHeaders().get(JoseHeaderNames.CRIT)).isNull();

		assertThat(encodedJweNestedJws.getIssuer()).isEqualTo(jwtClaimsSet.getIssuer());
		assertThat(encodedJweNestedJws.getSubject()).isEqualTo(jwtClaimsSet.getSubject());
		assertThat(encodedJweNestedJws.getAudience()).isEqualTo(jwtClaimsSet.getAudience());
		assertThat(encodedJweNestedJws.getExpiresAt()).isEqualTo(jwtClaimsSet.getExpiresAt());
		assertThat(encodedJweNestedJws.getNotBefore()).isEqualTo(jwtClaimsSet.getNotBefore());
		assertThat(encodedJweNestedJws.getIssuedAt()).isEqualTo(jwtClaimsSet.getIssuedAt());
		assertThat(encodedJweNestedJws.getId()).isEqualTo(jwtClaimsSet.getId());
		assertThat(encodedJweNestedJws.<String>getClaim("custom-claim-name")).isEqualTo("custom-claim-value");

		assertThat(encodedJweNestedJws.getTokenValue()).isNotNull();
	}

	enum JweAlgorithm implements JwaAlgorithm {

		RSA_OAEP_256("RSA-OAEP-256");

		private final String name;

		JweAlgorithm(String name) {
			this.name = name;
		}

		@Override
		public String getName() {
			return this.name;
		}

	}

	private static final class JweHeader extends JoseHeader {

		private JweHeader(Map<String, Object> headers) {
			super(headers);
		}

		@SuppressWarnings("unchecked")
		@Override
		public JweAlgorithm getAlgorithm() {
			return super.getAlgorithm();
		}

		private static Builder with(JweAlgorithm jweAlgorithm, String enc) {
			return new Builder(jweAlgorithm, enc);
		}

		private static Builder from(JweHeader headers) {
			return new Builder(headers);
		}

		private static final class Builder extends AbstractBuilder<JweHeader, Builder> {

			private Builder(JweAlgorithm jweAlgorithm, String enc) {
				Assert.notNull(jweAlgorithm, "jweAlgorithm cannot be null");
				Assert.hasText(enc, "enc cannot be empty");
				algorithm(jweAlgorithm);
				header("enc", enc);
			}

			private Builder(JweHeader headers) {
				Assert.notNull(headers, "headers cannot be null");
				Consumer<Map<String, Object>> headersConsumer = (h) -> h.putAll(headers.getHeaders());
				headers(headersConsumer);
			}

			@Override
			public JweHeader build() {
				return new JweHeader(getHeaders());
			}

		}

	}

	private static final class NimbusJweEncoder implements JwtEncoder {

		private static final String ENCODING_ERROR_MESSAGE_TEMPLATE = "An error occurred while attempting to encode the Jwt: %s";

		private static final Converter<JweHeader, JWEHeader> JWE_HEADER_CONVERTER = new JweHeaderConverter();

		private static final Converter<JwtClaimsSet, JWTClaimsSet> JWT_CLAIMS_SET_CONVERTER = new JwtClaimsSetConverter();

		private final JWKSource<SecurityContext> jwkSource;

		private final JwtEncoder jwsEncoder;

		private NimbusJweEncoder(JWKSource<SecurityContext> jwkSource) {
			Assert.notNull(jwkSource, "jwkSource cannot be null");
			this.jwkSource = jwkSource;
			this.jwsEncoder = new NimbusJwtEncoder(jwkSource);
		}

		@Override
		public Jwt encode(JwtEncoderParameters parameters) throws JwtEncodingException {
			Assert.notNull(parameters, "parameters cannot be null");

			// @formatter:off
			// **********************
			// Assume future API:
			// 		JwtEncoderParameters.getJweHeader()
			// **********************
			// @formatter:on
			JweHeader jweHeader = DEFAULT_JWE_HEADER; // Assume this is accessed via
														// JwtEncoderParameters.getJweHeader()

			JwsHeader jwsHeader = parameters.getJwsHeader();
			JwtClaimsSet claims = parameters.getClaims();

			JWK jwk = selectJwk(jweHeader);
			jweHeader = addKeyIdentifierHeadersIfNecessary(jweHeader, jwk);

			JWEHeader jweHeader2 = JWE_HEADER_CONVERTER.convert(jweHeader);
			JWTClaimsSet jwtClaimsSet = JWT_CLAIMS_SET_CONVERTER.convert(claims);

			String payload;
			if (jwsHeader != null) {
				// Sign then encrypt
				Jwt jws = this.jwsEncoder.encode(JwtEncoderParameters.from(jwsHeader, claims));
				payload = jws.getTokenValue();

				// @formatter:off
				jweHeader = JweHeader.from(jweHeader)
						.contentType("JWT")		// Indicates Nested JWT (REQUIRED)
						.build();
				// @formatter:on
			}
			else {
				// Encrypt only
				payload = jwtClaimsSet.toString();
			}

			JWEObject jweObject = new JWEObject(jweHeader2, new Payload(payload));
			try {
				// FIXME
				// Resolve type of JWEEncrypter using the JWK key type
				// For now, assuming RSA key type
				jweObject.encrypt(new RSAEncrypter(jwk.toRSAKey()));
			}
			catch (JOSEException ex) {
				throw new JwtEncodingException(String.format(ENCODING_ERROR_MESSAGE_TEMPLATE,
						"Failed to encrypt the JWT -> " + ex.getMessage()), ex);
			}
			String jwe = jweObject.serialize();

			// NOTE:
			// For the Nested JWS use case, we lose access to the JWS Header in the
			// returned JWT.
			// If this is needed, we can simply add the new method Jwt.getNestedHeaders().
			return new Jwt(jwe, claims.getIssuedAt(), claims.getExpiresAt(), jweHeader.getHeaders(),
					claims.getClaims());
		}

		private JWK selectJwk(JweHeader headers) {
			List<JWK> jwks;
			try {
				JWKSelector jwkSelector = new JWKSelector(createJwkMatcher(headers));
				jwks = this.jwkSource.get(jwkSelector, null);
			}
			catch (Exception ex) {
				throw new JwtEncodingException(String.format(ENCODING_ERROR_MESSAGE_TEMPLATE,
						"Failed to select a JWK encryption key -> " + ex.getMessage()), ex);
			}

			if (jwks.size() > 1) {
				throw new JwtEncodingException(String.format(ENCODING_ERROR_MESSAGE_TEMPLATE,
						"Found multiple JWK encryption keys for algorithm '" + headers.getAlgorithm().getName() + "'"));
			}

			if (jwks.isEmpty()) {
				throw new JwtEncodingException(
						String.format(ENCODING_ERROR_MESSAGE_TEMPLATE, "Failed to select a JWK encryption key"));
			}

			return jwks.get(0);
		}

		private static JWKMatcher createJwkMatcher(JweHeader headers) {
			JWEAlgorithm jweAlgorithm = JWEAlgorithm.parse(headers.getAlgorithm().getName());

			// @formatter:off
			return new JWKMatcher.Builder()
					.keyType(KeyType.forAlgorithm(jweAlgorithm))
					.keyID(headers.getKeyId())
					.keyUses(KeyUse.ENCRYPTION, null)
					.algorithms(jweAlgorithm, null)
					.x509CertSHA256Thumbprint(Base64URL.from(headers.getX509SHA256Thumbprint()))
					.build();
			// @formatter:on
		}

		private static JweHeader addKeyIdentifierHeadersIfNecessary(JweHeader headers, JWK jwk) {
			// Check if headers have already been added
			if (StringUtils.hasText(headers.getKeyId()) && StringUtils.hasText(headers.getX509SHA256Thumbprint())) {
				return headers;
			}
			// Check if headers can be added from JWK
			if (!StringUtils.hasText(jwk.getKeyID()) && jwk.getX509CertSHA256Thumbprint() == null) {
				return headers;
			}

			JweHeader.Builder headersBuilder = JweHeader.from(headers);
			if (!StringUtils.hasText(headers.getKeyId()) && StringUtils.hasText(jwk.getKeyID())) {
				headersBuilder.keyId(jwk.getKeyID());
			}
			if (!StringUtils.hasText(headers.getX509SHA256Thumbprint()) && jwk.getX509CertSHA256Thumbprint() != null) {
				headersBuilder.x509SHA256Thumbprint(jwk.getX509CertSHA256Thumbprint().toString());
			}

			return headersBuilder.build();
		}

	}

	private static class JweHeaderConverter implements Converter<JweHeader, JWEHeader> {

		@Override
		public JWEHeader convert(JweHeader headers) {
			JWEAlgorithm jweAlgorithm = JWEAlgorithm.parse(headers.getAlgorithm().getName());
			EncryptionMethod encryptionMethod = EncryptionMethod.parse(headers.getHeader("enc"));
			JWEHeader.Builder builder = new JWEHeader.Builder(jweAlgorithm, encryptionMethod);

			URL jwkSetUri = headers.getJwkSetUrl();
			if (jwkSetUri != null) {
				try {
					builder.jwkURL(jwkSetUri.toURI());
				}
				catch (Exception ex) {
					throw new IllegalArgumentException(
							"Unable to convert '" + JoseHeaderNames.JKU + "' JOSE header to a URI", ex);
				}
			}

			Map<String, Object> jwk = headers.getJwk();
			if (!CollectionUtils.isEmpty(jwk)) {
				try {
					builder.jwk(JWK.parse(jwk));
				}
				catch (Exception ex) {
					throw new IllegalArgumentException("Unable to convert '" + JoseHeaderNames.JWK + "' JOSE header",
							ex);
				}
			}

			String keyId = headers.getKeyId();
			if (StringUtils.hasText(keyId)) {
				builder.keyID(keyId);
			}

			URL x509Uri = headers.getX509Url();
			if (x509Uri != null) {
				try {
					builder.x509CertURL(x509Uri.toURI());
				}
				catch (Exception ex) {
					throw new IllegalArgumentException(
							"Unable to convert '" + JoseHeaderNames.X5U + "' JOSE header to a URI", ex);
				}
			}

			List<String> x509CertificateChain = headers.getX509CertificateChain();
			if (!CollectionUtils.isEmpty(x509CertificateChain)) {
				builder.x509CertChain(x509CertificateChain.stream().map(Base64::new).collect(Collectors.toList()));
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

			Map<String, Object> customHeaders = headers.getHeaders().entrySet().stream()
					.filter((header) -> !JWEHeader.getRegisteredParameterNames().contains(header.getKey()))
					.collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
			if (!CollectionUtils.isEmpty(customHeaders)) {
				builder.customParams(customHeaders);
			}

			return builder.build();
		}

	}

	private static class JwtClaimsSetConverter implements Converter<JwtClaimsSet, JWTClaimsSet> {

		@Override
		public JWTClaimsSet convert(JwtClaimsSet claims) {
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

	}

}
