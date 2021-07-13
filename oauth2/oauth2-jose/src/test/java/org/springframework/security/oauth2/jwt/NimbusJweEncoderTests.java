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
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import org.junit.Before;
import org.junit.Test;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.oauth2.core.AbstractOAuth2Token;
import org.springframework.security.oauth2.jose.JwaAlgorithm;
import org.springframework.security.oauth2.jose.TestJwks;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link NimbusJweEncoder} (future support for JWE).
 *
 * @author Joe Grandja
 */
public class NimbusJweEncoderTests {

	private List<JWK> jwkList;

	private JWKSource<SecurityContext> jwkSource;

	private NimbusJweEncoder jweEncoder;

	private NimbusJwsEncoder jwsEncoder;

	@Before
	public void setUp() {
		this.jwkList = new ArrayList<>();
		this.jwkSource = (jwkSelector, securityContext) -> jwkSelector.select(new JWKSet(this.jwkList));
		this.jweEncoder = new NimbusJweEncoder(this.jwkSource);
		this.jwsEncoder = new NimbusJwsEncoder(this.jwkSource);
	}

	@Test
	public void encodeWhenJwtClaimsSetThenEncodes() {
		RSAKey rsaJwk = TestJwks.DEFAULT_RSA_JWK;
		this.jwkList.add(rsaJwk);

		// @formatter:off
		JoseHeader jweHeader = JoseHeader.withAlgorithm(JweAlgorithm.RSA_OAEP_256)
				.header("enc", EncryptionMethod.A256GCM.getName())
				.build();
		// @formatter:on
		JwtClaimsSet jwtClaimsSet = TestJwtClaimsSets.jwtClaimsSet().build();

		Jwt encodedJwe = this.jweEncoder.encode(jweHeader, jwtClaimsSet);

		assertThat(encodedJwe.getHeaders().get(JoseHeaderNames.ALG)).isEqualTo(jweHeader.getAlgorithm());
		assertThat(encodedJwe.getHeaders().get("enc")).isEqualTo(jweHeader.<String>getHeader("enc"));
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

		JoseHeader jwsHeader = JoseHeader.withAlgorithm(SignatureAlgorithm.RS256).build();
		JwtClaimsSet jwtClaimsSet = TestJwtClaimsSets.jwtClaimsSet().build();

		Jwt encodedJws = this.jwsEncoder.encode(jwsHeader, jwtClaimsSet);

		// @formatter:off
		JoseHeader jweHeader = JoseHeader.withAlgorithm(JweAlgorithm.RSA_OAEP_256)
				.header("enc", EncryptionMethod.A256GCM.getName())
				.contentType("JWT")		// Indicates Nested JWT (REQUIRED)
				.build();
		// @formatter:on

		JoseToken encodedJweNestedJws = this.jweEncoder.encode(jweHeader,
				new JosePayload<>(encodedJws.getTokenValue()));

		assertThat(encodedJweNestedJws.getHeaders().<JweAlgorithm>getAlgorithm()).isEqualTo(jweHeader.getAlgorithm());
		assertThat(encodedJweNestedJws.getHeaders().<String>getHeader("enc")).isEqualTo(jweHeader.getHeader("enc"));
		assertThat(encodedJweNestedJws.getHeaders().getJwkSetUri()).isNull();
		assertThat(encodedJweNestedJws.getHeaders().getJwk()).isNull();
		assertThat(encodedJweNestedJws.getHeaders().getKeyId()).isEqualTo(rsaJwk.getKeyID());
		assertThat(encodedJweNestedJws.getHeaders().getX509Uri()).isNull();
		assertThat(encodedJweNestedJws.getHeaders().getX509CertificateChain()).isNull();
		assertThat(encodedJweNestedJws.getHeaders().getX509SHA1Thumbprint()).isNull();
		assertThat(encodedJweNestedJws.getHeaders().getX509SHA256Thumbprint()).isNull();
		assertThat(encodedJweNestedJws.getHeaders().getType()).isNull();
		assertThat(encodedJweNestedJws.getHeaders().getContentType()).isEqualTo("JWT");
		assertThat(encodedJweNestedJws.getHeaders().getCritical()).isNull();

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

	private static final class NimbusJweEncoder implements JwtEncoder, JoseEncoder {

		private static final String ENCODING_ERROR_MESSAGE_TEMPLATE = "An error occurred while attempting to encode the Jwt: %s";

		private static final Converter<JoseHeader, JWEHeader> JWE_HEADER_CONVERTER = new JweHeaderConverter();

		private static final Converter<JwtClaimsSet, JWTClaimsSet> JWT_CLAIMS_SET_CONVERTER = new JwtClaimsSetConverter();

		private final JWKSource<SecurityContext> jwkSource;

		private NimbusJweEncoder(JWKSource<SecurityContext> jwkSource) {
			Assert.notNull(jwkSource, "jwkSource cannot be null");
			this.jwkSource = jwkSource;
		}

		@Override
		public Jwt encode(JoseHeader headers, JwtClaimsSet claims) throws JwtEncodingException {
			Assert.notNull(headers, "headers cannot be null");
			Assert.notNull(claims, "claims cannot be null");

			JWTClaimsSet jwtClaimsSet = JWT_CLAIMS_SET_CONVERTER.convert(claims);

			JoseToken joseToken = encode(headers, new JosePayload<>(jwtClaimsSet.toString()));

			return new Jwt(joseToken.getTokenValue(), claims.getIssuedAt(), claims.getExpiresAt(),
					joseToken.getHeaders().getHeaders(), claims.getClaims());
		}

		@Override
		public JoseToken encode(JoseHeader headers, JosePayload<?> payload) throws JwtEncodingException {
			Assert.notNull(headers, "headers cannot be null");
			Assert.notNull(payload, "payload cannot be null");

			JWEHeader jweHeader;
			try {
				jweHeader = JWE_HEADER_CONVERTER.convert(headers);
			}
			catch (Exception ex) {
				throw new JwtEncodingException(String.format(ENCODING_ERROR_MESSAGE_TEMPLATE, ex.getMessage()), ex);
			}

			JWK jwk = selectJwk(jweHeader);
			if (jwk == null) {
				throw new JwtEncodingException(
						String.format(ENCODING_ERROR_MESSAGE_TEMPLATE, "Failed to select a JWK encryption key"));
			}

			jweHeader = addKeyIdentifierHeadersIfNecessary(jweHeader, jwk);
			headers = syncKeyIdentifierHeadersIfNecessary(headers, jweHeader);

			// FIXME
			// Resolve type of JosePayload.content
			// For now, assuming String type
			String payloadContent = (String) payload.getContent();

			JWEObject jweObject = new JWEObject(jweHeader, new Payload(payloadContent));
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

			return new JoseToken(jwe, null, null, headers, payload);
		}

		private JWK selectJwk(JWEHeader jweHeader) {
			JWKSelector jwkSelector = new JWKSelector(JWKMatcher.forJWEHeader(jweHeader));

			List<JWK> jwks;
			try {
				jwks = this.jwkSource.get(jwkSelector, null);
			}
			catch (KeySourceException ex) {
				throw new JwtEncodingException(String.format(ENCODING_ERROR_MESSAGE_TEMPLATE,
						"Failed to select a JWK encryption key -> " + ex.getMessage()), ex);
			}

			if (jwks.size() > 1) {
				throw new JwtEncodingException(String.format(ENCODING_ERROR_MESSAGE_TEMPLATE,
						"Found multiple JWK encryption keys for algorithm '" + jweHeader.getAlgorithm().getName()
								+ "'"));
			}

			return !jwks.isEmpty() ? jwks.get(0) : null;
		}

		private static JWEHeader addKeyIdentifierHeadersIfNecessary(JWEHeader jweHeader, JWK jwk) {
			// Check if headers have already been added
			if (StringUtils.hasText(jweHeader.getKeyID()) && jweHeader.getX509CertSHA256Thumbprint() != null) {
				return jweHeader;
			}
			// Check if headers can be added from JWK
			if (!StringUtils.hasText(jwk.getKeyID()) && jwk.getX509CertSHA256Thumbprint() == null) {
				return jweHeader;
			}

			JWEHeader.Builder headerBuilder = new JWEHeader.Builder(jweHeader);
			if (!StringUtils.hasText(jweHeader.getKeyID()) && StringUtils.hasText(jwk.getKeyID())) {
				headerBuilder.keyID(jwk.getKeyID());
			}
			if (jweHeader.getX509CertSHA256Thumbprint() == null && jwk.getX509CertSHA256Thumbprint() != null) {
				headerBuilder.x509CertSHA256Thumbprint(jwk.getX509CertSHA256Thumbprint());
			}

			return headerBuilder.build();
		}

		private static JoseHeader syncKeyIdentifierHeadersIfNecessary(JoseHeader joseHeader, JWEHeader jweHeader) {
			String jweHeaderX509SHA256Thumbprint = null;
			if (jweHeader.getX509CertSHA256Thumbprint() != null) {
				jweHeaderX509SHA256Thumbprint = jweHeader.getX509CertSHA256Thumbprint().toString();
			}
			if (Objects.equals(joseHeader.getKeyId(), jweHeader.getKeyID())
					&& Objects.equals(joseHeader.getX509SHA256Thumbprint(), jweHeaderX509SHA256Thumbprint)) {
				return joseHeader;
			}

			JoseHeader.Builder headerBuilder = JoseHeader.from(joseHeader);
			if (!Objects.equals(joseHeader.getKeyId(), jweHeader.getKeyID())) {
				headerBuilder.keyId(jweHeader.getKeyID());
			}
			if (!Objects.equals(joseHeader.getX509SHA256Thumbprint(), jweHeaderX509SHA256Thumbprint)) {
				headerBuilder.x509SHA256Thumbprint(jweHeaderX509SHA256Thumbprint);
			}

			return headerBuilder.build();
		}

	}

	private static class JweHeaderConverter implements Converter<JoseHeader, JWEHeader> {

		@Override
		public JWEHeader convert(JoseHeader headers) {
			JWEAlgorithm jweAlgorithm = JWEAlgorithm.parse(headers.getAlgorithm().getName());
			EncryptionMethod encryptionMethod = EncryptionMethod.parse(headers.getHeader("enc"));
			JWEHeader.Builder builder = new JWEHeader.Builder(jweAlgorithm, encryptionMethod);

			URL jwkSetUri = headers.getJwkSetUri();
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

			URL x509Uri = headers.getX509Uri();
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

	static class JoseToken extends AbstractOAuth2Token {

		private final JoseHeader headers;

		private final JosePayload<?> payload;

		JoseToken(String tokenValue, Instant issuedAt, Instant expiresAt, JoseHeader headers, JosePayload<?> payload) {
			super(tokenValue, issuedAt, expiresAt);
			this.headers = headers;
			this.payload = payload;
		}

		JoseHeader getHeaders() {
			return this.headers;
		}

		JosePayload<?> getPayload() {
			return this.payload;
		}

	}

	static class JosePayload<T> {

		private final T content;

		JosePayload(T content) {
			this.content = content;
		}

		T getContent() {
			return this.content;
		}

	}

	// @formatter:off
	/*
	 * IMPORTANT DESIGN DECISION
	 * -------------------------
	 *
	 * This API is needed in order to support "Nested JWT".
	 *
	 * See section 2. Terminology
	 * https://tools.ietf.org/html/rfc7519#section-2
	 *
	 * Nested JWT
	 * 		A JWT in which nested signing and/or encryption are employed.
	 * 		In Nested JWTs, a JWT is used as the payload or plaintext value of an
     * 		enclosing JWS or JWE structure, respectively.
	 *
	 * See section 3. JSON Web Token (JWT) Overview
	 * https://tools.ietf.org/html/rfc7519#section-3
	 *
	 * JWTs represent a set of claims as a JSON object that is encoded in a
	 * JWS and/or JWE structure.  This JSON object is the JWT Claims Set.
	 *
	 * The contents of the JOSE Header describe the cryptographic operations
	 * applied to the JWT Claims Set.  If the JOSE Header is for a JWS, the
	 * JWT is represented as a JWS and the claims are digitally signed or
	 * MACed, with the JWT Claims Set being the JWS Payload.  If the JOSE
	 * Header is for a JWE, the JWT is represented as a JWE and the claims
	 * are encrypted, with the JWT Claims Set being the plaintext encrypted
	 * by the JWE.  A JWT may be enclosed in another JWE or JWS structure to
	 * create a Nested JWT, enabling nested signing and encryption to be
	 * performed.
	 *
	 * -----------------------
	 *
	 * In summary, the `JwtEncoder` API is designed for signing (JWS) and encrypting (JWE) a JWT Claims Set.
	 * Whereas, the `JoseEncoder` API is a higher level of abstraction that can be used for Nested JWT (signing and encryption).
	 * NOTE: The `JosePayload` type provides the flexibility to support any data type,
	 * e.g. JWT/JWS, JwtClaimsSet, String, Map, byte[], etc.
	 */
	interface JoseEncoder {

		JoseToken encode(JoseHeader headers, JosePayload<?> payload) throws JwtEncodingException;

	}
	// @formatter:on

}
