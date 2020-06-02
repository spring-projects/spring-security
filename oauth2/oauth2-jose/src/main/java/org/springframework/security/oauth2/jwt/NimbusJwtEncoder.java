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
import com.nimbusds.jose.crypto.factories.DefaultJWSSignerFactory;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.produce.JWSSignerFactory;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.util.Assert;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.Map;

/**
 * A low-level Nimbus implementation of {@link JwtEncoder} which takes a raw Nimbus configuration.
 * <p>
 * This class currently supports signing JWTs according to the JSON Web Signature (JWS) specification
 * and encoding them in the JWS Compact Serialization format.
 *
 * @author Gergely Krajcsovszki
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7515">JSON Web Signature (JWS)</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7515#section-3.1">JWS Compact Serialization</a>
 * @since TODO
 */
public final class NimbusJwtEncoder implements JwtEncoder {
	private static final String ENCODING_ERROR_MESSAGE_TEMPLATE =
			"An error occurred while attempting to encode the Jwt: %s";
	private static final String SIGNER_CREATION_ERROR_MESSAGE_TEMPLATE =
			"An error occurred while creating a Jwt signer: %s";
	private static final String JWK_CREATION_ERROR_MESSAGE_TEMPLATE =
			"An error occurred while creating a JWK: %s";

	private final JWSSigner jwsSigner;

	private final JWSAlgorithm jwsAlgorithm;

	/**
	 * Configures a {@link NimbusJwtEncoder} with the given parameters
	 *
	 * @param jwsSigner             the {@link JWSSigner} to use
	 * @param preferredJwsAlgorithm the {@link JWSAlgorithm} to use.
	 *                              If left null, the first one returned by {@link JWSSigner#supportedJWSAlgorithms()} will be used.
	 *                              Must be compatible with the keys set in the {@link JWSSigner}.
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
			throw new JwtSigningException(String.format(ENCODING_ERROR_MESSAGE_TEMPLATE, ex.getMessage()), ex);
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

	// TODO: builder from local JWKSet and optional JWKSelector?

	/**
	 * Use the private key from the given key pair to sign JWTs. The supplied {@link KeyPair} must contain
	 * both a public and a private key for the same, supported signing algorithm. The public key is used
	 * to determine the algorithm to use and to get any required parameters for it, while the private key
	 * will be used to generate the signature.
	 *
	 * @param keys the {@link KeyPair} to use
	 * @return a {@link PrivateKeyJwtEncoderBuilder} for further configurations
	 */
	public static PrivateKeyJwtEncoderBuilder withPrivateKey(KeyPair keys) {
		return new PrivateKeyJwtEncoderBuilder(keys.getPublic(), keys.getPrivate());
	}

	/**
	 * Use the given {@code SecretKey} to sign JWTs
	 *
	 * @param secretKey the {@code SecretKey} to use
	 * @return a {@link SecretKeyJwtEncoderBuilder} for further configurations
	 */
	public static SecretKeyJwtEncoderBuilder withSecretKey(SecretKey secretKey) {
		return new SecretKeyJwtEncoderBuilder(secretKey);
	}

	/**
	 * A builder for creating {@link NimbusJwtEncoder} instances based on a private key.
	 */
	public static final class PrivateKeyJwtEncoderBuilder extends JwtEncoderBuilderBase<PrivateKeyJwtEncoderBuilder> {

		private PrivateKeyJwtEncoderBuilder(PublicKey publicKey, PrivateKey privateKey) {
			super(buildJwk(publicKey, privateKey));
		}

		private static JWK buildJwk(PublicKey publicKey, PrivateKey privateKey) {
			Assert.notNull(publicKey, "publicKey cannot be null");
			Assert.notNull(privateKey, "privateKey cannot be null");

			if (publicKey instanceof RSAPublicKey) {
				try {
					return new RSAKey.Builder((RSAPublicKey) publicKey).privateKey(privateKey).build();
				} catch (Exception e) {
					throw new JwtSigningException(
							String.format(JWK_CREATION_ERROR_MESSAGE_TEMPLATE,
									"Failed to create RSAKey from supplied public and private key: " + e.getMessage()), e);
				}
			}


			if (publicKey instanceof ECPublicKey) {
				try {
					ECPublicKey ecPublicKey = (ECPublicKey) publicKey;
					return new ECKey.Builder(Curve.forECParameterSpec(ecPublicKey.getParams()), ecPublicKey)
							.privateKey(privateKey)
							.build();
				} catch (Exception e) {
					throw new JwtSigningException(
							String.format(JWK_CREATION_ERROR_MESSAGE_TEMPLATE,
									"Failed to create ECKey from supplied public and private key: " + e.getMessage()), e);
				}
			}

			throw new JwtSigningException(
					String.format(JWK_CREATION_ERROR_MESSAGE_TEMPLATE,
							"The supplied public key is not supported, expected " + RSAPublicKey.class.getSimpleName()
									+ " or " + ECPublicKey.class.getSimpleName() + ", got "
									+ publicKey.getClass().getSimpleName()));
		}

		/**
		 * Use the given signing
		 * <a href="https://tools.ietf.org/html/rfc7515#section-4.1.1" target="_blank">algorithm</a>.
		 * <p>
		 * Must be compatible with the keys set in the constructor.
		 * <p>
		 * If not set, the first one in the list of supported algorithms of the {@link JWSSigner} generated
		 * from the {@link PrivateKey} will be used.
		 *
		 * @param signatureAlgorithm the algorithm to use
		 * @return a {@link PrivateKeyJwtEncoderBuilder} for further configurations
		 */
		public PrivateKeyJwtEncoderBuilder signatureAlgorithm(SignatureAlgorithm signatureAlgorithm) {
			Assert.notNull(signatureAlgorithm, "signatureAlgorithm cannot be null");
			this.jwsAlgorithm = JWSAlgorithm.parse(signatureAlgorithm.getName());
			return this;
		}
	}

	/**
	 * A builder for creating {@link NimbusJwtEncoder} instances based on a {@code SecretKey}.
	 */
	public static final class SecretKeyJwtEncoderBuilder extends JwtEncoderBuilderBase<SecretKeyJwtEncoderBuilder> {

		private SecretKeyJwtEncoderBuilder(SecretKey secretKey) {
			super(buildJwk(secretKey));
		}

		private static JWK buildJwk(SecretKey secretKey) {
			Assert.notNull(secretKey, "secretKey cannot be null");
			return new OctetSequenceKey.Builder(secretKey).build();
		}

		/**
		 * Use the given
		 * <a href="https://tools.ietf.org/html/rfc7515#section-4.1.1" target="_blank">algorithm</a>
		 * when generating the MAC.
		 * <p>
		 * Must be compatible with the keys set in the constructor.
		 * <p>
		 * If not set, the first one in the list of supported algorithms of the {@link JWSSigner} generated
		 * from the {@link SecretKey} will be used.
		 *
		 * @param macAlgorithm the MAC algorithm to use
		 * @return this builder for further configurations
		 */
		public SecretKeyJwtEncoderBuilder macAlgorithm(MacAlgorithm macAlgorithm) {
			Assert.notNull(macAlgorithm, "macAlgorithm cannot be null");
			this.jwsAlgorithm = JWSAlgorithm.parse(macAlgorithm.getName());
			return this;
		}
	}

	/**
	 * A base class for builders for creating {@link NimbusJwtEncoder} instances.
	 */
	static abstract class JwtEncoderBuilderBase<T extends JwtEncoderBuilderBase> {
		JWSAlgorithm jwsAlgorithm;
		private final JWK jwk;
		private JWSSignerFactory jwsSignerFactory;

		JwtEncoderBuilderBase(JWK jwk) {
			this.jwk = jwk;
		}

		/**
		 * Use the given {@link JWSSignerFactory}.
		 * <p>
		 * If not specified, a {@link DefaultJWSSignerFactory} will be used.
		 *
		 * @param jwsSignerFactory the {@link JWSSignerFactory} to use
		 * @return this builder for further configurations
		 */
		@SuppressWarnings("unchecked")
		public T jwsSignerFactory(JWSSignerFactory jwsSignerFactory) {
			Assert.notNull(jwsSignerFactory, "jwsSignerFactory cannot be null");
			this.jwsSignerFactory = jwsSignerFactory;
			return (T) this;
		}

		JWSSigner jwsSigner() {
			if (jwsSignerFactory == null) {
				jwsSignerFactory = new DefaultJWSSignerFactory();
			}
			try {
				return jwsSignerFactory.createJWSSigner(jwk);
			} catch (JOSEException ex) {
				throw new JwtSigningException(
						String.format(SIGNER_CREATION_ERROR_MESSAGE_TEMPLATE, ex.getMessage()), ex);
			}
		}

		/**
		 * Build the configured {@link NimbusJwtEncoder}.
		 *
		 * @return the configured {@link NimbusJwtEncoder}
		 */
		public NimbusJwtEncoder build() {
			return new NimbusJwtEncoder(jwsSigner(), jwsAlgorithm);
		}
	}
}
