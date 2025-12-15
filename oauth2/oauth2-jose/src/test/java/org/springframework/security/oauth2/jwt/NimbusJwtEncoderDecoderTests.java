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

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Objects;
import java.util.Set;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.impl.ECDSA;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyOperation;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import org.junit.jupiter.api.Test;

import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Use {@link NimbusJwtDecoder} to decode JWT's encoded with {@link NimbusJwtEncoder}
 *
 * @author Ziqin Wang
 */
class NimbusJwtEncoderDecoderTests {

	@Test
	void encodeAndDecodeHS256() throws GeneralSecurityException {
		KeyGenerator keyGenerator = KeyGenerator.getInstance("HmacSHA256");
		SecretKey secretKey = keyGenerator.generateKey();

		NimbusJwtEncoder jwtEncoder = NimbusJwtEncoder.withSecretKey(secretKey).build();
		JwtClaimsSet claims = TestJwtClaimsSets.jwtClaimsSet().build();
		String jwt = jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();

		NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withSecretKey(secretKey).build();
		Jwt decodedJwt = jwtDecoder.decode(jwt);

		assertThat(decodedJwt.getSubject()).isEqualTo("subject");
	}

	@Test
	void encodeAndDecodeRS256() throws GeneralSecurityException {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(2048);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
		RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

		NimbusJwtEncoder jwtEncoder = NimbusJwtEncoder.withKeyPair(publicKey, privateKey).build();
		JwtClaimsSet claims = TestJwtClaimsSets.jwtClaimsSet().build();
		String jwt = jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();

		NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withPublicKey(publicKey).build();
		Jwt decodedJwt = jwtDecoder.decode(jwt);

		assertThat(decodedJwt.getSubject()).isEqualTo("subject");
	}

	@Test
	void encodeAndDecodeES256() throws GeneralSecurityException, JOSEException {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
		keyPairGenerator.initialize(new ECGenParameterSpec("secp256r1"));
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
		ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();

		NimbusJwtEncoder jwtEncoder = NimbusJwtEncoder.withKeyPair(publicKey, privateKey).build();
		JwtClaimsSet claims = TestJwtClaimsSets.jwtClaimsSet().build();
		String jwt = jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();

		Curve curve = Curve.forECParameterSpec(publicKey.getParams());
		JWK jwk = new ECKey.Builder(curve, publicKey).keyOperations(Set.of(KeyOperation.VERIFY))
			.keyUse(KeyUse.SIGNATURE)
			.algorithm(ECDSA.resolveAlgorithm(curve))
			.keyIDFromThumbprint()
			.build();
		NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withJwkSource(new ImmutableJWKSet<>(new JWKSet(jwk)))
			.jwsAlgorithm(Objects.requireNonNull(SignatureAlgorithm.from(jwk.getAlgorithm().getName())))
			.build();
		Jwt decodedJwt = jwtDecoder.decode(jwt);

		assertThat(decodedJwt.getSubject()).isEqualTo("subject");
	}

}
