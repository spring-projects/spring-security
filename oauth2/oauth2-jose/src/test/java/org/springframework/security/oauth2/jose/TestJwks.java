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

package org.springframework.security.oauth2.jose;

import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import javax.crypto.SecretKey;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;

/**
 * @author Joe Grandja
 */
public final class TestJwks {

	// @formatter:off
	public static final RSAKey DEFAULT_RSA_JWK =
			jwk(
					TestKeys.DEFAULT_PUBLIC_KEY,
					TestKeys.DEFAULT_PRIVATE_KEY
			).build();
	// @formatter:on

	// @formatter:off
	public static final ECKey DEFAULT_EC_JWK =
			jwk(
					(ECPublicKey) TestKeys.DEFAULT_EC_KEY_PAIR.getPublic(),
					(ECPrivateKey) TestKeys.DEFAULT_EC_KEY_PAIR.getPrivate()
			).build();
	// @formatter:on

	// @formatter:off
	public static final OctetSequenceKey DEFAULT_SECRET_JWK =
			jwk(
					TestKeys.DEFAULT_SECRET_KEY
			).build();
	// @formatter:on

	private TestJwks() {
	}

	public static RSAKey.Builder jwk(RSAPublicKey publicKey, RSAPrivateKey privateKey) {
		// @formatter:off
		return new RSAKey.Builder(publicKey)
				.privateKey(privateKey)
				.keyID("rsa-jwk-kid");
		// @formatter:on
	}

	public static ECKey.Builder jwk(ECPublicKey publicKey, ECPrivateKey privateKey) {
		// @formatter:off
		Curve curve = Curve.forECParameterSpec(publicKey.getParams());
		return new ECKey.Builder(curve, publicKey)
				.privateKey(privateKey)
				.keyID("ec-jwk-kid");
		// @formatter:on
	}

	public static OctetSequenceKey.Builder jwk(SecretKey secretKey) {
		// @formatter:off
		return new OctetSequenceKey.Builder(secretKey)
				.keyID("secret-jwk-kid");
		// @formatter:on
	}

}
