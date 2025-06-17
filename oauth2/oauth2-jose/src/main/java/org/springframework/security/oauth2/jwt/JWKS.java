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

import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.Set;

import javax.crypto.SecretKey;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.impl.ECDSA;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyOperation;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;

final class JWKS {

	private JWKS() {

	}

	static OctetSequenceKey.Builder signing(SecretKey key) throws JOSEException {
		Date issued = new Date();
		return new OctetSequenceKey.Builder(key).keyOperations(Set.of(KeyOperation.SIGN))
			.keyUse(KeyUse.SIGNATURE)
			.algorithm(JWSAlgorithm.HS256)
			.keyIDFromThumbprint()
			.issueTime(issued)
			.notBeforeTime(issued);
	}

	static ECKey.Builder signingWithEc(ECPublicKey pub, ECPrivateKey key) throws JOSEException {
		Date issued = new Date();
		Curve curve = Curve.forECParameterSpec(pub.getParams());
		JWSAlgorithm algorithm = computeAlgorithm(curve);
		return new ECKey.Builder(curve, pub).privateKey(key)
			.keyOperations(Set.of(KeyOperation.SIGN))
			.keyUse(KeyUse.SIGNATURE)
			.algorithm(algorithm)
			.keyIDFromThumbprint()
			.issueTime(issued)
			.notBeforeTime(issued);
	}

	private static JWSAlgorithm computeAlgorithm(Curve curve) {
		try {
			return ECDSA.resolveAlgorithm(curve);
		}
		catch (JOSEException ex) {
			throw new IllegalArgumentException(ex);
		}
	}

	static RSAKey.Builder signingWithRsa(RSAPublicKey pub, RSAPrivateKey key) throws JOSEException {
		Date issued = new Date();
		return new RSAKey.Builder(pub).privateKey(key)
			.keyUse(KeyUse.SIGNATURE)
			.keyOperations(Set.of(KeyOperation.SIGN))
			.algorithm(JWSAlgorithm.RS256)
			.keyIDFromThumbprint()
			.issueTime(issued)
			.notBeforeTime(issued);
	}

}
