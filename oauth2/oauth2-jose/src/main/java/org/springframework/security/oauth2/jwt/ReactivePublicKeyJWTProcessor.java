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

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.jwt.proc.JWTProcessor;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithms;
import reactor.core.publisher.Mono;

import java.security.interfaces.RSAPublicKey;

/**
 * A simple implementation of {@link ReactiveJWTProcessor}.
 * This implementation is mainly a wrapper around a simple {@link com.nimbusds.jwt.proc.JWTProcessor}.
 * JWT will be validated against a provided public key.
 */
public class ReactivePublicKeyJWTProcessor implements ReactiveJWTProcessor {
	private final JWTProcessor<SecurityContext> jwtProcessor;

	public ReactivePublicKeyJWTProcessor(RSAPublicKey publicKey) {
		this(publicKey, JWSAlgorithm.parse(JwsAlgorithms.RS256));
	}

	public ReactivePublicKeyJWTProcessor(RSAPublicKey publicKey, JWSAlgorithm algorithm) {
		RSAKey rsaKey = new RSAKey.Builder(publicKey).build();
		JWKSet jwkSet = new JWKSet(rsaKey);
		JWKSource<SecurityContext> jwkSource = new ImmutableJWKSet<>(jwkSet);
		JWSKeySelector<SecurityContext> jwsKeySelector = new JWSVerificationKeySelector<>(algorithm, jwkSource);

		DefaultJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
		jwtProcessor.setJWSKeySelector(jwsKeySelector);
		jwtProcessor.setJWTClaimsSetVerifier((claims, context) -> {
		});

		this.jwtProcessor = jwtProcessor;
	}

	public Mono<JWTClaimsSet> process(SignedJWT jwt) {
		return Mono.defer(() -> {
			try {
				return Mono.just(jwtProcessor.process(jwt, null));
			} catch (BadJOSEException | JOSEException e) {
				return Mono.error(e);
			}
		});
	}
}
