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

import java.util.HashSet;
import java.util.Set;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import reactor.core.publisher.Mono;

import org.springframework.util.Assert;

final class ReactiveJwtDecoderProviderConfigurationUtils {

	static <C extends SecurityContext> Mono<ConfigurableJWTProcessor<C>> addJWSAlgorithms(
			ReactiveRemoteJWKSource jwkSource, ConfigurableJWTProcessor<C> jwtProcessor) {
		JWSKeySelector<C> selector = jwtProcessor.getJWSKeySelector();
		if (!(selector instanceof JWSVerificationKeySelector)) {
			return Mono.just(jwtProcessor);
		}
		JWKSource<C> delegate = ((JWSVerificationKeySelector<C>) selector).getJWKSource();
		return getJWSAlgorithms(jwkSource).map((algorithms) -> new JWSVerificationKeySelector<>(algorithms, delegate))
				.map((replacement) -> {
					jwtProcessor.setJWSKeySelector(replacement);
					return jwtProcessor;
				});
	}

	static Mono<Set<JWSAlgorithm>> getJWSAlgorithms(ReactiveRemoteJWKSource jwkSource) {
		JWKMatcher jwkMatcher = new JWKMatcher.Builder().publicOnly(true).keyUses(KeyUse.SIGNATURE, null)
				.keyTypes(KeyType.RSA, KeyType.EC).build();
		return jwkSource.get(new JWKSelector(jwkMatcher)).map((jwks) -> {
			Set<JWSAlgorithm> jwsAlgorithms = new HashSet<>();
			for (JWK jwk : jwks) {
				if (jwk.getAlgorithm() != null) {
					JWSAlgorithm jwsAlgorithm = JWSAlgorithm.parse(jwk.getAlgorithm().getName());
					jwsAlgorithms.add(jwsAlgorithm);
				}
				else {
					if (jwk.getKeyType() == KeyType.RSA) {
						jwsAlgorithms.addAll(JWSAlgorithm.Family.RSA);
					}
					else if (jwk.getKeyType() == KeyType.EC) {
						jwsAlgorithms.addAll(JWSAlgorithm.Family.EC);
					}
				}
			}
			Assert.notEmpty(jwsAlgorithms, "Failed to find any algorithms from the JWK set");
			return jwsAlgorithms;
		}).onErrorMap(KeySourceException.class, (ex) -> new IllegalStateException(ex));
	}

	private ReactiveJwtDecoderProviderConfigurationUtils() {
	}

}
