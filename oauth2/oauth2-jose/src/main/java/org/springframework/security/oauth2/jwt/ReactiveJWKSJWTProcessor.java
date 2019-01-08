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
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.jwt.proc.JWTProcessor;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithms;
import org.springframework.util.Assert;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

/**
 * A simple implementation of {@link ReactiveJWTProcessor}.
 * This implementation is mainly a wrapper around a simple {@link com.nimbusds.jwt.proc.JWTProcessor}
 * but with a reactive initialization to get public key from a JWKS endpoint.
 */
public class ReactiveJWKSJWTProcessor implements ReactiveJWTProcessor {
	private final JWTProcessor<JWKContext> jwtProcessor;
	private final JWKSelectorFactory jwkSelectorFactory;
	private final ReactiveRemoteJWKSource reactiveJwkSource;

	public ReactiveJWKSJWTProcessor(String jwkSetUrl) {
		this(jwkSetUrl, WebClient.create(), JWSAlgorithm.parse(JwsAlgorithms.RS256));
	}

	public ReactiveJWKSJWTProcessor(String jwkSetUrl, WebClient webClient) {
		this(jwkSetUrl, webClient, JWSAlgorithm.parse(JwsAlgorithms.RS256));
	}

	public ReactiveJWKSJWTProcessor(String jwkSetUrl, JWSAlgorithm algorithm) {
		this(jwkSetUrl, WebClient.create(), algorithm);
	}

	public ReactiveJWKSJWTProcessor(String jwkSetUrl, WebClient webClient, JWSAlgorithm algorithm) {
		Assert.hasText(jwkSetUrl, "jwkSetUrl cannot be empty");

		JWKSource<JWKContext> jwkSource = new JWKContextJWKSource();
		JWSKeySelector<JWKContext> jwsKeySelector = new JWSVerificationKeySelector<>(algorithm, jwkSource);

		DefaultJWTProcessor<JWKContext> jwtProcessor = new DefaultJWTProcessor<>();
		jwtProcessor.setJWSKeySelector(jwsKeySelector);
		jwtProcessor.setJWTClaimsSetVerifier((claims, context) -> {
		});

		reactiveJwkSource = new ReactiveRemoteJWKSource(webClient, jwkSetUrl);

		jwkSelectorFactory = new JWKSelectorFactory(algorithm);

		this.jwtProcessor = jwtProcessor;
	}

	public Mono<JWTClaimsSet> process(SignedJWT jwt) {
		return Mono.defer(() -> {
			try {
				JWKSelector select = jwkSelectorFactory.createSelector(jwt.getHeader());
				return reactiveJwkSource
						.get(select)
						.map(JWKContext::new)
						.map(context -> createClaimsSet(jwt, context));
			} catch (RuntimeException ex) {
				return Mono.error(new JwtException("An error occurred while attempting to decode the Jwt: " + ex.getMessage(), ex));
			}
		});
	}

	private JWTClaimsSet createClaimsSet(JWT parsedToken, JWKContext context) {
		try {
			return this.jwtProcessor.process(parsedToken, context);
		} catch (BadJOSEException | JOSEException e) {
			throw new JwtException("Failed to validate the token", e);
		}
	}
}
