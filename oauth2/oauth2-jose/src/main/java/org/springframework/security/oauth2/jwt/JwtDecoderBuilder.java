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

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.util.Assert;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.*;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * An abstraction of the common functionality for the two main JwtDecoderBuilder instances
 * ({@link NimbusJwtDecoder}, and {@link NimbusReactiveJwtDecoder}).
 * @param <T>
 */
public abstract class JwtDecoderBuilder<T> {

	private static final Log log = LogFactory.getLog(JwtDecoderBuilder.class);

	private final String jwkSetUri;

	private final Set<SignatureAlgorithm> signatureAlgorithms = new HashSet<>();

	protected JwtDecoderBuilder(String jwkSetUri) {
		Assert.hasText(jwkSetUri, "jwkSetUri cannot be empty");
		this.jwkSetUri = jwkSetUri;
	}

	protected abstract T self();

	/**
	 * Provides access to the location of the JWK Set.
	 * @return the JWK Set URI.
	 */
	protected String getJwkSetUri() {
		return jwkSetUri;
	}

	/**
	 * Append the given signing
	 * <a href="https://tools.ietf.org/html/rfc7515#section-4.1.1" target="_blank">algorithm</a>
	 * to the set of algorithms to use.
	 *
	 * @param signatureAlgorithm the algorithm to use
	 * @return a {@link NimbusReactiveJwtDecoder.JwkSetUriReactiveJwtDecoderBuilder} for further configurations
	 */
	public T jwsAlgorithm(SignatureAlgorithm signatureAlgorithm) {
		Assert.notNull(signatureAlgorithm, "sig cannot be null");
		this.signatureAlgorithms.add(signatureAlgorithm);
		return self();
	}

	/**
	 * Configure the list of
	 * <a href="https://tools.ietf.org/html/rfc7515#section-4.1.1" target="_blank">algorithms</a>
	 * to use with the given {@link Consumer}.
	 *
	 * @param signatureAlgorithmsConsumer a {@link Consumer} for further configuring the algorithm list
	 * @return a {@link NimbusReactiveJwtDecoder.JwkSetUriReactiveJwtDecoderBuilder} for further configurations
	 */
	public T jwsAlgorithms(Consumer<Set<SignatureAlgorithm>> signatureAlgorithmsConsumer) {
		Assert.notNull(signatureAlgorithmsConsumer, "signatureAlgorithmsConsumer cannot be null");
		signatureAlgorithmsConsumer.accept(this.signatureAlgorithms);
		return self();
	}

	/**
	 * Fetches {@link SignatureAlgorithm}s based on the configured {@link JWKSource}s keys.
	 * @param jwkSource
	 * @return A set of {@link JWSAlgorithm}s to be used for JWT signature verification.
	 */
	protected Set<JWSAlgorithm> getSignatureAlgorithms(JWKSource<SecurityContext> jwkSource) {
		Set<SignatureAlgorithm> jwkAlgorithms = getDefaultAlgorithms();
		try {
			jwkAlgorithms.addAll(fetchSignatureVerificationAlgorithms(jwkSource));
		} catch (Exception ex) {
			log.error("Error fetching Signature Verification algorithms");
		}
		return convertToJwsAlgorithms(jwkAlgorithms);
	}

	/**
	 * Fetches {@link SignatureAlgorithm}s based on the configured {@link ReactiveJWKSource}s keys.
	 * @param jwkSource
	 * @return A set of {@link JWSAlgorithm}s to be used for JWT signature verification.
	 */
	protected Set<JWSAlgorithm> getSignatureAlgorithms(ReactiveJWKSource jwkSource) {
		Set<SignatureAlgorithm> jwkAlgorithms = getDefaultAlgorithms();
		try {
			jwkAlgorithms.addAll(fetchSignatureVerificationAlgorithms(jwkSource));
		} catch (Exception ex) {
			log.error("Error fetching Signature Verification algorithms");
		}
		return convertToJwsAlgorithms(jwkAlgorithms);
	}

	/**
	 * Retains the original functionality for adding {@link SignatureAlgorithm#RS256} as a default algorithm if none are provided.
	 * @return A set of default {@link SignatureAlgorithm}s
	 */
	private Set<SignatureAlgorithm> getDefaultAlgorithms() {
		Set<SignatureAlgorithm> jwkAlgorithms = new HashSet<>();
		if (this.signatureAlgorithms.isEmpty()) {
			jwkAlgorithms.add(SignatureAlgorithm.RS256);
		} else {
			jwkAlgorithms.addAll(this.signatureAlgorithms);
		}
		return jwkAlgorithms;
	}

	private Set<JWSAlgorithm> convertToJwsAlgorithms(Set<SignatureAlgorithm> algorithms) {
		return algorithms.stream()
				.map(algorithm -> JWSAlgorithm.parse(algorithm.getName()))
				.collect(Collectors.toSet());
	}

	/**
	 * Given a valid {@link JWKSource}, fetches, and parses out the algorithms of available JWKs.
	 * @param jwkSource
	 * @return A set of {@link SignatureAlgorithm} instances that may be used to validate a JWT (JWS).
	 */
	private Set<SignatureAlgorithm> fetchSignatureVerificationAlgorithms(JWKSource<SecurityContext> jwkSource) {
		return fetchSignatureVerificationAlgorithms(fetchSignatureVerificationJwks(jwkSource));
	}

	/**
	 * Given a valid {@link ReactiveJWKSource}, fetches, and parses out the algorithms of available JWKs.
	 * @param jwkSource
	 * @return A set of {@link SignatureAlgorithm} instances that may be used to validate a JWT (JWS).
	 */
	private Set<SignatureAlgorithm> fetchSignatureVerificationAlgorithms(ReactiveJWKSource jwkSource) {
		return fetchSignatureVerificationAlgorithms(fetchSignatureVerificationJwks(jwkSource));
	}

	/**
	 * Converts a list of {@link JWK}s into a set of {@link SignatureAlgorithm}s.
	 * @param jwks
	 * @return A set of {@link SignatureAlgorithm} instances that may be used to validate a JWT (JWS).
	 */
	private Set<SignatureAlgorithm> fetchSignatureVerificationAlgorithms(List<JWK> jwks) {
		if (jwks == null) {
			return Collections.emptySet();
		}
		return jwks.stream().map(jwk -> {
			Algorithm algorithm = jwk.getAlgorithm();
			if (algorithm != null) {
				return SignatureAlgorithm.from(algorithm.getName());
			}
			return null;
		}).filter(Objects::nonNull).collect(Collectors.toSet());
	}

	/**
	 * Given a valid {@link JWKSource}, fetches the raw list of available {@link JWK}s.
	 * @param jwkSource
	 * @return An filtered list of available {@link JWK}s from the given source that may be used for JWT signature verification.
	 */
	private List<JWK> fetchSignatureVerificationJwks(JWKSource<SecurityContext> jwkSource) {
		try {
			return jwkSource.get(getSignatureVerificationKeySelector(), null);
		} catch (Exception ex) {
			log.error("Error fetching Signature Algorithms from JWK source.");
		}
		return Collections.emptyList();
	}

	/**
	 * Given a valid {@link ReactiveJWKSource}, fetches the raw list of available {@link JWK}s.
	 * @param jwkSource
	 * @return An filtered list of available {@link JWK}s from the given source that may be used for JWT signature verification.
	 */
	private List<JWK> fetchSignatureVerificationJwks(ReactiveJWKSource jwkSource) {
		return jwkSource.get(getSignatureVerificationKeySelector()).block();
	}

	private JWKSelector getSignatureVerificationKeySelector() {
		return new JWKSelector(new JWKMatcher.Builder()
				.keyUse(KeyUse.SIGNATURE)
				.build());
	}

	/**
	 * Converts a {@link String} into a {@link URL}.
	 * @param url the source URL string.
	 * @return a {@link URL} version of the source URL string.
	 */
	protected static URL toURL(String url) {
		try {
			return new URL(url);
		} catch (MalformedURLException ex) {
			throw new IllegalArgumentException("Invalid JWK Set URL \"" + url + "\" : " + ex.getMessage(), ex);
		}
	}

}
