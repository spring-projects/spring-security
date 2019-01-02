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

import com.nimbusds.jose.RemoteKeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.text.ParseException;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

/**
 * @author Rob Winch
 * @since 5.1
 */
class ReactiveRemoteJWKSource implements ReactiveJWKSource {
	/**
	 * The cached JWK set.
	 */
	private final AtomicReference<Mono<JWKSet>> cachedJWKSet = new AtomicReference<>(Mono.empty());

	private WebClient webClient;

	private final String jwkSetURL;

	ReactiveRemoteJWKSource(String jwkSetURL, WebClient webClient) {
		this.jwkSetURL = jwkSetURL;
		this.webClient = webClient;
	}

	public Mono<List<JWK>> get(JWKSelector jwkSelector) {
		return this.cachedJWKSet.get()
				.switchIfEmpty(getJWKSet())
				.flatMap(jwkSet -> get(jwkSelector, jwkSet))
				.switchIfEmpty(getJWKSet().map(jwkSet -> jwkSelector.select(jwkSet)));
	}

	private Mono<List<JWK>> get(JWKSelector jwkSelector, JWKSet jwkSet) {
		return Mono.defer(() -> {
			// Run the selector on the JWK set
			List<JWK> matches = jwkSelector.select(jwkSet);

			if (!matches.isEmpty()) {
				// Success
				return Mono.just(matches);
			}

			// Refresh the JWK set if the sought key ID is not in the cached JWK set

			// Looking for JWK with specific ID?
			String soughtKeyID = getFirstSpecifiedKeyID(jwkSelector.getMatcher());
			if (soughtKeyID == null) {
				// No key ID specified, return no matches
				return Mono.just(Collections.emptyList());
			}

			if (jwkSet.getKeyByKeyId(soughtKeyID) != null) {
				// The key ID exists in the cached JWK set, matching
				// failed for some other reason, return no matches
				return Mono.just(Collections.emptyList());
			}

			return Mono.empty();

		});
	}

	/**
	 * Updates the cached JWK set from the configured URL.
	 *
	 * @return The updated JWK set.
	 *
	 * @throws RemoteKeySourceException If JWK retrieval failed.
	 */
	private Mono<JWKSet> getJWKSet() {
		return this.webClient.get()
				.uri(this.jwkSetURL)
				.retrieve()
				.bodyToMono(String.class)
				.map(this::parse)
				.doOnNext(jwkSet -> this.cachedJWKSet.set(Mono.just(jwkSet)))
				.cache();
	}

	private JWKSet parse(String body) {
		try {
			return JWKSet.parse(body);
		}
		catch (ParseException e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * Returns the first specified key ID (kid) for a JWK matcher.
	 *
	 * @param jwkMatcher The JWK matcher. Must not be {@code null}.
	 *
	 * @return The first key ID, {@code null} if none.
	 */
	protected static String getFirstSpecifiedKeyID(final JWKMatcher jwkMatcher) {

		Set<String> keyIDs = jwkMatcher.getKeyIDs();

		if (keyIDs == null || keyIDs.isEmpty()) {
			return null;
		}

		for (String id: keyIDs) {
			if (id != null) {
				return id;
			}
		}
		return null; // No kid in matcher
	}
}
