/*
 * Copyright 2002-2024 the original author or authors.
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

import java.net.URI;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
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
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import org.springframework.core.ParameterizedTypeReference;
import org.springframework.util.Assert;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import org.springframework.web.util.UriComponentsBuilder;

final class ReactiveJwtDecoderProviderConfigurationUtils {

	private static final String OIDC_METADATA_PATH = "/.well-known/openid-configuration";

	private static final String OAUTH_METADATA_PATH = "/.well-known/oauth-authorization-server";

	private static final ParameterizedTypeReference<Map<String, Object>> STRING_OBJECT_MAP = new ParameterizedTypeReference<>() {
	};

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
		JWKMatcher jwkMatcher = new JWKMatcher.Builder().publicOnly(true)
			.keyUses(KeyUse.SIGNATURE, null)
			.keyTypes(KeyType.RSA, KeyType.EC)
			.build();
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
		}).onErrorMap(KeySourceException.class, IllegalStateException::new);
	}

	static Mono<Map<String, Object>> getConfigurationForIssuerLocation(String issuer, WebClient web) {
		URI uri = URI.create(issuer);
		return getConfiguration(issuer, web, oidc(uri), oidcRfc8414(uri), oauth(uri));
	}

	private static URI oidc(URI issuer) {
		// @formatter:off
		return UriComponentsBuilder.fromUri(issuer)
				.replacePath(issuer.getPath() + OIDC_METADATA_PATH)
				.build(Collections.emptyMap());
		// @formatter:on
	}

	private static URI oidcRfc8414(URI issuer) {
		// @formatter:off
		return UriComponentsBuilder.fromUri(issuer)
				.replacePath(OIDC_METADATA_PATH + issuer.getPath())
				.build(Collections.emptyMap());
		// @formatter:on
	}

	private static URI oauth(URI issuer) {
		// @formatter:off
		return UriComponentsBuilder.fromUri(issuer)
				.replacePath(OAUTH_METADATA_PATH + issuer.getPath())
				.build(Collections.emptyMap());
		// @formatter:on
	}

	private static Mono<Map<String, Object>> getConfiguration(String issuer, WebClient web, URI... uris) {
		String errorMessage = "Unable to resolve the Configuration with the provided Issuer of " + "\"" + issuer + "\"";
		return Flux.just(uris)
			.concatMap((uri) -> web.get().uri(uri).retrieve().bodyToMono(STRING_OBJECT_MAP))
			.flatMap((configuration) -> {
				if (configuration.get("jwks_uri") == null) {
					return Mono.error(() -> new IllegalArgumentException("The public JWK set URI must not be null"));
				}
				return Mono.just(configuration);
			})
			.onErrorContinue((ex) -> ex instanceof WebClientResponseException
					&& ((WebClientResponseException) ex).getStatusCode().is4xxClientError(), (ex, object) -> {
					})
			.onErrorMap(RuntimeException.class,
					(ex) -> (ex instanceof IllegalArgumentException) ? ex
							: new IllegalArgumentException(errorMessage, ex))
			.next()
			.switchIfEmpty(Mono.error(() -> new IllegalArgumentException(errorMessage)));
	}

	private ReactiveJwtDecoderProviderConfigurationUtils() {
	}

}
