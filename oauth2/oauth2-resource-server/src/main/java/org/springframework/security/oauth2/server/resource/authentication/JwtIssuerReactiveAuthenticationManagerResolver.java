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

package org.springframework.security.oauth2.server.resource.authentication;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Predicate;

import com.nimbusds.jwt.JWTParser;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import org.springframework.core.convert.converter.Converter;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoders;
import org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.oauth2.server.resource.web.server.ServerBearerTokenAuthenticationConverter;
import org.springframework.util.Assert;
import org.springframework.web.server.ServerWebExchange;

/**
 * An implementation of {@link ReactiveAuthenticationManagerResolver} that resolves a JWT-based
 * {@link ReactiveAuthenticationManager} based on the
 * <a href="https://openid.net/specs/openid-connect-core-1_0.html#IssuerIdentifier">Issuer</a> in a
 * signed JWT (JWS).
 *
 * To use, this class must be able to determine whether or not the `iss` claim is trusted. Recall that
 * anyone can stand up an authorization server and issue valid tokens to a resource server. The simplest way
 * to achieve this is to supply a whitelist of trusted issuers in the constructor.
 *
 * This class derives the Issuer from the `iss` claim found in the {@link ServerWebExchange}'s
 * <a href="https://tools.ietf.org/html/rfc6750#section-1.2" target="_blank">Bearer Token</a>.
 *
 * @author Josh Cummings
 * @since 5.3
 */
public final class JwtIssuerReactiveAuthenticationManagerResolver
		implements ReactiveAuthenticationManagerResolver<ServerWebExchange> {

	private final ReactiveAuthenticationManagerResolver<String> issuerAuthenticationManagerResolver;
	private final Converter<ServerWebExchange, Mono<String>> issuerConverter = new JwtClaimIssuerConverter();

	/**
	 * Construct a {@link JwtIssuerReactiveAuthenticationManagerResolver} using the provided parameters
	 *
	 * @param trustedIssuers a whitelist of trusted issuers
	 */
	public JwtIssuerReactiveAuthenticationManagerResolver(String... trustedIssuers) {
		this(Arrays.asList(trustedIssuers));
	}

	/**
	 * Construct a {@link JwtIssuerReactiveAuthenticationManagerResolver} using the provided parameters
	 *
	 * @param trustedIssuers a whitelist of trusted issuers
	 */
	public JwtIssuerReactiveAuthenticationManagerResolver(Collection<String> trustedIssuers) {
		Assert.notEmpty(trustedIssuers, "trustedIssuers cannot be empty");
		this.issuerAuthenticationManagerResolver =
				new TrustedIssuerJwtAuthenticationManagerResolver
						(Collections.unmodifiableCollection(trustedIssuers)::contains);
	}

	/**
	 * Construct a {@link JwtIssuerReactiveAuthenticationManagerResolver} using the provided parameters
	 *
	 * Note that the {@link ReactiveAuthenticationManagerResolver} provided in this constructor will need to
	 * verify that the issuer is trusted. This should be done via a whitelist.
	 *
	 * One way to achieve this is with a {@link Map} where the keys are the known issuers:
	 * <pre>
	 *     Map&lt;String, ReactiveAuthenticationManager&gt; authenticationManagers = new HashMap&lt;&gt;();
	 *     authenticationManagers.put("https://issuerOne.example.org", managerOne);
	 *     authenticationManagers.put("https://issuerTwo.example.org", managerTwo);
	 *     JwtIssuerReactiveAuthenticationManagerResolver resolver = new JwtIssuerReactiveAuthenticationManagerResolver
	 *     	(issuer -> Mono.justOrEmpty(authenticationManagers.get(issuer));
	 * </pre>
	 *
	 * The keys in the {@link Map} are the whitelist.
	 *
	 * @param issuerAuthenticationManagerResolver a strategy for resolving the {@link ReactiveAuthenticationManager}
	 * by the issuer
	 */
	public JwtIssuerReactiveAuthenticationManagerResolver
			(ReactiveAuthenticationManagerResolver<String> issuerAuthenticationManagerResolver) {

		Assert.notNull(issuerAuthenticationManagerResolver, "issuerAuthenticationManagerResolver cannot be null");
		this.issuerAuthenticationManagerResolver = issuerAuthenticationManagerResolver;
	}

	/**
	 * Return an {@link AuthenticationManager} based off of the `iss` claim found in the request's bearer token
	 *
	 * @throws OAuth2AuthenticationException if the bearer token is malformed or an {@link ReactiveAuthenticationManager}
	 * can't be derived from the issuer
	 */
	@Override
	public Mono<ReactiveAuthenticationManager> resolve(ServerWebExchange exchange) {
		return this.issuerConverter.convert(exchange)
				.flatMap(issuer ->
					this.issuerAuthenticationManagerResolver.resolve(issuer).switchIfEmpty(
							Mono.error(new InvalidBearerTokenException("Invalid issuer " + issuer)))
				);
	}

	private static class JwtClaimIssuerConverter
			implements Converter<ServerWebExchange, Mono<String>> {

		private final ServerBearerTokenAuthenticationConverter converter =
				new ServerBearerTokenAuthenticationConverter();

		@Override
		public Mono<String> convert(@NonNull ServerWebExchange exchange) {
			return this.converter.convert(exchange)
					.cast(BearerTokenAuthenticationToken.class)
					.flatMap(this::issuer);
		}

		private Mono<String> issuer(BearerTokenAuthenticationToken token) {
			try {
				String issuer = JWTParser.parse(token.getToken()).getJWTClaimsSet().getIssuer();
				return Mono.justOrEmpty(issuer).switchIfEmpty(
						Mono.error(new InvalidBearerTokenException("Missing issuer")));
			} catch (Exception e) {
				return Mono.error(new InvalidBearerTokenException(e.getMessage()));
			}
		}
	}

	private static class TrustedIssuerJwtAuthenticationManagerResolver
			implements ReactiveAuthenticationManagerResolver<String> {

		private final Map<String, Mono<? extends ReactiveAuthenticationManager>> authenticationManagers =
				new ConcurrentHashMap<>();
		private final Predicate<String> trustedIssuer;

		TrustedIssuerJwtAuthenticationManagerResolver(Predicate<String> trustedIssuer) {
			this.trustedIssuer = trustedIssuer;
		}

		@Override
		public Mono<ReactiveAuthenticationManager> resolve(String issuer) {
			return Mono.just(issuer)
					.filter(this.trustedIssuer)
					.flatMap(iss ->
						this.authenticationManagers.computeIfAbsent(iss, k ->
							Mono.fromCallable(() -> ReactiveJwtDecoders.fromIssuerLocation(iss))
									.subscribeOn(Schedulers.boundedElastic())
									.map(JwtReactiveAuthenticationManager::new)
									.cache())
					);
		}
	}
}
