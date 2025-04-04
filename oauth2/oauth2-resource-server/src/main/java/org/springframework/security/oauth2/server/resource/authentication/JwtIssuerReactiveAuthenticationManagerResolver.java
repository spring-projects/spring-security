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

package org.springframework.security.oauth2.server.resource.authentication;

import java.time.Duration;
import java.util.Collection;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Predicate;

import com.nimbusds.jwt.JWTParser;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import org.springframework.core.convert.converter.Converter;
import org.springframework.core.log.LogMessage;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoders;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.util.Assert;
import org.springframework.web.server.ServerWebExchange;

/**
 * An implementation of {@link ReactiveAuthenticationManagerResolver} that resolves a
 * JWT-based {@link ReactiveAuthenticationManager} based on the <a href=
 * "https://openid.net/specs/openid-connect-core-1_0.html#IssuerIdentifier">Issuer</a> in
 * a signed JWT (JWS).
 *
 * To use, this class must be able to determine whether the `iss` claim is trusted. Recall
 * that anyone can stand up an authorization server and issue valid tokens to a resource
 * server. The simplest way to achieve this is to supply a set of trusted issuers in the
 * constructor.
 *
 * This class derives the Issuer from the `iss` claim found in the
 * {@link ServerWebExchange}'s
 * <a href="https://tools.ietf.org/html/rfc6750#section-1.2" target="_blank">Bearer
 * Token</a>.
 *
 * @author Josh Cummings
 * @author Roman Matiushchenko
 * @since 5.3
 */
public final class JwtIssuerReactiveAuthenticationManagerResolver
		implements ReactiveAuthenticationManagerResolver<ServerWebExchange> {

	private final ReactiveAuthenticationManager authenticationManager;

	/**
	 * Construct a {@link JwtIssuerReactiveAuthenticationManagerResolver} using the
	 * provided parameters
	 * @param trustedIssuers an array of trusted issuers
	 * @deprecated use {@link #fromTrustedIssuers(String...)}
	 */
	@Deprecated(since = "6.2", forRemoval = true)
	public JwtIssuerReactiveAuthenticationManagerResolver(String... trustedIssuers) {
		this(Set.of(trustedIssuers));
	}

	/**
	 * Construct a {@link JwtIssuerReactiveAuthenticationManagerResolver} using the
	 * provided parameters
	 * @param trustedIssuers a collection of trusted issuers
	 * @deprecated use {@link #fromTrustedIssuers(Collection)}
	 */
	@Deprecated(since = "6.2", forRemoval = true)
	public JwtIssuerReactiveAuthenticationManagerResolver(Collection<String> trustedIssuers) {
		Assert.notEmpty(trustedIssuers, "trustedIssuers cannot be empty");
		this.authenticationManager = new ResolvingAuthenticationManager(
				new TrustedIssuerJwtAuthenticationManagerResolver(Set.copyOf(trustedIssuers)::contains));
	}

	/**
	 * Construct a {@link JwtIssuerReactiveAuthenticationManagerResolver} using the
	 * provided parameters
	 * @param trustedIssuers an array of trusted issuers
	 * @since 6.2
	 */
	public static JwtIssuerReactiveAuthenticationManagerResolver fromTrustedIssuers(String... trustedIssuers) {
		return fromTrustedIssuers(Set.of(trustedIssuers));
	}

	/**
	 * Construct a {@link JwtIssuerReactiveAuthenticationManagerResolver} using the
	 * provided parameters
	 * @param trustedIssuers a collection of trusted issuers
	 * @since 6.2
	 */
	public static JwtIssuerReactiveAuthenticationManagerResolver fromTrustedIssuers(Collection<String> trustedIssuers) {
		Assert.notEmpty(trustedIssuers, "trustedIssuers cannot be empty");
		return fromTrustedIssuers(Set.copyOf(trustedIssuers)::contains);
	}

	/**
	 * Construct a {@link JwtIssuerReactiveAuthenticationManagerResolver} using the
	 * provided parameters
	 * @param trustedIssuers a predicate to validate issuers
	 * @since 6.2
	 */
	public static JwtIssuerReactiveAuthenticationManagerResolver fromTrustedIssuers(Predicate<String> trustedIssuers) {
		Assert.notNull(trustedIssuers, "trustedIssuers cannot be null");
		return new JwtIssuerReactiveAuthenticationManagerResolver(
				new TrustedIssuerJwtAuthenticationManagerResolver(trustedIssuers));
	}

	/**
	 * Construct a {@link JwtIssuerReactiveAuthenticationManagerResolver} using the
	 * provided parameters
	 *
	 * Note that the {@link ReactiveAuthenticationManagerResolver} provided in this
	 * constructor will need to verify that the issuer is trusted. This should be done via
	 * an allowed set of issuers.
	 *
	 * One way to achieve this is with a {@link Map} where the keys are the known issuers:
	 * <pre>
	 *     Map&lt;String, ReactiveAuthenticationManager&gt; authenticationManagers = new HashMap&lt;&gt;();
	 *     authenticationManagers.put("https://issuerOne.example.org", managerOne);
	 *     authenticationManagers.put("https://issuerTwo.example.org", managerTwo);
	 *     JwtIssuerReactiveAuthenticationManagerResolver resolver = new JwtIssuerReactiveAuthenticationManagerResolver
	 *     	((issuer) -&gt; Mono.justOrEmpty(authenticationManagers.get(issuer));
	 * </pre>
	 *
	 * The keys in the {@link Map} are the trusted issuers.
	 * @param issuerAuthenticationManagerResolver a strategy for resolving the
	 * {@link ReactiveAuthenticationManager} by the issuer
	 */
	public JwtIssuerReactiveAuthenticationManagerResolver(
			ReactiveAuthenticationManagerResolver<String> issuerAuthenticationManagerResolver) {
		Assert.notNull(issuerAuthenticationManagerResolver, "issuerAuthenticationManagerResolver cannot be null");
		this.authenticationManager = new ResolvingAuthenticationManager(issuerAuthenticationManagerResolver);
	}

	/**
	 * Return an {@link AuthenticationManager} based off of the `iss` claim found in the
	 * request's bearer token
	 * @throws OAuth2AuthenticationException if the bearer token is malformed or an
	 * {@link ReactiveAuthenticationManager} can't be derived from the issuer
	 */
	@Override
	public Mono<ReactiveAuthenticationManager> resolve(ServerWebExchange exchange) {
		return Mono.just(this.authenticationManager);
	}

	private static class ResolvingAuthenticationManager implements ReactiveAuthenticationManager {

		private final Converter<BearerTokenAuthenticationToken, Mono<String>> issuerConverter = new JwtClaimIssuerConverter();

		private final ReactiveAuthenticationManagerResolver<String> issuerAuthenticationManagerResolver;

		ResolvingAuthenticationManager(
				ReactiveAuthenticationManagerResolver<String> issuerAuthenticationManagerResolver) {

			this.issuerAuthenticationManagerResolver = issuerAuthenticationManagerResolver;
		}

		@Override
		public Mono<Authentication> authenticate(Authentication authentication) {
			Assert.isTrue(authentication instanceof BearerTokenAuthenticationToken,
					"Authentication must be of type BearerTokenAuthenticationToken");
			BearerTokenAuthenticationToken token = (BearerTokenAuthenticationToken) authentication;
			return this.issuerConverter.convert(token)
				.flatMap((issuer) -> this.issuerAuthenticationManagerResolver.resolve(issuer)
					.switchIfEmpty(Mono.error(() -> {
						AuthenticationException ex = new InvalidBearerTokenException("Invalid issuer " + issuer);
						ex.setAuthenticationRequest(authentication);
						return ex;
					})))
				.flatMap((manager) -> manager.authenticate(authentication))
				.doOnError(AuthenticationException.class, (ex) -> ex.setAuthenticationRequest(authentication));
		}

	}

	private static class JwtClaimIssuerConverter implements Converter<BearerTokenAuthenticationToken, Mono<String>> {

		@Override
		public Mono<String> convert(@NonNull BearerTokenAuthenticationToken token) {
			try {
				String issuer = JWTParser.parse(token.getToken()).getJWTClaimsSet().getIssuer();
				if (issuer == null) {
					AuthenticationException ex = new InvalidBearerTokenException("Missing issuer");
					ex.setAuthenticationRequest(token);
					throw ex;
				}
				return Mono.just(issuer);
			}
			catch (Exception cause) {
				return Mono.error(() -> {
					AuthenticationException ex = new InvalidBearerTokenException(cause.getMessage(), cause);
					ex.setAuthenticationRequest(token);
					return ex;
				});
			}
		}

	}

	static class TrustedIssuerJwtAuthenticationManagerResolver
			implements ReactiveAuthenticationManagerResolver<String> {

		private final Log logger = LogFactory.getLog(getClass());

		private final Map<String, Mono<ReactiveAuthenticationManager>> authenticationManagers = new ConcurrentHashMap<>();

		private final Predicate<String> trustedIssuer;

		TrustedIssuerJwtAuthenticationManagerResolver(Predicate<String> trustedIssuer) {
			this.trustedIssuer = trustedIssuer;
		}

		@Override
		public Mono<ReactiveAuthenticationManager> resolve(String issuer) {
			if (!this.trustedIssuer.test(issuer)) {
				this.logger.debug("Did not resolve AuthenticationManager since issuer is not trusted");
				return Mono.empty();
			}
			// @formatter:off
			return this.authenticationManagers.computeIfAbsent(issuer,
					(k) -> Mono.<ReactiveAuthenticationManager>fromCallable(() -> new JwtReactiveAuthenticationManager(ReactiveJwtDecoders.fromIssuerLocation(k)))
							.doOnNext((manager) -> this.logger.debug(LogMessage.format("Resolved AuthenticationManager for issuer '%s'", issuer)))
							.subscribeOn(Schedulers.boundedElastic())
							.cache((manager) -> Duration.ofMillis(Long.MAX_VALUE), (ex) -> Duration.ZERO, () -> Duration.ZERO)
			);
			// @formatter:on
		}

	}

}
