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

import java.util.Collection;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Predicate;

import com.nimbusds.jwt.JWTParser;
import jakarta.servlet.http.HttpServletRequest;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.core.convert.converter.Converter;
import org.springframework.core.log.LogMessage;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.util.Assert;

/**
 * An implementation of {@link AuthenticationManagerResolver} that resolves a JWT-based
 * {@link AuthenticationManager} based on the <a href=
 * "https://openid.net/specs/openid-connect-core-1_0.html#IssuerIdentifier">Issuer</a> in
 * a signed JWT (JWS).
 *
 * To use, this class must be able to determine whether the `iss` claim is trusted. Recall
 * that anyone can stand up an authorization server and issue valid tokens to a resource
 * server. The simplest way to achieve this is to supply a set of trusted issuers in the
 * constructor.
 *
 * This class derives the Issuer from the `iss` claim found in the
 * {@link HttpServletRequest}'s
 * <a href="https://tools.ietf.org/html/rfc6750#section-1.2" target="_blank">Bearer
 * Token</a>.
 *
 * @author Josh Cummings
 * @since 5.3
 */
public final class JwtIssuerAuthenticationManagerResolver implements AuthenticationManagerResolver<HttpServletRequest> {

	private final AuthenticationManager authenticationManager;

	/**
	 * Construct a {@link JwtIssuerAuthenticationManagerResolver} using the provided
	 * parameters
	 * @param trustedIssuers an array of trusted issuers
	 * @deprecated use {@link #fromTrustedIssuers(String...)}
	 */
	@Deprecated(since = "6.2", forRemoval = true)
	public JwtIssuerAuthenticationManagerResolver(String... trustedIssuers) {
		this(Set.of(trustedIssuers));
	}

	/**
	 * Construct a {@link JwtIssuerAuthenticationManagerResolver} using the provided
	 * parameters
	 * @param trustedIssuers a collection of trusted issuers
	 * @deprecated use {@link #fromTrustedIssuers(Collection)}
	 */
	@Deprecated(since = "6.2", forRemoval = true)
	public JwtIssuerAuthenticationManagerResolver(Collection<String> trustedIssuers) {
		Assert.notEmpty(trustedIssuers, "trustedIssuers cannot be empty");
		this.authenticationManager = new ResolvingAuthenticationManager(
				new TrustedIssuerJwtAuthenticationManagerResolver(Set.copyOf(trustedIssuers)::contains));
	}

	/**
	 * Construct a {@link JwtIssuerAuthenticationManagerResolver} using the provided
	 * parameters
	 * @param trustedIssuers an array of trusted issuers
	 * @since 6.2
	 */
	public static JwtIssuerAuthenticationManagerResolver fromTrustedIssuers(String... trustedIssuers) {
		return fromTrustedIssuers(Set.of(trustedIssuers));
	}

	/**
	 * Construct a {@link JwtIssuerAuthenticationManagerResolver} using the provided
	 * parameters
	 * @param trustedIssuers a collection of trusted issuers
	 * @since 6.2
	 */
	public static JwtIssuerAuthenticationManagerResolver fromTrustedIssuers(Collection<String> trustedIssuers) {
		Assert.notEmpty(trustedIssuers, "trustedIssuers cannot be empty");
		return fromTrustedIssuers(Set.copyOf(trustedIssuers)::contains);
	}

	/**
	 * Construct a {@link JwtIssuerAuthenticationManagerResolver} using the provided
	 * parameters
	 * @param trustedIssuers a predicate to validate issuers
	 * @since 6.2
	 */
	public static JwtIssuerAuthenticationManagerResolver fromTrustedIssuers(Predicate<String> trustedIssuers) {
		Assert.notNull(trustedIssuers, "trustedIssuers cannot be null");
		return new JwtIssuerAuthenticationManagerResolver(
				new TrustedIssuerJwtAuthenticationManagerResolver(trustedIssuers));
	}

	/**
	 * Construct a {@link JwtIssuerAuthenticationManagerResolver} using the provided
	 * parameters
	 *
	 * Note that the {@link AuthenticationManagerResolver} provided in this constructor
	 * will need to verify that the issuer is trusted. This should be done via an allowed
	 * set of issuers.
	 *
	 * One way to achieve this is with a {@link Map} where the keys are the known issuers:
	 * <pre>
	 *     Map&lt;String, AuthenticationManager&gt; authenticationManagers = new HashMap&lt;&gt;();
	 *     authenticationManagers.put("https://issuerOne.example.org", managerOne);
	 *     authenticationManagers.put("https://issuerTwo.example.org", managerTwo);
	 *     JwtAuthenticationManagerResolver resolver = new JwtAuthenticationManagerResolver
	 *     	(authenticationManagers::get);
	 * </pre>
	 *
	 * The keys in the {@link Map} are the allowed issuers.
	 * @param issuerAuthenticationManagerResolver a strategy for resolving the
	 * {@link AuthenticationManager} by the issuer
	 */
	public JwtIssuerAuthenticationManagerResolver(
			AuthenticationManagerResolver<String> issuerAuthenticationManagerResolver) {
		Assert.notNull(issuerAuthenticationManagerResolver, "issuerAuthenticationManagerResolver cannot be null");
		this.authenticationManager = new ResolvingAuthenticationManager(issuerAuthenticationManagerResolver);
	}

	/**
	 * Return an {@link AuthenticationManager} based off of the `iss` claim found in the
	 * request's bearer token
	 * @throws OAuth2AuthenticationException if the bearer token is malformed or an
	 * {@link AuthenticationManager} can't be derived from the issuer
	 */
	@Override
	public AuthenticationManager resolve(HttpServletRequest request) {
		return this.authenticationManager;
	}

	private static class ResolvingAuthenticationManager implements AuthenticationManager {

		private final Converter<BearerTokenAuthenticationToken, String> issuerConverter = new JwtClaimIssuerConverter();

		private final AuthenticationManagerResolver<String> issuerAuthenticationManagerResolver;

		ResolvingAuthenticationManager(AuthenticationManagerResolver<String> issuerAuthenticationManagerResolver) {
			this.issuerAuthenticationManagerResolver = issuerAuthenticationManagerResolver;
		}

		@Override
		public Authentication authenticate(Authentication authentication) throws AuthenticationException {
			Assert.isTrue(authentication instanceof BearerTokenAuthenticationToken,
					"Authentication must be of type BearerTokenAuthenticationToken");
			BearerTokenAuthenticationToken token = (BearerTokenAuthenticationToken) authentication;
			String issuer = this.issuerConverter.convert(token);
			AuthenticationManager authenticationManager = this.issuerAuthenticationManagerResolver.resolve(issuer);
			if (authenticationManager == null) {
				AuthenticationException ex = new InvalidBearerTokenException("Invalid issuer");
				ex.setAuthenticationRequest(authentication);
				throw ex;
			}
			try {
				return authenticationManager.authenticate(authentication);
			}
			catch (AuthenticationException ex) {
				ex.setAuthenticationRequest(authentication);
				throw ex;
			}
		}

	}

	private static class JwtClaimIssuerConverter implements Converter<BearerTokenAuthenticationToken, String> {

		@Override
		public String convert(@NonNull BearerTokenAuthenticationToken authentication) {
			String token = authentication.getToken();
			try {
				String issuer = JWTParser.parse(token).getJWTClaimsSet().getIssuer();
				if (issuer != null) {
					return issuer;
				}
			}
			catch (Exception cause) {
				AuthenticationException ex = new InvalidBearerTokenException(cause.getMessage(), cause);
				ex.setAuthenticationRequest(authentication);
				throw ex;
			}
			AuthenticationException ex = new InvalidBearerTokenException("Missing issuer");
			ex.setAuthenticationRequest(authentication);
			throw ex;
		}

	}

	static class TrustedIssuerJwtAuthenticationManagerResolver implements AuthenticationManagerResolver<String> {

		private final Log logger = LogFactory.getLog(getClass());

		private final Map<String, AuthenticationManager> authenticationManagers = new ConcurrentHashMap<>();

		private final Predicate<String> trustedIssuer;

		TrustedIssuerJwtAuthenticationManagerResolver(Predicate<String> trustedIssuer) {
			this.trustedIssuer = trustedIssuer;
		}

		@Override
		public AuthenticationManager resolve(String issuer) {
			if (this.trustedIssuer.test(issuer)) {
				AuthenticationManager authenticationManager = this.authenticationManagers.computeIfAbsent(issuer,
						(k) -> {
							this.logger.debug("Constructing AuthenticationManager");
							JwtDecoder jwtDecoder = JwtDecoders.fromIssuerLocation(issuer);
							return new JwtAuthenticationProvider(jwtDecoder)::authenticate;
						});
				this.logger.debug(LogMessage.format("Resolved AuthenticationManager for issuer '%s'", issuer));
				return authenticationManager;
			}
			else {
				this.logger.debug("Did not resolve AuthenticationManager since issuer is not trusted");
			}
			return null;
		}

	}

}
