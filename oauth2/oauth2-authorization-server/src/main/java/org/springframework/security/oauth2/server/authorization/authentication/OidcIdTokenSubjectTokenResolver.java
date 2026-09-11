/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.oauth2.server.authorization.authentication;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jspecify.annotations.Nullable;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * An {@link OAuth2TokenExchangeSubjectTokenResolver} implementation that resolves
 * externally-issued OIDC ID tokens using a configurable {@link JwtDecoderFactory}.
 *
 * <p>
 * This resolver activates when the {@code subject_token_type} is
 * {@code urn:ietf:params:oauth:token-type:id_token}. It decodes and validates the ID
 * token using a {@link JwtDecoder} obtained from the provided factory, then constructs an
 * {@link OAuth2TokenExchangeSubjectTokenContext} from the token's claims.
 *
 * <p>
 * When constructed with no arguments, the resolver uses the
 * {@link ClientSettings#getIdTokenJwkSetUrl()} setting to resolve the external IdP's JWKS
 * endpoint per client. Example client registration:
 *
 * <pre>
 * RegisteredClient.withId(UUID.randomUUID().toString())
 *     .clientId("cicd-client")
 *     .clientSettings(ClientSettings.builder()
 *         .idTokenJwkSetUrl("https://gitlab.com/oauth/discovery/keys")
 *         .build())
 *     .build();
 * </pre>
 *
 * <p>
 * For advanced use cases (e.g., multi-issuer routing, custom validation), a custom
 * {@link JwtDecoderFactory} can be provided via the constructor.
 *
 * @author Bapuji Koraganti
 * @since 7.0
 * @see OAuth2TokenExchangeSubjectTokenResolver
 * @see OAuth2TokenExchangeSubjectTokenContext
 * @see JwtDecoderFactory
 * @see ClientSettings#getIdTokenJwkSetUrl()
 */
public final class OidcIdTokenSubjectTokenResolver implements OAuth2TokenExchangeSubjectTokenResolver {

	private static final String ID_TOKEN_TYPE_VALUE = "urn:ietf:params:oauth:token-type:id_token";

	private final Log logger = LogFactory.getLog(getClass());

	private final JwtDecoderFactory<RegisteredClient> jwtDecoderFactory;

	/**
	 * Constructs an {@code OidcIdTokenSubjectTokenResolver} that uses the
	 * {@link ClientSettings#getIdTokenJwkSetUrl()} setting to resolve the external IdP's
	 * JWKS endpoint for each client. Decoders are cached per client.
	 * @since 7.0
	 */
	public OidcIdTokenSubjectTokenResolver() {
		this(new DefaultIdTokenJwtDecoderFactory());
	}

	/**
	 * Constructs an {@code OidcIdTokenSubjectTokenResolver} using the provided
	 * {@link JwtDecoderFactory}.
	 * @param jwtDecoderFactory the factory for creating {@link JwtDecoder} instances
	 * keyed by {@link RegisteredClient}
	 */
	public OidcIdTokenSubjectTokenResolver(JwtDecoderFactory<RegisteredClient> jwtDecoderFactory) {
		Assert.notNull(jwtDecoderFactory, "jwtDecoderFactory cannot be null");
		this.jwtDecoderFactory = jwtDecoderFactory;
	}

	@Override
	public @Nullable OAuth2TokenExchangeSubjectTokenContext resolve(String subjectToken, String subjectTokenType,
			RegisteredClient registeredClient) {
		if (!ID_TOKEN_TYPE_VALUE.equals(subjectTokenType)) {
			return null;
		}

		JwtDecoder jwtDecoder = this.jwtDecoderFactory.createDecoder(registeredClient);
		Jwt jwt;
		try {
			jwt = jwtDecoder.decode(subjectToken);
		}
		catch (JwtException ex) {
			if (this.logger.isDebugEnabled()) {
				this.logger.debug("Failed to decode ID token: " + ex.getMessage());
			}
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
		}

		String subject = jwt.getSubject();
		if (subject == null) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
		}

		Authentication principal = new IdTokenAuthenticationToken(subject);

		return new OAuth2TokenExchangeSubjectTokenContext(principal, subject, jwt.getClaims(), Collections.emptySet());
	}

	/**
	 * Default {@link JwtDecoderFactory} that reads the JWKS endpoint from
	 * {@link ClientSettings#getIdTokenJwkSetUrl()} and caches decoders per client.
	 */
	private static final class DefaultIdTokenJwtDecoderFactory implements JwtDecoderFactory<RegisteredClient> {

		private final Map<String, JwtDecoder> jwtDecoders = new ConcurrentHashMap<>();

		@Override
		public JwtDecoder createDecoder(RegisteredClient registeredClient) {
			return this.jwtDecoders.computeIfAbsent(registeredClient.getId(), (key) -> {
				String idTokenJwkSetUrl = registeredClient.getClientSettings().getIdTokenJwkSetUrl();
				if (!StringUtils.hasText(idTokenJwkSetUrl)) {
					OAuth2Error oauth2Error = new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT,
							"Failed to find an ID Token Verifier for Client: '" + registeredClient.getId()
									+ "'. Check to ensure you have configured the ID Token JWK Set URL.",
							null);
					throw new OAuth2AuthenticationException(oauth2Error);
				}
				return NimbusJwtDecoder.withJwkSetUri(idTokenJwkSetUrl).build();
			});
		}

	}

	/**
	 * An {@link Authentication} representing a principal resolved from an
	 * externally-issued ID token.
	 */
	private static final class IdTokenAuthenticationToken extends AbstractAuthenticationToken {

		private static final long serialVersionUID = 1L;

		private final String subject;

		IdTokenAuthenticationToken(String subject) {
			super(List.of());
			this.subject = subject;
			setAuthenticated(true);
		}

		@Override
		public Object getCredentials() {
			return "";
		}

		@Override
		public Object getPrincipal() {
			return this.subject;
		}

	}

}
