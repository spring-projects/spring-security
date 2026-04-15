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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jspecify.annotations.Nullable;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.util.Assert;

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
 * @author Bapuji Koraganti
 * @since 7.0
 * @see OAuth2TokenExchangeSubjectTokenResolver
 * @see OAuth2TokenExchangeSubjectTokenContext
 * @see JwtDecoderFactory
 */
public final class OidcIdTokenSubjectTokenResolver implements OAuth2TokenExchangeSubjectTokenResolver {

	private static final String ID_TOKEN_TYPE_VALUE = "urn:ietf:params:oauth:token-type:id_token";

	private final Log logger = LogFactory.getLog(getClass());

	private final JwtDecoderFactory<RegisteredClient> jwtDecoderFactory;

	/**
	 * Constructs an {@code OidcIdTokenSubjectTokenResolver} using the provided
	 * parameters.
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
