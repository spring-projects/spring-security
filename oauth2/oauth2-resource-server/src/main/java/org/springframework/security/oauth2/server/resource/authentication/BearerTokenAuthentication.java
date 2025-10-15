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

package org.springframework.security.oauth2.server.resource.authentication;

import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

import org.jspecify.annotations.Nullable;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.BuildableAuthentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.Transient;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.util.Assert;

/**
 * An {@link org.springframework.security.core.Authentication} token that represents a
 * successful authentication as obtained through a bearer token.
 *
 * @author Josh Cummings
 * @since 5.2
 */
@Transient
public class BearerTokenAuthentication extends AbstractOAuth2TokenAuthenticationToken<OAuth2AccessToken>
		implements BuildableAuthentication {

	private static final long serialVersionUID = 620L;

	private final Map<String, Object> attributes;

	/**
	 * Constructs a {@link BearerTokenAuthentication} with the provided arguments
	 * @param principal The OAuth 2.0 attributes
	 * @param credentials The verified token
	 * @param authorities The authorities associated with the given token
	 */
	public BearerTokenAuthentication(OAuth2AuthenticatedPrincipal principal, OAuth2AccessToken credentials,
			Collection<? extends GrantedAuthority> authorities) {
		super(credentials, principal, credentials, authorities);
		Assert.isTrue(credentials.getTokenType() == OAuth2AccessToken.TokenType.BEARER,
				"credentials must be a bearer token");
		this.attributes = Collections.unmodifiableMap(new LinkedHashMap<>(principal.getAttributes()));
		setAuthenticated(true);
	}

	protected BearerTokenAuthentication(Builder<?> builder) {
		super(builder);
		this.attributes = Collections.unmodifiableMap(new LinkedHashMap<>(builder.attributes));
	}

	@Override
	public Map<String, Object> getTokenAttributes() {
		return this.attributes;
	}

	@Override
	public Builder<?> toBuilder() {
		return new Builder<>(this);
	}

	/**
	 * A builder preserving the concrete {@link Authentication} type
	 *
	 * @since 7.0
	 */
	public static class Builder<B extends Builder<B>>
			extends AbstractOAuth2TokenAuthenticationBuilder<OAuth2AccessToken, B> {

		private Map<String, Object> attributes;

		protected Builder(BearerTokenAuthentication token) {
			super(token);
			this.attributes = token.getTokenAttributes();
		}

		/**
		 * Use this principal. Must be of type {@link OAuth2AuthenticatedPrincipal}
		 * @param principal the principal to use
		 * @return the {@link Builder} for further configurations
		 */
		@Override
		public B principal(@Nullable Object principal) {
			Assert.isInstanceOf(OAuth2AuthenticatedPrincipal.class, principal,
					"principal must be of type OAuth2AuthenticatedPrincipal");
			this.attributes = ((OAuth2AuthenticatedPrincipal) principal).getAttributes();
			return super.principal(principal);
		}

		/**
		 * A synonym for {@link #token(OAuth2AccessToken)}
		 * @param token the token to use
		 * @return the {@link Builder} for further configurations
		 */
		@Override
		public B credentials(@Nullable Object token) {
			Assert.isInstanceOf(OAuth2AccessToken.class, token, "token must be of type OAuth2AccessToken");
			return token((OAuth2AccessToken) token);
		}

		/**
		 * Use this token. Must have a {@link OAuth2AccessToken#getTokenType()} as
		 * {@link OAuth2AccessToken.TokenType#BEARER}.
		 * @param token the token to use
		 * @return the {@link Builder} for further configurations
		 */
		@Override
		public B token(OAuth2AccessToken token) {
			Assert.isTrue(token.getTokenType() == OAuth2AccessToken.TokenType.BEARER, "token must be a bearer token");
			super.credentials(token);
			return super.token(token);
		}

		/**
		 * {@inheritDoc}
		 */
		@Override
		public BearerTokenAuthentication build() {
			return new BearerTokenAuthentication(this);
		}

	}

}
