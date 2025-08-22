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

import org.springframework.security.core.Authentication;
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
public class BearerTokenAuthentication extends AbstractOAuth2TokenAuthenticationToken<OAuth2AccessToken> {

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

	@Override
	public Map<String, Object> getTokenAttributes() {
		return this.attributes;
	}

	@Override
	public Builder toBuilder() {
		return new Builder().apply(this);
	}

	/**
	 * A builder preserving the concrete {@link Authentication} type
	 *
	 * @since 7.0
	 */
	public static final class Builder extends AbstractAuthenticationBuilder<BearerTokenAuthentication, Builder> {

		private OAuth2AuthenticatedPrincipal principal;

		private OAuth2AccessToken token;

		private Builder() {

		}

		public Builder apply(BearerTokenAuthentication authentication) {
			return super.apply(authentication).principal((OAuth2AuthenticatedPrincipal) authentication.getPrincipal())
				.credentials(authentication.getToken());
		}

		public Builder principal(OAuth2AuthenticatedPrincipal principal) {
			this.principal = principal;
			return this;
		}

		public Builder credentials(OAuth2AccessToken credentials) {
			this.token = credentials;
			return this;
		}

		@Override
		protected BearerTokenAuthentication build(Collection<GrantedAuthority> authorities) {
			return new BearerTokenAuthentication(this.principal, this.token, authorities);
		}

	}

}
