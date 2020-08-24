/*
 * Copyright 2002-2019 the original author or authors.
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

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityCoreVersion;
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

	private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

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

}
