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

import static org.springframework.security.oauth2.server.resource.authentication.OAuth2IntrospectionClaimNames.SUBJECT;

import java.util.Collection;
import java.util.Map;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.util.Assert;

/**
 * An {@link org.springframework.security.core.Authentication} token that represents a successful authentication as
 * obtained through an opaque token
 * <a target="_blank" href="https://tools.ietf.org/html/rfc7662">introspection</a>
 * process.
 *
 * @author Josh Cummings
 * @since 5.2
 */
public class OAuth2IntrospectionAuthenticationToken
		extends AbstractOAuth2TokenAuthenticationToken<OAuth2AccessToken> {

	private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

	private String name;

	/**
	 * Constructs a {@link OAuth2IntrospectionAuthenticationToken} with the provided arguments
	 *
	 * @param token The verified token
	 * @param authorities The authorities associated with the given token
	 */
	public OAuth2IntrospectionAuthenticationToken(OAuth2AccessToken token,
			Collection<? extends GrantedAuthority> authorities) {

		this(token, authorities, null);
	}

	/**
	 * Constructs a {@link OAuth2IntrospectionAuthenticationToken} with the provided arguments
	 *
	 * @param token The verified token
	 * @param authorities The authorities associated with the given token
	 * @param name The name associated with this token
	 */
	public OAuth2IntrospectionAuthenticationToken(OAuth2AccessToken token,
		Collection<? extends GrantedAuthority> authorities, String name) {
		
		super(token, token.getAttributes(), token, authorities);
		Assert.notEmpty(token.getAttributes(), "attributes cannot be empty");
		this.name = name == null ? (String) token.getAttributes().get(SUBJECT) : name;
		setAuthenticated(true);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Map<String, Object> getTokenAttributes() {
		return this.getToken().getAttributes();
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String getName() {
		return this.name;
	}
}
