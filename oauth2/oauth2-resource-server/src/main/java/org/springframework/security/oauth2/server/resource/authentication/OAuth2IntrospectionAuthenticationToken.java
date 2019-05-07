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
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.util.Assert;

import static org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionClaimNames.SUBJECT;

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

	private Map<String, Object> attributes;
	private String name;

	/**
	 * Constructs a {@link OAuth2IntrospectionAuthenticationToken} with the provided arguments
	 *
	 * @param token The verified token
	 * @param authorities The authorities associated with the given token
	 */
	public OAuth2IntrospectionAuthenticationToken(OAuth2AccessToken token,
			Map<String, Object> attributes, Collection<? extends GrantedAuthority> authorities) {

		this(token, attributes, authorities, null);
	}

	/**
	 * Constructs a {@link OAuth2IntrospectionAuthenticationToken} with the provided arguments
	 *
	 * @param token The verified token
	 * @param authorities The authorities associated with the given token
	 * @param name The name associated with this token
	 */
	public OAuth2IntrospectionAuthenticationToken(OAuth2AccessToken token,
		Map<String, Object> attributes, Collection<? extends GrantedAuthority> authorities, String name) {

		super(token, attributes(attributes), token, authorities);
		this.attributes = attributes(attributes);
		this.name = name == null ? (String) attributes.get(SUBJECT) : name;
		setAuthenticated(true);
	}

	private static Map<String, Object> attributes(Map<String, Object> attributes) {
		Assert.notEmpty(attributes, "attributes cannot be empty");
		return Collections.unmodifiableMap(new LinkedHashMap<>(attributes));
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Map<String, Object> getTokenAttributes() {
		return this.attributes;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String getName() {
		return this.name;
	}
}
