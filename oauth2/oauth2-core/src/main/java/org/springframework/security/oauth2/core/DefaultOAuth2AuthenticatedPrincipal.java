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

package org.springframework.security.oauth2.core;

import java.io.Serializable;
import java.util.Collection;
import java.util.Collections;
import java.util.Map;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.util.Assert;

/**
 * A domain object that wraps the attributes of an OAuth 2.0 token.
 *
 * @author Clement Ng
 * @author Josh Cummings
 * @since 5.2
 */
public final class DefaultOAuth2AuthenticatedPrincipal implements OAuth2AuthenticatedPrincipal, Serializable {

	private final Map<String, Object> attributes;

	private final Collection<GrantedAuthority> authorities;

	private final String name;

	/**
	 * Constructs an {@code DefaultOAuth2AuthenticatedPrincipal} using the provided
	 * parameters.
	 * @param attributes the attributes of the OAuth 2.0 token
	 * @param authorities the authorities of the OAuth 2.0 token
	 */
	public DefaultOAuth2AuthenticatedPrincipal(Map<String, Object> attributes,
			Collection<GrantedAuthority> authorities) {

		this(null, attributes, authorities);
	}

	/**
	 * Constructs an {@code DefaultOAuth2AuthenticatedPrincipal} using the provided
	 * parameters.
	 * @param name the name attached to the OAuth 2.0 token
	 * @param attributes the attributes of the OAuth 2.0 token
	 * @param authorities the authorities of the OAuth 2.0 token
	 */
	public DefaultOAuth2AuthenticatedPrincipal(String name, Map<String, Object> attributes,
			Collection<GrantedAuthority> authorities) {

		Assert.notEmpty(attributes, "attributes cannot be empty");
		this.attributes = Collections.unmodifiableMap(attributes);
		this.authorities = authorities == null ? AuthorityUtils.NO_AUTHORITIES
				: Collections.unmodifiableCollection(authorities);
		this.name = name == null ? (String) this.attributes.get("sub") : name;
	}

	/**
	 * Gets the attributes of the OAuth 2.0 token in map form.
	 * @return a {@link Map} of the attribute's objects keyed by the attribute's names
	 */
	@Override
	public Map<String, Object> getAttributes() {
		return this.attributes;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return this.authorities;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String getName() {
		return this.name;
	}

}
