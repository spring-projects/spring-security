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

import java.util.Collection;
import java.util.Map;

import org.springframework.lang.Nullable;
import org.springframework.security.core.AuthenticatedPrincipal;
import org.springframework.security.core.GrantedAuthority;

/**
 * An {@link AuthenticatedPrincipal} that represents the principal associated with an
 * OAuth 2.0 token.
 *
 * @author Josh Cummings
 * @since 5.2
 */
public interface OAuth2AuthenticatedPrincipal extends AuthenticatedPrincipal {

	/**
	 * Get the OAuth 2.0 token attribute by name
	 * @param name the name of the attribute
	 * @param <A> the type of the attribute
	 * @return the attribute or {@code null} otherwise
	 */
	@Nullable
	@SuppressWarnings("unchecked")
	default <A> A getAttribute(String name) {
		return (A) getAttributes().get(name);
	}

	/**
	 * Get the OAuth 2.0 token attributes
	 * @return the OAuth 2.0 token attributes
	 */
	Map<String, Object> getAttributes();

	/**
	 * Get the {@link Collection} of {@link GrantedAuthority}s associated with this OAuth
	 * 2.0 token
	 * @return the OAuth 2.0 token authorities
	 */
	Collection<? extends GrantedAuthority> getAuthorities();

}
