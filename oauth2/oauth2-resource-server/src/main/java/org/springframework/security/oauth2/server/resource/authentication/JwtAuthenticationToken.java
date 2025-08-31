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
import java.util.Map;

import org.springframework.security.core.AuthenticatedPrincipal;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.Transient;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * An implementation of an {@link AbstractOAuth2TokenAuthenticationToken} representing a
 * {@link Jwt} {@code Authentication}.
 *
 * @author Joe Grandja
 * @author Andrey Litvitski
 * @since 5.1
 * @see AbstractOAuth2TokenAuthenticationToken
 * @see Jwt
 */
@Transient
public class JwtAuthenticationToken extends AbstractOAuth2TokenAuthenticationToken<Jwt> {

	private static final long serialVersionUID = 620L;

	private final String name;

	/**
	 * Constructs a {@code JwtAuthenticationToken} using the provided parameters.
	 * @param jwt the JWT
	 */
	public JwtAuthenticationToken(Jwt jwt) {
		super(jwt);
		this.name = jwt.getSubject();
	}

	/**
	 * Constructs a {@code JwtAuthenticationToken} using the provided parameters.
	 * @param jwt the JWT
	 * @param authorities the authorities assigned to the JWT
	 */
	public JwtAuthenticationToken(Jwt jwt, Collection<? extends GrantedAuthority> authorities) {
		super(jwt, authorities);
		this.setAuthenticated(true);
		this.name = jwt.getSubject();
	}

	/**
	 * Constructs a {@code JwtAuthenticationToken} using the provided parameters.
	 * @param jwt the JWT
	 * @param authorities the authorities assigned to the JWT
	 * @param name the principal name
	 */
	public JwtAuthenticationToken(Jwt jwt, Collection<? extends GrantedAuthority> authorities, String name) {
		super(jwt, authorities);
		this.setAuthenticated(true);
		this.name = name;
	}

	/**
	 * Constructs a {@code JwtAuthenticationToken} using the provided parameters.
	 * @param jwt the JWT
	 * @param principal the principal
	 * @param authorities the authorities assigned to the JWT
	 */
	public JwtAuthenticationToken(Jwt jwt, Object principal, Collection<? extends GrantedAuthority> authorities) {
		super(jwt, principal, jwt, authorities);
		this.setAuthenticated(true);
		if (principal instanceof AuthenticatedPrincipal) {
			this.name = ((AuthenticatedPrincipal) principal).getName();
		} else {
			this.name = jwt.getSubject();
		}
	}

	@Override
	public Map<String, Object> getTokenAttributes() {
		return this.getToken().getClaims();
	}

	/**
	 * The principal name which is, by default, the {@link Jwt}'s subject
	 */
	@Override
	public String getName() {
		return this.name;
	}

}
