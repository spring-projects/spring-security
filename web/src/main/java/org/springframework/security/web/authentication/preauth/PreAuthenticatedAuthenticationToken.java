/*
 * Copyright 2002-2016 the original author or authors.
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
package org.springframework.security.web.authentication.preauth;

import java.util.Collection;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityCoreVersion;

/**
 * {@link org.springframework.security.core.Authentication} implementation for
 * pre-authenticated authentication.
 *
 * @author Ruud Senden
 * @since 2.0
 */
public class PreAuthenticatedAuthenticationToken extends AbstractAuthenticationToken {

	private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

	private final Object principal;

	private final Object credentials;

	/**
	 * Constructor used for an authentication request. The
	 * {@link org.springframework.security.core.Authentication#isAuthenticated()} will
	 * return <code>false</code>.
	 * @param aPrincipal The pre-authenticated principal
	 * @param aCredentials The pre-authenticated credentials
	 */
	public PreAuthenticatedAuthenticationToken(Object aPrincipal, Object aCredentials) {
		super(null);
		this.principal = aPrincipal;
		this.credentials = aCredentials;
	}

	/**
	 * Constructor used for an authentication response. The
	 * {@link org.springframework.security.core.Authentication#isAuthenticated()} will
	 * return <code>true</code>.
	 * @param aPrincipal The authenticated principal
	 * @param anAuthorities The granted authorities
	 */
	public PreAuthenticatedAuthenticationToken(Object aPrincipal, Object aCredentials,
			Collection<? extends GrantedAuthority> anAuthorities) {
		super(anAuthorities);
		this.principal = aPrincipal;
		this.credentials = aCredentials;
		setAuthenticated(true);
	}

	/**
	 * Get the credentials
	 */
	@Override
	public Object getCredentials() {
		return this.credentials;
	}

	/**
	 * Get the principal
	 */
	@Override
	public Object getPrincipal() {
		return this.principal;
	}

}
