/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.saml2.provider.service.authentication;

import java.io.Serial;
import java.util.Collection;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.AuthenticatedPrincipal;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.Assert;

/**
 * An implementation of an {@link AbstractAuthenticationToken} that represents an
 * authenticated SAML 2.0 {@link Authentication}.
 * <p>
 * The {@link Authentication} associates valid SAML assertion data with a Spring Security
 * authentication object The complete assertion is contained in the object in String
 * format, {@link Saml2Authentication#getSaml2Response()}
 *
 * @since 5.2
 * @see AbstractAuthenticationToken
 */
public class Saml2Authentication extends AbstractAuthenticationToken {

	@Serial
	private static final long serialVersionUID = 405897702378720477L;

	private final AuthenticatedPrincipal principal;

	private final String saml2Response;

	/**
	 * Construct a {@link Saml2Authentication} using the provided parameters
	 * @param principal the logged in user
	 * @param saml2Response the SAML 2.0 response used to authenticate the user
	 * @param authorities the authorities for the logged in user
	 */
	public Saml2Authentication(AuthenticatedPrincipal principal, String saml2Response,
			Collection<? extends GrantedAuthority> authorities) {
		super(authorities);
		Assert.notNull(principal, "principal cannot be null");
		Assert.hasText(saml2Response, "saml2Response cannot be null");
		this.principal = principal;
		this.saml2Response = saml2Response;
		setAuthenticated(true);
	}

	@Override
	public Object getPrincipal() {
		return this.principal;
	}

	/**
	 * Returns the SAML response object, as decoded XML. May contain encrypted elements
	 * @return string representation of the SAML Response XML object
	 */
	public String getSaml2Response() {
		return this.saml2Response;
	}

	@Override
	public Object getCredentials() {
		return getSaml2Response();
	}

}
