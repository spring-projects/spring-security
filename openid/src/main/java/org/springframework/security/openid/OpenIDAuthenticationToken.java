/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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
package org.springframework.security.openid;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityCoreVersion;

/**
 * OpenID Authentication Token
 *
 * @deprecated The OpenID 1.0 and 2.0 protocols have been deprecated and users are
 * <a href="https://openid.net/specs/openid-connect-migration-1_0.html">encouraged to migrate</a>
 * to <a href="https://openid.net/connect/">OpenID Connect</a>.
 * @author Robin Bramley
 */
public class OpenIDAuthenticationToken extends AbstractAuthenticationToken {

	private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

	// ~ Instance fields
	// ================================================================================================

	private final OpenIDAuthenticationStatus status;
	private final Object principal;
	private final String identityUrl;
	private final String message;
	private final List<OpenIDAttribute> attributes;

	// ~ Constructors
	// ===================================================================================================

	public OpenIDAuthenticationToken(OpenIDAuthenticationStatus status,
			String identityUrl, String message, List<OpenIDAttribute> attributes) {
		super(new ArrayList<>(0));
		this.principal = identityUrl;
		this.status = status;
		this.identityUrl = identityUrl;
		this.message = message;
		this.attributes = attributes;
		setAuthenticated(false);
	}

	/**
	 * Created by the <tt>OpenIDAuthenticationProvider</tt> on successful authentication.
	 *
	 * @param principal usually the <tt>UserDetails</tt> returned by the configured
	 * <tt>UserDetailsService</tt> used by the <tt>OpenIDAuthenticationProvider</tt>.
	 *
	 */
	public OpenIDAuthenticationToken(Object principal,
			Collection<? extends GrantedAuthority> authorities, String identityUrl,
			List<OpenIDAttribute> attributes) {
		super(authorities);
		this.principal = principal;
		this.status = OpenIDAuthenticationStatus.SUCCESS;
		this.identityUrl = identityUrl;
		this.message = null;
		this.attributes = attributes;

		setAuthenticated(true);
	}

	// ~ Methods
	// ========================================================================================================

	/**
	 * Returns 'null' always, as no credentials are processed by the OpenID provider.
	 * @see org.springframework.security.core.Authentication#getCredentials()
	 */
	public Object getCredentials() {
		return null;
	}

	public String getIdentityUrl() {
		return identityUrl;
	}

	public String getMessage() {
		return message;
	}

	/**
	 * Returns the <tt>principal</tt> value.
	 *
	 * @see org.springframework.security.core.Authentication#getPrincipal()
	 */
	public Object getPrincipal() {
		return principal;
	}

	public OpenIDAuthenticationStatus getStatus() {
		return status;
	}

	public List<OpenIDAttribute> getAttributes() {
		return attributes;
	}

	@Override
	public String toString() {
		return "[" + super.toString() + ", attributes : " + attributes + "]";
	}
}
