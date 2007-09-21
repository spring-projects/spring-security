/*
 * Copyright 2005-2007 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.providers.portlet;

import org.springframework.security.GrantedAuthority;
import org.springframework.security.providers.AbstractAuthenticationToken;

/**
 * <code>Authentication</code> implementation for JSR 168 Portlet authentication.  <p>The
 * corresponding authentication provider is  {@link PortletAuthenticationProvider}.</p>
 *
 * @author John A. Lewis
 * @since 2.0
 * @version $Id$
 */
public class PortletAuthenticationToken extends AbstractAuthenticationToken {

	//~ Instance fields ================================================================================================

	private static final long serialVersionUID = 1L;

	private Object principal;
	private Object credentials;

	//~ Constructors ===================================================================================================

	public PortletAuthenticationToken(Object principal, Object credentials, GrantedAuthority[] authorities) {
		super(authorities);
		this.principal = principal;
		this.credentials = credentials;
	}

	//~ Methods ========================================================================================================

	public Object getPrincipal() {
		return this.principal;
	}

	public Object getCredentials() {
		return this.credentials;
	}

}
