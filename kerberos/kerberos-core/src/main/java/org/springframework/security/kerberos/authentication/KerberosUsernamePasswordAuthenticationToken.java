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

package org.springframework.security.kerberos.authentication;

import java.util.Collection;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

/**
 * <p>
 * Holds the Username/Password as well as the JAAS Subject allowing multi-tier
 * authentications using Kerberos.
 * </p>
 *
 * <p>
 * The JAAS Subject has in its private credentials the Kerberos tickets for generating new
 * tickets against other service principals using
 * <code>KerberosMultiTier.authenticateService()</code>
 * </p>
 *
 * @author Bogdan Mustiata
 * @see KerberosAuthenticationProvider
 * @see KerberosMultiTier
 */
public class KerberosUsernamePasswordAuthenticationToken extends UsernamePasswordAuthenticationToken
		implements KerberosAuthentication {

	private static final long serialVersionUID = 6327699460703504153L;

	private final JaasSubjectHolder jaasSubjectHolder;

	/**
	 * <p>
	 * Creates an authentication token that holds the username and password, and the
	 * Subject that the user will need to create new authentication tokens against other
	 * services.
	 * </p>
	 * @param principal
	 * @param credentials
	 * @param authorities
	 * @param subjectHolder
	 */
	public KerberosUsernamePasswordAuthenticationToken(Object principal, Object credentials,
			Collection<? extends GrantedAuthority> authorities, JaasSubjectHolder subjectHolder) {
		super(principal, credentials, authorities);
		this.jaasSubjectHolder = subjectHolder;
	}

	@Override
	public JaasSubjectHolder getJaasSubjectHolder() {
		return this.jaasSubjectHolder;
	}

}
