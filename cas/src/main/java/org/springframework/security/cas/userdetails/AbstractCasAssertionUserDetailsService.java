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
package org.springframework.security.cas.userdetails;

import org.jasig.cas.client.validation.Assertion;

import org.springframework.security.cas.authentication.CasAssertionAuthenticationToken;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;

/**
 * Abstract class for using the provided CAS assertion to construct a new User object.
 * This generally is most useful when combined with a SAML-based response from the CAS
 * Server/client.
 *
 * @author Scott Battaglia
 * @since 3.0
 */
public abstract class AbstractCasAssertionUserDetailsService
		implements AuthenticationUserDetailsService<CasAssertionAuthenticationToken> {

	public final UserDetails loadUserDetails(final CasAssertionAuthenticationToken token) {
		return loadUserDetails(token.getAssertion());
	}

	/**
	 * Protected template method for construct a
	 * {@link org.springframework.security.core.userdetails.UserDetails} via the supplied
	 * CAS assertion.
	 * @param assertion the assertion to use to construct the new UserDetails. CANNOT be
	 * NULL.
	 * @return the newly constructed UserDetails.
	 */
	protected abstract UserDetails loadUserDetails(Assertion assertion);

}
