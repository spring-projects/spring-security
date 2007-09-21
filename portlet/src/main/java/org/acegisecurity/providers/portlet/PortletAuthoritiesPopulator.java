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

import org.springframework.security.Authentication;
import org.springframework.security.AuthenticationException;
import org.springframework.security.userdetails.UserDetails;

/**
 * Populates the <code>UserDetails</code> associated with the
 * portlet user presented by the portlet container.
 *
 * @author John A. Lewis
 * @since 2.0
 * @version $Id$
 */
public interface PortletAuthoritiesPopulator {

	//~ Methods ========================================================================================================

	/**
	 * Obtains the granted authorities for the specified Authentication object.
	 * <p>May throw any <code>AuthenticationException</code> or return <code>null</code>
	 * if the authorities are unavailable.</p>
	 * @param authentication the authentication object seeking authorities
	 * @return the details of the indicated user (at minimum the granted authorities and the username)
	 * @throws AuthenticationException if the user details are not available or the authentication is not valid for some reason
	 */
	public UserDetails getUserDetails(Authentication authentication) throws AuthenticationException;

}
