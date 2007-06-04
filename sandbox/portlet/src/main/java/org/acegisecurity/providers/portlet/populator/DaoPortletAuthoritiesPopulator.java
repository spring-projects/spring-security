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

package org.acegisecurity.providers.portlet.populator;

import org.acegisecurity.Authentication;
import org.acegisecurity.AuthenticationException;
import org.acegisecurity.AuthenticationServiceException;
import org.acegisecurity.providers.portlet.PortletAuthenticationProvider;
import org.acegisecurity.providers.portlet.PortletAuthoritiesPopulator;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UserDetailsService;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.util.Assert;

/**
 * Populates the portlet authorities via a {@link UserDetailsService}.
 *
 * @author John A. Lewis
 * @since 2.0
 * @version $Id$
 */
public class DaoPortletAuthoritiesPopulator
		implements PortletAuthoritiesPopulator,	InitializingBean {

	//~ Instance fields ================================================================================================

    private UserDetailsService userDetailsService;

	//~ Methods ========================================================================================================

	public void afterPropertiesSet() throws Exception {
		Assert.notNull(this.userDetailsService, "A userDetailsService must be set");
	}

	public UserDetails getUserDetails(Authentication authentication)
			throws AuthenticationException {

		// make sure the Authentication object is valid
		if (authentication == null || authentication.getPrincipal() == null) {
			throw new AuthenticationServiceException(
					"must pass valid Authentication object with non-null principal");
		}

		// get the username from the principal
		String username = PortletAuthenticationProvider.getUsernameFromPrincipal(authentication.getPrincipal());

		// call the UserDetailsService with the username
		return this.userDetailsService.loadUserByUsername(username);
	}


	public UserDetailsService getUserDetailsService() {
		return userDetailsService;
	}

	public void setUserDetailsService(UserDetailsService userDetailsService) {
		this.userDetailsService = userDetailsService;
	}

}
