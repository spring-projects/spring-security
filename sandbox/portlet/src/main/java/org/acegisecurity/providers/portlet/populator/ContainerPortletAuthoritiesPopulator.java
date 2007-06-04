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

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import javax.portlet.PortletRequest;

import org.acegisecurity.Authentication;
import org.acegisecurity.AuthenticationException;
import org.acegisecurity.AuthenticationServiceException;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.GrantedAuthorityImpl;
import org.acegisecurity.providers.portlet.PortletAuthenticationProvider;
import org.acegisecurity.providers.portlet.PortletAuthoritiesPopulator;
import org.acegisecurity.userdetails.User;
import org.acegisecurity.userdetails.UserDetails;

/**
 * Populates the portlet authorities via role information from the portlet container.
 * Primarily it uses the <code>PortletRequest.isUserInRole(role)</code> method to
 * check if the user is in a list of configured roles.
 * <p>This bean has the following configurable properties:</p>
 * <ul>
 *     <li><code>rolesToCheck</code> : A list of strings containing names of roles to check.
 *         These roles must also be properly declared in a &lt;security-role-ref&gt; element
 *         of the portlet descriptor in the portlet.xml file.</li>
 *     <li><code>rolePrefix</code> : The prefix to be added onto each role name that as it is
 *         added to the list of authorities.  The default value is 'ROLE_'.</li>
 *     <li><code>userRole</code> : The role that all authenticated users will automatically be
 *         granted.  The default value is 'ROLE_USER'.</li>
 * </ul>
 *
 * @author John A. Lewis
 * @since 2.0
 * @version $Id$
 */
public class ContainerPortletAuthoritiesPopulator
		implements PortletAuthoritiesPopulator {

	//~ Static fields/initializers =====================================================================================

	private static final String defaultRolePrefix = "ROLE_";
	private static final String defaultUserRole = "ROLE_USER";

	//~ Instance fields ================================================================================================

    private List rolesToCheck;
    private String rolePrefix = defaultRolePrefix;
    private String userRole = defaultUserRole;

	//~ Methods ========================================================================================================

	public UserDetails getUserDetails(Authentication authentication)
		throws AuthenticationException {

		// get the username and password for the authentication
		String username = PortletAuthenticationProvider.getUsernameFromPrincipal(authentication.getPrincipal());
		String password = authentication.getCredentials().toString();

		// see if we can load authorities from the portlet request
		Object details = authentication.getDetails();
		if (!(details instanceof PortletRequest)) {
			throw new AuthenticationServiceException("expected getDetails() to return the PortletRequest object");
		}
		GrantedAuthority[] authorities = loadGrantedAuthorities((PortletRequest)details);

		// construct and return the new user
		return new User(username, password, true, true, true, true,	authorities);
	}

	private GrantedAuthority[] loadGrantedAuthorities(PortletRequest request) {

		// start the list and add the standard user role
		ArrayList authorities = new ArrayList();
		authorities.add(new GrantedAuthorityImpl(getUserRole()));

		// iterate through the configured list of roles to check (if there is one)
		if (this.rolesToCheck != null) {
			for(Iterator i = this.rolesToCheck.iterator(); i.hasNext(); ) {
				String role = (String)i.next();

				// if the request says the user has that role, then add it
				if (request.isUserInRole(role)) {
					authorities.add(new GrantedAuthorityImpl(getRolePrefix() + role));
				}

			}
		}

        // return the array of GrantedAuthority objects
		return (GrantedAuthority[])authorities.toArray(new GrantedAuthority[authorities.size()]);
	}


	public List getRolesToCheck() {
		return rolesToCheck;
	}

	public void setRolesToCheck(List rolesToCheck) {
		this.rolesToCheck = rolesToCheck;
	}

	public String getRolePrefix() {
		return rolePrefix;
	}

	public void setRolePrefix(String rolePrefix) {
		this.rolePrefix = rolePrefix;
	}

	public String getUserRole() {
		return userRole;
	}

	public void setUserRole(String userRole) {
		this.userRole = userRole;
	}

}
