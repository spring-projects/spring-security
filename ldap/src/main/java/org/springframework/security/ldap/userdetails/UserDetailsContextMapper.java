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
package org.springframework.security.ldap.userdetails;

import java.util.Collection;

import org.springframework.ldap.core.DirContextAdapter;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

/**
 * Operations to map a UserDetails object to and from a Spring LDAP
 * {@code DirContextOperations} implementation. Used by {@code LdapUserDetailsManager}
 * when loading and saving/creating user information, and also by the
 * {@code LdapAuthenticationProvider} to allow customization of the user data loaded
 * during authentication.
 *
 * @author Luke Taylor
 * @since 2.0
 */
public interface UserDetailsContextMapper {

	/**
	 * Creates a fully populated UserDetails object for use by the security framework.
	 * @param ctx the context object which contains the user information.
	 * @param username the user's supplied login name.
	 * @param authorities
	 * @return the user object.
	 */
	UserDetails mapUserFromContext(DirContextOperations ctx, String username,
			Collection<? extends GrantedAuthority> authorities);

	/**
	 * Reverse of the above operation. Populates a context object from the supplied user
	 * object. Called when saving a user, for example.
	 */
	void mapUserToContext(UserDetails user, DirContextAdapter ctx);

}
