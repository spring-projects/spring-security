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
package org.springframework.security.web.authentication.switchuser;

import java.util.Collection;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

/**
 * Allows subclasses to modify the {@link GrantedAuthority} list that will be assigned to
 * the principal when they assume the identity of a different principal.
 *
 * <p>
 * Configured against the {@link SwitchUserFilter}.
 *
 * @author Ben Alex
 *
 */
public interface SwitchUserAuthorityChanger {

	/**
	 * Allow subclasses to add or remove authorities that will be granted when in switch
	 * user mode.
	 *
	 * @param targetUser the UserDetails representing the identity being switched to
	 * @param currentAuthentication the current Authentication of the principal performing
	 * the switching
	 * @param authoritiesToBeGranted all
	 * {@link org.springframework.security.core.GrantedAuthority} instances to be granted
	 * to the user, excluding the special "switch user" authority that is used internally
	 * (guaranteed never null)
	 *
	 * @return the modified list of granted authorities.
	 */
	Collection<? extends GrantedAuthority> modifyGrantedAuthorities(
			UserDetails targetUser, Authentication currentAuthentication,
			Collection<? extends GrantedAuthority> authoritiesToBeGranted);
}
