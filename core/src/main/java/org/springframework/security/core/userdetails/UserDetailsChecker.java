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
package org.springframework.security.core.userdetails;

/**
 * Called by classes which make use of a {@link UserDetailsService} to check the status of
 * the loaded <tt>UserDetails</tt> object. Typically this will involve examining the
 * various flags associated with the account and raising an exception if the information
 * cannot be used (for example if the user account is locked or disabled), but a custom
 * implementation could perform any checks it wished.
 * <p>
 * The intention is that this interface should only be used for checks on the persistent
 * data associated with the user. It should not involved in making any authentication
 * decisions based on a submitted authentication request.
 *
 * @author Luke Taylor
 * @since 2.0
 * @see org.springframework.security.authentication.AccountStatusUserDetailsChecker
 * @see org.springframework.security.authentication.AccountStatusException
 */
public interface UserDetailsChecker {

	/**
	 * Examines the User
	 * @param toCheck the UserDetails instance whose status should be checked.
	 */
	void check(UserDetails toCheck);

}
