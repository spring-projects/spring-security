/*
 * Copyright 2002-2024 the original author or authors.
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
 * Repository interface for accessing user authorities.
 *
 * @author Marcus da Coregio
 * @since 6.4
 * @see UserAuthorities
 */
public interface UserAuthoritiesRepository {

	/**
	 * Finds the authorities associated with the given username.
	 * @param username the username for which to find authorities
	 * @return the {@link UserAuthorities} object containing authorities associated with
	 * the specified username
	 * @throws UsernameNotFoundException if the user could not be found or the user has no
	 * GrantedAuthority
	 */
	UserAuthorities findAuthoritiesByUsername(String username) throws UsernameNotFoundException;

}
