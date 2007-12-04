/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.config;

import org.springframework.dao.DataAccessException;
import org.springframework.security.GrantedAuthority;
import org.springframework.security.GrantedAuthorityImpl;
import org.springframework.security.userdetails.User;
import org.springframework.security.userdetails.UserDetails;
import org.springframework.security.userdetails.UserDetailsService;
import org.springframework.security.userdetails.UsernameNotFoundException;


/**
 * @author Ben Alex
 * @version $Id: DataSourcePopulator.java 2291 2007-12-03 02:56:52Z benalex $
 */
public class CustomUserDetailsService implements UserDetailsService {

	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException, DataAccessException {
		if ("rod".equals(username)) {
			return new User("rod", "koala", true, true, true, true, new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_FOO")});
		}
		throw new UsernameNotFoundException("unsupported by stub");
	}
	
}
