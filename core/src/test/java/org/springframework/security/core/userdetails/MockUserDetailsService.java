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

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;

/**
 * A test UserDetailsService containing a set of standard usernames corresponding to their
 * account status: valid, locked, disabled, credentialsExpired, expired. All passwords are
 * "".
 *
 * @author Luke Taylor
 */
public class MockUserDetailsService implements UserDetailsService {
	private Map<String, User> users = new HashMap<String, User>();
	private List<GrantedAuthority> auths = AuthorityUtils
			.createAuthorityList("ROLE_USER");

	public MockUserDetailsService() {
		users.put("valid", new User("valid", "", true, true, true, true, auths));
		users.put("locked", new User("locked", "", true, true, true, false, auths));
		users.put("disabled", new User("disabled", "", false, true, true, true, auths));
		users.put("credentialsExpired", new User("credentialsExpired", "", true, true,
				false, true, auths));
		users.put("expired", new User("expired", "", true, false, true, true, auths));
	}

	public UserDetails loadUserByUsername(String username) {
		if (users.get(username) == null) {
			throw new UsernameNotFoundException("User not found: " + username);
		}

		return users.get(username);
	}
}
