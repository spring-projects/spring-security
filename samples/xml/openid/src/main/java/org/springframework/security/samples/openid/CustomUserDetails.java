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

package org.springframework.security.samples.openid;

import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

/**
 * Customized {@code UserDetails} implementation.
 *
 * @deprecated The OpenID 1.0 and 2.0 protocols have been deprecated and users are
 *  <a href="https://openid.net/specs/openid-connect-migration-1_0.html">encouraged to migrate</a>
 *  to <a href="https://openid.net/connect/">OpenID Connect</a>, which is supported by <code>spring-security-oauth2</code>.
 * @author Luke Taylor
 * @since 3.1
 */
public class CustomUserDetails extends User {
	private String email;
	private String name;
	private boolean newUser;

	public CustomUserDetails(String username, Collection<GrantedAuthority> authorities) {
		super(username, "unused", authorities);
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public boolean isNewUser() {
		return newUser;
	}

	public void setNewUser(boolean newUser) {
		this.newUser = newUser;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}
}
