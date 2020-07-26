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
package org.springframework.security.provisioning;

import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.security.core.userdetails.UserDetails;

/**
 * @author Luke Taylor
 * @since 3.1
 */
class MutableUser implements MutableUserDetails {

	private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

	private String password;

	private final UserDetails delegate;

	MutableUser(UserDetails user) {
		this.delegate = user;
		this.password = user.getPassword();
	}

	public String getPassword() {
		return this.password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public Collection<? extends GrantedAuthority> getAuthorities() {
		return this.delegate.getAuthorities();
	}

	public String getUsername() {
		return this.delegate.getUsername();
	}

	public boolean isAccountNonExpired() {
		return this.delegate.isAccountNonExpired();
	}

	public boolean isAccountNonLocked() {
		return this.delegate.isAccountNonLocked();
	}

	public boolean isCredentialsNonExpired() {
		return this.delegate.isCredentialsNonExpired();
	}

	public boolean isEnabled() {
		return this.delegate.isEnabled();
	}

}
