/*
 * Copyright 2004-present the original author or authors.
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

import org.jspecify.annotations.Nullable;

import org.springframework.security.authentication.password.ChangePasswordAdvice;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.security.core.userdetails.UserDetails;

/**
 * @author Luke Taylor
 * @since 3.1
 */
class MutableUser implements MutableUserDetails {

	private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

	private @Nullable String password;

	private ChangePasswordAdvice advice = ChangePasswordAdvice.ABSTAIN;

	private final UserDetails delegate;

	MutableUser(UserDetails user) {
		this.delegate = user;
		this.password = user.getPassword();
	}

	@Override
	public @Nullable String getPassword() {
		return this.password;
	}

	@Override
	public void setPassword(@Nullable String password) {
		this.password = password;
	}

	@Override
	public ChangePasswordAdvice getChangePasswordAdvice() {
		return advice;
	}

	public void setChangePasswordAdvice(ChangePasswordAdvice advice) {
		this.advice = advice;
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return this.delegate.getAuthorities();
	}

	@Override
	public String getUsername() {
		return this.delegate.getUsername();
	}

	@Override
	public boolean isAccountNonExpired() {
		return this.delegate.isAccountNonExpired();
	}

	@Override
	public boolean isAccountNonLocked() {
		return this.delegate.isAccountNonLocked();
	}

	@Override
	public boolean isCredentialsNonExpired() {
		return this.delegate.isCredentialsNonExpired();
	}

	@Override
	public boolean isEnabled() {
		return this.delegate.isEnabled();
	}

}
