/*
 * Copyright 2002-2019 the original author or authors.
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

package org.springframework.security.webauthn.sample.domain.entity;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.webauthn.userdetails.WebAuthnUserDetails;

import java.util.Collection;
import java.util.Collections;
import java.util.List;

/**
 * User model
 */
public class UserEntity implements WebAuthnUserDetails {

	private Integer id;
	private byte[] userHandle;
	private String username;

	private List<AuthenticatorEntity> authenticators;

	private String password;

	private boolean locked;

	private boolean singleFactorAuthenticationAllowed;

	public Integer getId() {
		return id;
	}

	public void setId(Integer id) {
		this.id = id;
	}

	@Override
	public byte[] getUserHandle() {
		return userHandle;
	}

	public void setUserHandle(byte[] userHandle) {
		this.userHandle = userHandle;
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	@Override
	public List<AuthenticatorEntity> getAuthenticators() {
		return authenticators;
	}

	public void setAuthenticators(List<AuthenticatorEntity> authenticators) {
		this.authenticators = authenticators;
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return Collections.emptyList();
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public boolean isLocked() {
		return locked;
	}

	public void setLocked(boolean locked) {
		this.locked = locked;
	}

	@Override
	public boolean isSingleFactorAuthenticationAllowed() {
		return singleFactorAuthenticationAllowed;
	}

	@Override
	public void setSingleFactorAuthenticationAllowed(boolean singleFactorAuthenticationAllowed) {
		this.singleFactorAuthenticationAllowed = singleFactorAuthenticationAllowed;
	}

	@Override
	public boolean isAccountNonExpired() {
		return true;
	}

	@Override
	public boolean isAccountNonLocked() {
		return !isLocked();
	}

	@Override
	public boolean isCredentialsNonExpired() {
		return true;
	}

	@Override
	public boolean isEnabled() {
		return true;
	}

	/**
	 * return String representation
	 */
	@Override
	public String toString() {
		return username;
	}

}
