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

package org.springframework.security.webauthn.sample.app.web;


import javax.validation.Valid;
import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;

/**
 * Form for User
 */
public class UserCreateForm {

	@NotNull
	private String userHandle;

	@NotEmpty
	private String username;

	@NotEmpty
	private String password;

	@Valid
	@NotNull
	private AuthenticatorCreateForm authenticator;

	private boolean singleFactorAuthenticationAllowed;

	public String getUserHandle() {
		return userHandle;
	}

	public void setUserHandle(String userHandle) {
		this.userHandle = userHandle;
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public AuthenticatorCreateForm getAuthenticator() {
		return authenticator;
	}

	public void setAuthenticator(AuthenticatorCreateForm authenticator) {
		this.authenticator = authenticator;
	}

	public boolean isSingleFactorAuthenticationAllowed() {
		return singleFactorAuthenticationAllowed;
	}

	public void setSingleFactorAuthenticationAllowed(boolean singleFactorAuthenticationAllowed) {
		this.singleFactorAuthenticationAllowed = singleFactorAuthenticationAllowed;
	}

}
