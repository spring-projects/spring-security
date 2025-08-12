/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

package org.springframework.security.authentication.jaas;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import javax.security.auth.login.LoginContext;

import org.jspecify.annotations.Nullable;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.Assert;

/**
 * UsernamePasswordAuthenticationToken extension to carry the Jaas LoginContext that the
 * user was logged into
 *
 * @author Ray Krueger
 */
public class JaasAuthenticationToken extends UsernamePasswordAuthenticationToken {

	private static final long serialVersionUID = 620L;

	private final transient LoginContext loginContext;

	public JaasAuthenticationToken(Object principal, @Nullable Object credentials, LoginContext loginContext) {
		super(principal, credentials);
		this.loginContext = loginContext;
	}

	public JaasAuthenticationToken(Object principal, @Nullable Object credentials, List<GrantedAuthority> authorities,
			LoginContext loginContext) {
		super(principal, credentials, authorities);
		this.loginContext = loginContext;
	}

	public LoginContext getLoginContext() {
		return this.loginContext;
	}

	@Override
	public JaasAuthenticationToken withGrantedAuthorities(Collection<GrantedAuthority> authorities) {
		Assert.isTrue(isAuthenticated(), "cannot grant authorities to unauthenticated tokens");
		return new JaasAuthenticationToken(getPrincipal(), getCredentials(), new ArrayList<>(authorities),
				this.loginContext);
	}

}
