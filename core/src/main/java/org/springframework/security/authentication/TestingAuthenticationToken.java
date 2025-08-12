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

package org.springframework.security.authentication;

import java.util.Collection;
import java.util.List;

import org.springframework.security.core.AuthenticationResult;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.util.Assert;

/**
 * An {@link org.springframework.security.core.Authentication} implementation that is
 * designed for use whilst unit testing.
 * <p>
 * The corresponding authentication provider is {@link TestingAuthenticationProvider}.
 *
 * @author Ben Alex
 */
public class TestingAuthenticationToken extends AbstractAuthenticationToken implements AuthenticationResult {

	private static final long serialVersionUID = 1L;

	private final Object credentials;

	private final Object principal;

	public TestingAuthenticationToken(Object principal, Object credentials) {
		super(null);
		this.principal = principal;
		this.credentials = credentials;
	}

	public TestingAuthenticationToken(Object principal, Object credentials, String... authorities) {
		this(principal, credentials, AuthorityUtils.createAuthorityList(authorities));
	}

	public TestingAuthenticationToken(Object principal, Object credentials,
			List<? extends GrantedAuthority> authorities) {
		this(principal, credentials, (Collection<? extends GrantedAuthority>) authorities);
	}

	public TestingAuthenticationToken(Object principal, Object credentials,
			Collection<? extends GrantedAuthority> authorities) {
		super(authorities);
		this.principal = principal;
		this.credentials = credentials;
		setAuthenticated(true);
	}

	@Override
	public TestingAuthenticationToken withGrantedAuthorities(Collection<GrantedAuthority> authorities) {
		Assert.isTrue(isAuthenticated(), "cannot grant authorities to unauthenticated tokens");
		return new TestingAuthenticationToken(getPrincipal(), this.credentials, authorities);
	}

	@Override
	public Object getCredentials() {
		return this.credentials;
	}

	@Override
	public Object getPrincipal() {
		return this.principal;
	}

}
