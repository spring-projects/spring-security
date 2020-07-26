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

package org.springframework.security.authentication.rcp;

import java.util.Collection;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.Assert;

/**
 * Server-side processor of a remote authentication request.
 * <p>
 * This bean requires no security interceptor to protect it. Instead, the bean uses the
 * configured <code>AuthenticationManager</code> to resolve an authentication request.
 *
 * @author Ben Alex
 */
public class RemoteAuthenticationManagerImpl implements RemoteAuthenticationManager, InitializingBean {

	private AuthenticationManager authenticationManager;

	@Override
	public void afterPropertiesSet() {
		Assert.notNull(this.authenticationManager, "authenticationManager is required");
	}

	@Override
	public Collection<? extends GrantedAuthority> attemptAuthentication(String username, String password)
			throws RemoteAuthenticationException {
		UsernamePasswordAuthenticationToken request = new UsernamePasswordAuthenticationToken(username, password);

		try {
			return this.authenticationManager.authenticate(request).getAuthorities();
		}
		catch (AuthenticationException authEx) {
			throw new RemoteAuthenticationException(authEx.getMessage());
		}
	}

	protected AuthenticationManager getAuthenticationManager() {
		return this.authenticationManager;
	}

	public void setAuthenticationManager(AuthenticationManager authenticationManager) {
		this.authenticationManager = authenticationManager;
	}

}
