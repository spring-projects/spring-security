/*
 * Copyright 2017-2017 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.abac;


import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

/**
 * Convenience class for better access to roles in SpEl
 *
 * @author Renato Soppelsa
 * @since 5.0.0
 */
public class AbacAuththenticationWrapper implements Authentication {

	private Authentication authentication;
	private Set<String> authSet;

	public AbacAuththenticationWrapper(Authentication authentication) {
		this.authentication = authentication;
		if (authentication.getAuthorities() != null) {
			authSet = new HashSet<String>(authentication.getAuthorities().size());
			for (GrantedAuthority auth : authentication.getAuthorities()) {
				authSet.add(auth.getAuthority());
			}
		}
	}

	public Authentication getAuthentication() {
		return authentication;
	}

	public boolean hasAuthority(String auth) {
		return authSet.contains(auth);
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return authentication.getAuthorities();
	}

	@Override
	public Object getCredentials() {
		return authentication.getCredentials();
	}

	@Override
	public Object getDetails() {
		return authentication.getDetails();
	}

	public Object getPrincipal() {
		return authentication.getPrincipal();
	}

	@Override
	public boolean isAuthenticated() {
		return authentication.isAuthenticated();
	}

	@Override
	public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
		authentication.setAuthenticated(isAuthenticated);
	}

	@Override
	public String getName() {
		return authentication.getName();
	}
}

