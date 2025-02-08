/*
 * Copyright 2002-2021 the original author or authors.
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

package org.springframework.security.authorization;

import java.io.Serial;
import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;

/**
 * Represents an {@link AuthorizationDecision} based on a collection of authorities
 *
 * @author Marcus Da Coregio
 * @since 5.6
 */
public class AuthorityAuthorizationDecision extends AuthorizationDecision {

	@Serial
	private static final long serialVersionUID = -8338309042331376592L;

	private final Collection<GrantedAuthority> authorities;

	public AuthorityAuthorizationDecision(boolean granted, Collection<GrantedAuthority> authorities) {
		super(granted);
		this.authorities = authorities;
	}

	public Collection<GrantedAuthority> getAuthorities() {
		return this.authorities;
	}

	@Override
	public String toString() {
		return getClass().getSimpleName() + " [" + "granted=" + isGranted() + ", authorities=" + this.authorities + ']';
	}

}
