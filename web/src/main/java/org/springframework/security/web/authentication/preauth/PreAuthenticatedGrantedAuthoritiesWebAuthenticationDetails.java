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
package org.springframework.security.web.authentication.preauth;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.security.core.authority.GrantedAuthoritiesContainer;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

import javax.servlet.http.HttpServletRequest;
import java.util.*;

/**
 * This WebAuthenticationDetails implementation allows for storing a list of
 * pre-authenticated Granted Authorities.
 *
 * @author Ruud Senden
 * @author Luke Taylor
 * @since 2.0
 */
public class PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetails extends
		WebAuthenticationDetails implements GrantedAuthoritiesContainer {

	private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

	private final List<GrantedAuthority> authorities;

	public PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetails(
			HttpServletRequest request, Collection<? extends GrantedAuthority> authorities) {
		super(request);

		List<GrantedAuthority> temp = new ArrayList<GrantedAuthority>(authorities.size());
		temp.addAll(authorities);
		this.authorities = Collections.unmodifiableList(temp);
	}

	public List<GrantedAuthority> getGrantedAuthorities() {
		return authorities;
	}

	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append(super.toString()).append("; ");
		sb.append(authorities);
		return sb.toString();
	}
}
