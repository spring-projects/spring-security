/*
 * Copyright 2002-2014 the original author or authors.
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
package org.springframework.security.test.context.support;

import java.util.ArrayList;
import java.util.List;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.util.StringUtils;

/**
 * A {@link WithUserDetailsSecurityContextFactory} that works with {@link WithMockUser}.
 *
 * @author Rob Winch
 * @since 4.0
 * @see WithMockUser
 */
final class WithMockUserSecurityContextFactory implements
		WithSecurityContextFactory<WithMockUser> {

	public SecurityContext createSecurityContext(WithMockUser withUser) {
		String username = StringUtils.hasLength(withUser.username()) ? withUser
				.username() : withUser.value();
		if (username == null) {
			throw new IllegalArgumentException(withUser
					+ " cannot have null username on both username and value properites");
		}
		List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
		for (String role : withUser.roles()) {
			if (role.startsWith("ROLE_")) {
				throw new IllegalArgumentException("roles cannot start with ROLE_ Got "
						+ role);
			}
			authorities.add(new SimpleGrantedAuthority("ROLE_" + role));
		}
		User principal = new User(username, withUser.password(), true, true, true, true,
				authorities);
		Authentication authentication = new UsernamePasswordAuthenticationToken(
				principal, principal.getPassword(), principal.getAuthorities());
		SecurityContext context = SecurityContextHolder.createEmptyContext();
		context.setAuthentication(authentication);
		return context;
	}
}