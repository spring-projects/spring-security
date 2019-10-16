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
package org.springframework.security.core.authority;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.StringUtils;
import org.springframework.util.Assert;

/**
 * Utility method for manipulating <tt>GrantedAuthority</tt> collections etc.
 * <p>
 * Mainly intended for internal use.
 *
 * @author Luke Taylor
 */
public abstract class AuthorityUtils {
	public static final List<GrantedAuthority> NO_AUTHORITIES = Collections.emptyList();

	/**
	 * Creates a array of GrantedAuthority objects from a comma-separated string
	 * representation (e.g. "ROLE_A, ROLE_B, ROLE_C").
	 *
	 * @param authorityString the comma-separated string
	 * @return the authorities created by tokenizing the string
	 */
	public static List<GrantedAuthority> commaSeparatedStringToAuthorityList(
			String authorityString) {
		return createAuthorityList(StringUtils
				.tokenizeToStringArray(authorityString, ","));
	}

	/**
	 * Converts an array of GrantedAuthority objects to a Set.
	 * @return a Set of the Strings obtained from each call to
	 * GrantedAuthority.getAuthority()
	 */
	public static Set<String> authorityListToSet(
			Collection<? extends GrantedAuthority> userAuthorities) {
		Assert.notNull(userAuthorities, "userAuthorities cannot be null");
		Set<String> set = new HashSet<>(userAuthorities.size());

		for (GrantedAuthority authority : userAuthorities) {
			set.add(authority.getAuthority());
		}

		return set;
	}

	/**
	 * Converts authorities into a List of GrantedAuthority objects.
	 *
	 * @param authorities the authorities to convert
	 * @return a List of GrantedAuthority objects
	 */
	public static List<GrantedAuthority> createAuthorityList(String... authorities) {
		List<GrantedAuthority> grantedAuthorities = new ArrayList<>(authorities.length);

		for (String authority : authorities) {
			grantedAuthorities.add(new SimpleGrantedAuthority(authority));
		}

		return grantedAuthorities;
	}
}
