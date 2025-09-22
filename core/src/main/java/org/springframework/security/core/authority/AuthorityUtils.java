/*
 * Copyright 2004-present the original author or authors.
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
import java.util.stream.Stream;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * Utility method for manipulating <tt>GrantedAuthority</tt> collections etc.
 * <p>
 * Mainly intended for internal use.
 *
 * @author Luke Taylor
 * @author Evgeniy Cheban
 */
public final class AuthorityUtils {

	public static final List<GrantedAuthority> NO_AUTHORITIES = Collections.emptyList();

	private static String[] KNOWN_PREFIXES = { "ROLE_", "SCOPE_", "FACTOR_" };

	private AuthorityUtils() {
	}

	/**
	 * Creates a array of GrantedAuthority objects from a comma-separated string
	 * representation (e.g. "ROLE_A, ROLE_B, ROLE_C").
	 * @param authorityString the comma-separated string
	 * @return the authorities created by tokenizing the string
	 */
	public static List<GrantedAuthority> commaSeparatedStringToAuthorityList(String authorityString) {
		return createAuthorityList(StringUtils.tokenizeToStringArray(authorityString, ","));
	}

	/**
	 * Converts an array of GrantedAuthority objects to a Set.
	 * @return a Set of the Strings obtained from each call to
	 * GrantedAuthority.getAuthority()
	 */
	public static Set<String> authorityListToSet(Collection<? extends GrantedAuthority> userAuthorities) {
		Assert.notNull(userAuthorities, "userAuthorities cannot be null");
		Set<String> set = new HashSet<>(userAuthorities.size());
		for (GrantedAuthority authority : userAuthorities) {
			set.add(authority.getAuthority());
		}
		return set;
	}

	/**
	 * Converts authorities into a List of GrantedAuthority objects.
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

	/**
	 * Converts authorities into a List of GrantedAuthority objects.
	 * @param authorities the authorities to convert
	 * @return a List of GrantedAuthority objects
	 * @since 6.1
	 */
	public static List<GrantedAuthority> createAuthorityList(Collection<String> authorities) {
		List<GrantedAuthority> grantedAuthorities = new ArrayList<>(authorities.size());
		for (String authority : authorities) {
			grantedAuthorities.add(new SimpleGrantedAuthority(authority));
		}
		return grantedAuthorities;
	}

	/**
	 * Return a {@link Stream} containing only the authorities of the given type;
	 * {@code "ROLE"}, {@code "SCOPE"}, or {@code "FACTOR"}.
	 * @param type the authority type; {@code "ROLE"}, {@code "SCOPE"}, or
	 * {@code "FACTOR"}
	 * @param authorities the list of authorities
	 * @return a {@link Stream} containing the authorities of the given type
	 */
	public static Stream<GrantedAuthority> authoritiesOfType(String type, Collection<GrantedAuthority> authorities) {
		return authorities.stream().filter((a) -> a.getAuthority().startsWith(type + "_"));
	}

	/**
	 * Return the simple name of a {@link GrantedAuthority}, which is its name, less any
	 * common prefix; that is, {@code ROLE_}, {@code SCOPE_}, or {@code FACTOR_}.
	 * <p>
	 * For example, if the authority is {@code ROLE_USER}, then the simple name is
	 * {@code user}.
	 * <p>
	 * If the authority is {@code FACTOR_PASSWORD}, then the simple name is
	 * {@code password}.
	 * @param authority the granted authority
	 * @return the simple name of the authority
	 */
	public static String getSimpleName(GrantedAuthority authority) {
		String name = authority.getAuthority();
		for (String prefix : KNOWN_PREFIXES) {
			if (name.startsWith(prefix)) {
				return name.substring(prefix.length());
			}
		}
		return name;
	}

}
