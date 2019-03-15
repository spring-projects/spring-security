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
package org.springframework.security.cas.userdetails;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.util.Assert;
import org.jasig.cas.client.validation.Assertion;

import java.util.List;
import java.util.ArrayList;

/**
 * Populates the {@link org.springframework.security.core.GrantedAuthority}s for a user by
 * reading a list of attributes that were returned as part of the CAS response. Each
 * attribute is read and each value of the attribute is turned into a GrantedAuthority. If
 * the attribute has no value then its not added.
 *
 * @author Scott Battaglia
 * @since 3.0
 */
public final class GrantedAuthorityFromAssertionAttributesUserDetailsService extends
		AbstractCasAssertionUserDetailsService {

	private static final String NON_EXISTENT_PASSWORD_VALUE = "NO_PASSWORD";

	private final String[] attributes;

	private boolean convertToUpperCase = true;

	public GrantedAuthorityFromAssertionAttributesUserDetailsService(
			final String[] attributes) {
		Assert.notNull(attributes, "attributes cannot be null.");
		Assert.isTrue(attributes.length > 0,
				"At least one attribute is required to retrieve roles from.");
		this.attributes = attributes;
	}

	@SuppressWarnings("unchecked")
	@Override
	protected UserDetails loadUserDetails(final Assertion assertion) {
		final List<GrantedAuthority> grantedAuthorities = new ArrayList<>();

		for (final String attribute : this.attributes) {
			final Object value = assertion.getPrincipal().getAttributes().get(attribute);

			if (value == null) {
				continue;
			}

			if (value instanceof List) {
				final List list = (List) value;

				for (final Object o : list) {
					grantedAuthorities.add(new SimpleGrantedAuthority(
							this.convertToUpperCase ? o.toString().toUpperCase() : o
									.toString()));
				}

			}
			else {
				grantedAuthorities.add(new SimpleGrantedAuthority(
						this.convertToUpperCase ? value.toString().toUpperCase() : value
								.toString()));
			}

		}

		return new User(assertion.getPrincipal().getName(), NON_EXISTENT_PASSWORD_VALUE,
				true, true, true, true, grantedAuthorities);
	}

	/**
	 * Converts the returned attribute values to uppercase values.
	 *
	 * @param convertToUpperCase true if it should convert, false otherwise.
	 */
	public void setConvertToUpperCase(final boolean convertToUpperCase) {
		this.convertToUpperCase = convertToUpperCase;
	}
}
