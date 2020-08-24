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

import java.util.ArrayList;
import java.util.List;

import org.jasig.cas.client.validation.Assertion;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.Assert;

/**
 * Populates the {@link org.springframework.security.core.GrantedAuthority}s for a user by
 * reading a list of attributes that were returned as part of the CAS response. Each
 * attribute is read and each value of the attribute is turned into a GrantedAuthority. If
 * the attribute has no value then its not added.
 *
 * @author Scott Battaglia
 * @since 3.0
 */
public final class GrantedAuthorityFromAssertionAttributesUserDetailsService
		extends AbstractCasAssertionUserDetailsService {

	private static final String NON_EXISTENT_PASSWORD_VALUE = "NO_PASSWORD";

	private final String[] attributes;

	private boolean convertToUpperCase = true;

	public GrantedAuthorityFromAssertionAttributesUserDetailsService(final String[] attributes) {
		Assert.notNull(attributes, "attributes cannot be null.");
		Assert.isTrue(attributes.length > 0, "At least one attribute is required to retrieve roles from.");
		this.attributes = attributes;
	}

	@SuppressWarnings("unchecked")
	@Override
	protected UserDetails loadUserDetails(final Assertion assertion) {
		List<GrantedAuthority> grantedAuthorities = new ArrayList<>();
		for (String attribute : this.attributes) {
			Object value = assertion.getPrincipal().getAttributes().get(attribute);
			if (value != null) {
				if (value instanceof List) {
					for (Object o : (List<?>) value) {
						grantedAuthorities.add(createSimpleGrantedAuthority(o));
					}
				}
				else {
					grantedAuthorities.add(createSimpleGrantedAuthority(value));
				}
			}
		}
		return new User(assertion.getPrincipal().getName(), NON_EXISTENT_PASSWORD_VALUE, true, true, true, true,
				grantedAuthorities);
	}

	private SimpleGrantedAuthority createSimpleGrantedAuthority(Object o) {
		return new SimpleGrantedAuthority(this.convertToUpperCase ? o.toString().toUpperCase() : o.toString());
	}

	/**
	 * Converts the returned attribute values to uppercase values.
	 * @param convertToUpperCase true if it should convert, false otherwise.
	 */
	public void setConvertToUpperCase(final boolean convertToUpperCase) {
		this.convertToUpperCase = convertToUpperCase;
	}

}
