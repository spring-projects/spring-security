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
package org.springframework.security.core.authority.mapping;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Locale;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.util.Assert;

/**
 * <p>
 * This class implements the Attributes2GrantedAuthoritiesMapper interface by doing a
 * one-to-one mapping from roles to Spring Security GrantedAuthorities. Optionally a
 * prefix can be added, and the attribute name can be converted to upper or lower case.
 * <p>
 * By default, the attribute is prefixed with "ROLE_" unless it already starts with
 * "ROLE_", and no case conversion is done.
 *
 * @author Ruud Senden
 * @since 2.0
 */
public class SimpleAttributes2GrantedAuthoritiesMapper
		implements Attributes2GrantedAuthoritiesMapper, InitializingBean {

	private String attributePrefix = "ROLE_";

	private boolean convertAttributeToUpperCase = false;

	private boolean convertAttributeToLowerCase = false;

	private boolean addPrefixIfAlreadyExisting = false;

	/**
	 * Check whether all properties have been set to correct values.
	 */
	public void afterPropertiesSet() {
		Assert.isTrue(!(isConvertAttributeToUpperCase() && isConvertAttributeToLowerCase()),
				"Either convertAttributeToUpperCase or convertAttributeToLowerCase can be set to true, but not both");
	}

	/**
	 * Map the given list of string attributes one-to-one to Spring Security
	 * GrantedAuthorities.
	 */
	public List<GrantedAuthority> getGrantedAuthorities(Collection<String> attributes) {
		List<GrantedAuthority> result = new ArrayList<>(attributes.size());
		for (String attribute : attributes) {
			result.add(getGrantedAuthority(attribute));
		}
		return result;
	}

	/**
	 * Map the given role one-on-one to a Spring Security GrantedAuthority, optionally
	 * doing case conversion and/or adding a prefix.
	 * @param attribute The attribute for which to get a GrantedAuthority
	 * @return GrantedAuthority representing the given role.
	 */
	private GrantedAuthority getGrantedAuthority(String attribute) {
		if (isConvertAttributeToLowerCase()) {
			attribute = attribute.toLowerCase(Locale.getDefault());
		}
		else if (isConvertAttributeToUpperCase()) {
			attribute = attribute.toUpperCase(Locale.getDefault());
		}
		if (isAddPrefixIfAlreadyExisting() || !attribute.startsWith(getAttributePrefix())) {
			return new SimpleGrantedAuthority(getAttributePrefix() + attribute);
		}
		else {
			return new SimpleGrantedAuthority(attribute);
		}
	}

	private boolean isConvertAttributeToLowerCase() {
		return this.convertAttributeToLowerCase;
	}

	public void setConvertAttributeToLowerCase(boolean b) {
		this.convertAttributeToLowerCase = b;
	}

	private boolean isConvertAttributeToUpperCase() {
		return this.convertAttributeToUpperCase;
	}

	public void setConvertAttributeToUpperCase(boolean b) {
		this.convertAttributeToUpperCase = b;
	}

	private String getAttributePrefix() {
		return this.attributePrefix == null ? "" : this.attributePrefix;
	}

	public void setAttributePrefix(String string) {
		this.attributePrefix = string;
	}

	private boolean isAddPrefixIfAlreadyExisting() {
		return this.addPrefixIfAlreadyExisting;
	}

	public void setAddPrefixIfAlreadyExisting(boolean b) {
		this.addPrefixIfAlreadyExisting = b;
	}

}
