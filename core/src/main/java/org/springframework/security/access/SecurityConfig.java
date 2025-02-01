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

package org.springframework.security.access;

import java.io.Serial;
import java.util.ArrayList;
import java.util.List;

import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * Stores a {@link ConfigAttribute} as a <code>String</code>.
 *
 * @author Ben Alex
 */
public class SecurityConfig implements ConfigAttribute {

	@Serial
	private static final long serialVersionUID = -7138084564199804304L;

	private final String attrib;

	public SecurityConfig(String config) {
		Assert.hasText(config, "You must provide a configuration attribute");
		this.attrib = config;
	}

	@Override
	public boolean equals(Object obj) {
		if (obj instanceof ConfigAttribute attr) {
			return this.attrib.equals(attr.getAttribute());
		}
		return false;
	}

	@Override
	public String getAttribute() {
		return this.attrib;
	}

	@Override
	public int hashCode() {
		return this.attrib.hashCode();
	}

	@Override
	public String toString() {
		return this.attrib;
	}

	public static List<ConfigAttribute> createListFromCommaDelimitedString(String access) {
		return createList(StringUtils.commaDelimitedListToStringArray(access));
	}

	public static List<ConfigAttribute> createList(String... attributeNames) {
		Assert.notNull(attributeNames, "You must supply an array of attribute names");
		List<ConfigAttribute> attributes = new ArrayList<>(attributeNames.length);
		for (String attribute : attributeNames) {
			attributes.add(new SecurityConfig(attribute.trim()));
		}
		return attributes;
	}

}
