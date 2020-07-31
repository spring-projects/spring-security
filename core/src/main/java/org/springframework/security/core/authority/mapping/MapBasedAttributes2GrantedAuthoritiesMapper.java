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
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.StringTokenizer;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * This class implements the Attributes2GrantedAuthoritiesMapper and
 * MappableAttributesRetriever interfaces based on the supplied Map. It supports both
 * one-to-one and one-to-many mappings. The granted authorities to map to can be supplied
 * either as a String or as a GrantedAuthority object.
 *
 * @author Ruud Senden
 */
public class MapBasedAttributes2GrantedAuthoritiesMapper
		implements Attributes2GrantedAuthoritiesMapper, MappableAttributesRetriever, InitializingBean {

	private Map<String, Collection<GrantedAuthority>> attributes2grantedAuthoritiesMap = null;

	private String stringSeparator = ",";

	private Set<String> mappableAttributes = null;

	@Override
	public void afterPropertiesSet() {
		Assert.notNull(this.attributes2grantedAuthoritiesMap, "attributes2grantedAuthoritiesMap must be set");
	}

	/**
	 * Map the given array of attributes to Spring Security GrantedAuthorities.
	 */
	@Override
	public List<GrantedAuthority> getGrantedAuthorities(Collection<String> attributes) {
		ArrayList<GrantedAuthority> result = new ArrayList<>();
		for (String attribute : attributes) {
			Collection<GrantedAuthority> granted = this.attributes2grantedAuthoritiesMap.get(attribute);
			if (granted != null) {
				result.addAll(granted);
			}
		}
		result.trimToSize();
		return result;
	}

	/**
	 * @return Returns the attributes2grantedAuthoritiesMap.
	 */
	public Map<String, Collection<GrantedAuthority>> getAttributes2grantedAuthoritiesMap() {
		return this.attributes2grantedAuthoritiesMap;
	}

	/**
	 * @param attributes2grantedAuthoritiesMap The attributes2grantedAuthoritiesMap to
	 * set.
	 */
	public void setAttributes2grantedAuthoritiesMap(final Map<?, ?> attributes2grantedAuthoritiesMap) {
		Assert.notEmpty(attributes2grantedAuthoritiesMap,
				"A non-empty attributes2grantedAuthoritiesMap must be supplied");
		this.attributes2grantedAuthoritiesMap = preProcessMap(attributes2grantedAuthoritiesMap);
		this.mappableAttributes = Collections.unmodifiableSet(this.attributes2grantedAuthoritiesMap.keySet());
	}

	/**
	 * Preprocess the given map to convert all the values to GrantedAuthority collections
	 * @param orgMap The map to process
	 * @return the processed Map
	 */
	private Map<String, Collection<GrantedAuthority>> preProcessMap(Map<?, ?> orgMap) {
		Map<String, Collection<GrantedAuthority>> result = new HashMap<>(orgMap.size());
		for (Map.Entry<?, ?> entry : orgMap.entrySet()) {
			Assert.isInstanceOf(String.class, entry.getKey(),
					"attributes2grantedAuthoritiesMap contains non-String objects as keys");
			result.put((String) entry.getKey(), getGrantedAuthorityCollection(entry.getValue()));
		}
		return result;
	}

	/**
	 * Convert the given value to a collection of Granted Authorities
	 * @param value The value to convert to a GrantedAuthority Collection
	 * @return Collection containing the GrantedAuthority Collection
	 */
	private Collection<GrantedAuthority> getGrantedAuthorityCollection(Object value) {
		Collection<GrantedAuthority> result = new ArrayList<>();
		addGrantedAuthorityCollection(result, value);
		return result;
	}

	/**
	 * Convert the given value to a collection of Granted Authorities, adding the result
	 * to the given result collection.
	 * @param value The value to convert to a GrantedAuthority Collection
	 * @return Collection containing the GrantedAuthority Collection
	 */
	private void addGrantedAuthorityCollection(Collection<GrantedAuthority> result, Object value) {
		if (value == null) {
			return;
		}
		if (value instanceof Collection<?>) {
			addGrantedAuthorityCollection(result, (Collection<?>) value);
		}
		else if (value instanceof Object[]) {
			addGrantedAuthorityCollection(result, (Object[]) value);
		}
		else if (value instanceof String) {
			addGrantedAuthorityCollection(result, (String) value);
		}
		else if (value instanceof GrantedAuthority) {
			result.add((GrantedAuthority) value);
		}
		else {
			throw new IllegalArgumentException("Invalid object type: " + value.getClass().getName());
		}
	}

	private void addGrantedAuthorityCollection(Collection<GrantedAuthority> result, Collection<?> value) {
		for (Object elt : value) {
			addGrantedAuthorityCollection(result, elt);
		}
	}

	private void addGrantedAuthorityCollection(Collection<GrantedAuthority> result, Object[] value) {
		for (Object aValue : value) {
			addGrantedAuthorityCollection(result, aValue);
		}
	}

	private void addGrantedAuthorityCollection(Collection<GrantedAuthority> result, String value) {
		StringTokenizer tokenizer = new StringTokenizer(value, this.stringSeparator, false);
		while (tokenizer.hasMoreTokens()) {
			String token = tokenizer.nextToken();
			if (StringUtils.hasText(token)) {
				result.add(new SimpleGrantedAuthority(token));
			}
		}
	}

	/**
	 *
	 * @see org.springframework.security.core.authority.mapping.MappableAttributesRetriever#getMappableAttributes()
	 */
	@Override
	public Set<String> getMappableAttributes() {
		return this.mappableAttributes;
	}

	/**
	 * @return Returns the stringSeparator.
	 */
	public String getStringSeparator() {
		return this.stringSeparator;
	}

	/**
	 * @param stringSeparator The stringSeparator to set.
	 */
	public void setStringSeparator(String stringSeparator) {
		this.stringSeparator = stringSeparator;
	}

}
