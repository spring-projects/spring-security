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
package org.springframework.security.openid;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * @deprecated The OpenID 1.0 and 2.0 protocols have been deprecated and users are
 * <a href="https://openid.net/specs/openid-connect-migration-1_0.html">encouraged to migrate</a>
 * to <a href="https://openid.net/connect/">OpenID Connect</a>, which is supported by <code>spring-security-oauth2</code>.
 * @author Luke Taylor
 * @since 3.1
 */
public class RegexBasedAxFetchListFactory implements AxFetchListFactory {
	private final Map<Pattern, List<OpenIDAttribute>> idToAttributes;

	/**
	 * @param regexMap map of regular-expressions (matching the identifier) to attributes
	 * which should be fetched for that pattern.
	 */
	public RegexBasedAxFetchListFactory(Map<String, List<OpenIDAttribute>> regexMap) {
		idToAttributes = new LinkedHashMap<>();
		for (Map.Entry<String, List<OpenIDAttribute>> entry : regexMap.entrySet()) {
			idToAttributes.put(Pattern.compile(entry.getKey()), entry.getValue());
		}
	}

	/**
	 * Iterates through the patterns stored in the map and returns the list of attributes
	 * defined for the first match. If no match is found, returns an empty list.
	 */
	public List<OpenIDAttribute> createAttributeList(String identifier) {
		for (Map.Entry<Pattern, List<OpenIDAttribute>> entry : idToAttributes.entrySet()) {
			if (entry.getKey().matcher(identifier).matches()) {
				return entry.getValue();
			}
		}

		return Collections.emptyList();
	}

}
