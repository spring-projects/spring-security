/*
 * Copyright 2002-2019 the original author or authors.
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
package org.springframework.security.oauth2.server.resource.authentication;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.core.convert.converter.Converter;
import org.springframework.util.StringUtils;

/**
 * Extracts the scopes from {@code Map<String,Object>} claims.
 * Supported values are space separated strings and string collections.
 * Only the claims listed in "claimsToScan" provided at construction are scanned.
 * Returned scopes are the union of successfully parsed values.
 *
 * @author Eric Deandrea
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 * @since 5.2
 */
public class TokenAttributesScopesConverter implements Converter<Map<String, Object>, Set<String>> {

	static final Collection<String> WELL_KNOWN_SCOPE_ATTRIBUTE_NAMES = Arrays.asList("scope", "scp");

	private Set<String> claimsToScan;

	/**
	 * @param claimsToScan what claims should be looked for {@code String} or {@code Collection<String>} scopes 
	 */
	public TokenAttributesScopesConverter(final Collection<String> claimsToScan) {
		setClaimsToScan(claimsToScan);
	}

	/**
	 * Defaults scanned scope claims to reasonable ones: {@link #WELL_KNOWN_SCOPE_ATTRIBUTE_NAMES}
	 */
	public TokenAttributesScopesConverter() {
		this(WELL_KNOWN_SCOPE_ATTRIBUTE_NAMES);
	}

	/**
	 * Gets the scopes from "claimsToScan".
	 * Supported values are space separated strings and string collections.
	 * Claims with unsupported values are skipped.
	 * If several claims have valid values, returned scopes are the union of all.
	 * 
	 * @param claims Token claims
	 * @return The scopes from the token
	 */
	@SuppressWarnings("unchecked")
	@Override
	public Set<String> convert(final Map<String, Object> claims) {
		return claims.entrySet().stream().filter(e -> claimsToScan.contains(e.getKey())).flatMap(scopesEntry -> {
			final Object scopes = scopesEntry.getValue();
			if (scopes instanceof String) {
				if (StringUtils.hasText((String) scopes)) {
					return Stream.of(((String) scopes).split(" "));
				} else {
					return Stream.empty();
				}
			} else if (scopes instanceof Collection) {
				return ((Collection<String>) scopes).stream();
			}
			return Stream.empty();
		}).collect(Collectors.toSet());
	}

	public void setClaimsToScan(final Collection<String> claimsToScan) {
		this.claimsToScan = new HashSet<>(claimsToScan);
	}

}
