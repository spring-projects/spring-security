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
package org.springframework.security.oauth2.core.converter;

import org.springframework.core.convert.converter.Converter;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;

import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * A {@link Converter} that provides type conversion for claim values.
 *
 * @author Joe Grandja
 * @since 5.2
 * @see Converter
 */
public final class ClaimTypeConverter implements Converter<Map<String, Object>, Map<String, Object>> {

	private final Map<String, Converter<Object, ?>> claimTypeConverters;

	/**
	 * Constructs a {@code ClaimTypeConverter} using the provided parameters.
	 * @param claimTypeConverters a {@link Map} of {@link Converter}(s) keyed by claim
	 * name
	 */
	public ClaimTypeConverter(Map<String, Converter<Object, ?>> claimTypeConverters) {
		Assert.notEmpty(claimTypeConverters, "claimTypeConverters cannot be empty");
		Assert.noNullElements(claimTypeConverters.values().toArray(), "Converter(s) cannot be null");
		this.claimTypeConverters = Collections.unmodifiableMap(new LinkedHashMap<>(claimTypeConverters));
	}

	@Override
	public Map<String, Object> convert(Map<String, Object> claims) {
		if (CollectionUtils.isEmpty(claims)) {
			return claims;
		}

		Map<String, Object> result = new HashMap<>(claims);
		this.claimTypeConverters.forEach((claimName, typeConverter) -> {
			if (claims.containsKey(claimName)) {
				Object claim = claims.get(claimName);
				Object mappedClaim = typeConverter.convert(claim);
				if (mappedClaim != null) {
					result.put(claimName, mappedClaim);
				}
			}
		});

		return result;
	}

}
