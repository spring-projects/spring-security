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

package org.springframework.security.oauth2.jwt;

import org.springframework.core.convert.TypeDescriptor;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.oauth2.core.converter.ClaimConversionService;
import org.springframework.security.oauth2.core.converter.ClaimTypeConverter;
import org.springframework.util.Assert;

import java.net.URI;
import java.net.URL;
import java.time.Instant;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Converts a JWT claim set, claim by claim. Can be configured with custom converters
 * by claim name.
 *
 * @author Josh Cummings
 * @since 5.1
 * @see ClaimTypeConverter
 */
public final class MappedJwtClaimSetConverter implements Converter<Map<String, Object>, Map<String, Object>> {
	private final Map<String, Converter<Object, ?>> claimTypeConverters;
	private final Converter<Map<String, Object>, Map<String, Object>> delegate;

	/**
	 * Constructs a {@link MappedJwtClaimSetConverter} with the provided arguments
	 *
	 * This will completely replace any set of default converters.
	 *
	 * @param claimTypeConverters The {@link Map} of converters to use
	 */
	public MappedJwtClaimSetConverter(Map<String, Converter<Object, ?>> claimTypeConverters) {
		Assert.notNull(claimTypeConverters, "claimTypeConverters cannot be null");
		this.claimTypeConverters = claimTypeConverters;
		this.delegate = new ClaimTypeConverter(claimTypeConverters);
	}

	/**
	 * Construct a {@link MappedJwtClaimSetConverter}, overriding individual claim
	 * converters with the provided {@link Map} of {@link Converter}s.
	 *
	 * For example, the following would give an instance that is configured with only the default
	 * claim converters:
	 *
	 * <pre>
	 * 	MappedJwtClaimSetConverter.withDefaults(Collections.emptyMap());
	 * </pre>
	 *
	 * Or, the following would supply a custom converter for the subject, leaving the other defaults
	 * in place:
	 *
	 * <pre>
	 * 	MappedJwtClaimsSetConverter.withDefaults(
	 * 		Collections.singletonMap(JwtClaimNames.SUB, new UserDetailsServiceJwtSubjectConverter()));
	 * </pre>
	 *
	 * To completely replace the underlying {@link Map} of converters, see {@link MappedJwtClaimSetConverter#MappedJwtClaimSetConverter(Map)}.
	 *
	 * @param claimTypeConverters
	 * @return An instance of {@link MappedJwtClaimSetConverter} that contains the converters provided,
	 *   plus any defaults that were not overridden.
	 */
	public static MappedJwtClaimSetConverter withDefaults(Map<String, Converter<Object, ?>> claimTypeConverters) {
		Assert.notNull(claimTypeConverters, "claimTypeConverters cannot be null");

		Converter<Object, ?> stringConverter = getConverter(TypeDescriptor.valueOf(String.class));
		Converter<Object, ?> collectionStringConverter = getConverter(
				TypeDescriptor.collection(Collection.class, TypeDescriptor.valueOf(String.class)));

		Map<String, Converter<Object, ?>> claimNameToConverter = new HashMap<>();
		claimNameToConverter.put(JwtClaimNames.AUD, collectionStringConverter);
		claimNameToConverter.put(JwtClaimNames.EXP, MappedJwtClaimSetConverter::convertInstant);
		claimNameToConverter.put(JwtClaimNames.IAT, MappedJwtClaimSetConverter::convertInstant);
		claimNameToConverter.put(JwtClaimNames.ISS, MappedJwtClaimSetConverter::convertIssuer);
		claimNameToConverter.put(JwtClaimNames.JTI, stringConverter);
		claimNameToConverter.put(JwtClaimNames.NBF, MappedJwtClaimSetConverter::convertInstant);
		claimNameToConverter.put(JwtClaimNames.SUB, stringConverter);
		claimNameToConverter.putAll(claimTypeConverters);

		return new MappedJwtClaimSetConverter(claimNameToConverter);
	}

	private static Converter<Object, ?> getConverter(TypeDescriptor targetDescriptor) {
		final TypeDescriptor sourceDescriptor = TypeDescriptor.valueOf(Object.class);
		return source -> ClaimConversionService.getSharedInstance().convert(source, sourceDescriptor, targetDescriptor);
	}

	private static Instant convertInstant(Object source) {
		if (source == null) {
			return null;
		}
		final TypeDescriptor objectType = TypeDescriptor.valueOf(Object.class);
		final TypeDescriptor instantType = TypeDescriptor.valueOf(Instant.class);
		Instant result = (Instant) ClaimConversionService.getSharedInstance().convert(source, objectType, instantType);
		if (result == null) {
			throw new IllegalStateException("Could not coerce " + source + " into an Instant");
		}
		return result;
	}

	private static String convertIssuer(Object source) {
		if (source == null) {
			return null;
		}
		final TypeDescriptor objectType = TypeDescriptor.valueOf(Object.class);
		final TypeDescriptor urlType = TypeDescriptor.valueOf(URL.class);
		URL result = (URL) ClaimConversionService.getSharedInstance().convert(source, objectType, urlType);
		if (result != null) {
			return result.toExternalForm();
		}
		if (source instanceof String && ((String) source).contains(":")) {
			try {
				return new URI((String) source).toString();
			} catch (Exception ex) {
				throw new IllegalStateException("Could not coerce " + source + " into a URI String", ex);
			}
		}
		final TypeDescriptor stringType = TypeDescriptor.valueOf(String.class);
		return (String) ClaimConversionService.getSharedInstance().convert(source, objectType, stringType);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Map<String, Object> convert(Map<String, Object> claims) {
		Assert.notNull(claims, "claims cannot be null");

		Map<String, Object> mappedClaims = this.delegate.convert(claims);

		mappedClaims = removeClaims(mappedClaims);
		mappedClaims = addClaims(mappedClaims);

		Instant issuedAt = (Instant) mappedClaims.get(JwtClaimNames.IAT);
		Instant expiresAt = (Instant) mappedClaims.get(JwtClaimNames.EXP);
		if (issuedAt == null && expiresAt != null) {
			mappedClaims.put(JwtClaimNames.IAT, expiresAt.minusSeconds(1));
		}

		return mappedClaims;
	}

	private Map<String, Object> removeClaims(Map<String, Object> claims) {
		return claims.entrySet().stream()
				.filter(e -> e.getValue() != null)
				.collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
	}

	private Map<String, Object> addClaims(Map<String, Object> claims) {
		Map<String, Object> result = new HashMap<>(claims);
		this.claimTypeConverters.entrySet().stream()
				.filter(e -> !claims.containsKey(e.getKey()))
				.filter(e -> e.getValue().convert(null) != null)
				.forEach(e -> result.put(e.getKey(), e.getValue().convert(null)));
		return result;
	}
}
