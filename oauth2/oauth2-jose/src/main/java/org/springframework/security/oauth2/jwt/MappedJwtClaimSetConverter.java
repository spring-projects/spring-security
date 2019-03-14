/*
 * Copyright 2002-2018 the original author or authors.
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

import java.net.URI;
import java.net.URL;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

import org.springframework.core.convert.converter.Converter;
import org.springframework.util.Assert;

/**
 * Converts a JWT claim set, claim by claim. Can be configured with custom converters
 * by claim name.
 *
 * @author Josh Cummings
 * @since 5.1
 */
public final class MappedJwtClaimSetConverter
		implements Converter<Map<String, Object>, Map<String, Object>> {

	private static final Converter<Object, Collection<String>> AUDIENCE_CONVERTER = new AudienceConverter();
	private static final Converter<Object, String> ISSUER_CONVERTER = new IssuerConverter();
	private static final Converter<Object, String> STRING_CONVERTER = new StringConverter();
	private static final Converter<Object, Instant> TEMPORAL_CONVERTER = new InstantConverter();

	private final Map<String, Converter<Object, ?>> claimConverters;

	/**
	 * Constructs a {@link MappedJwtClaimSetConverter} with the provided arguments
	 *
	 * This will completely replace any set of default converters.
	 *
	 * @param claimConverters The {@link Map} of converters to use
	 */
	public MappedJwtClaimSetConverter(Map<String, Converter<Object, ?>> claimConverters) {
		Assert.notNull(claimConverters, "claimConverters cannot be null");
		this.claimConverters = new HashMap<>(claimConverters);
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
	 * To completely replace the underlying {@link Map} of converters, {@see MappedJwtClaimSetConverter(Map)}.
	 *
	 * @param claimConverters
	 * @return An instance of {@link MappedJwtClaimSetConverter} that contains the converters provided,
	 *   plus any defaults that were not overridden.
	 */
	public static MappedJwtClaimSetConverter withDefaults
			(Map<String, Converter<Object, ?>> claimConverters) {
		Assert.notNull(claimConverters, "claimConverters cannot be null");

		Map<String, Converter<Object, ?>> claimNameToConverter = new HashMap<>();
		claimNameToConverter.put(JwtClaimNames.AUD, AUDIENCE_CONVERTER);
		claimNameToConverter.put(JwtClaimNames.EXP, TEMPORAL_CONVERTER);
		claimNameToConverter.put(JwtClaimNames.IAT, TEMPORAL_CONVERTER);
		claimNameToConverter.put(JwtClaimNames.ISS, ISSUER_CONVERTER);
		claimNameToConverter.put(JwtClaimNames.JTI, STRING_CONVERTER);
		claimNameToConverter.put(JwtClaimNames.NBF, TEMPORAL_CONVERTER);
		claimNameToConverter.put(JwtClaimNames.SUB, STRING_CONVERTER);
		claimNameToConverter.putAll(claimConverters);

		return new MappedJwtClaimSetConverter(claimNameToConverter);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Map<String, Object> convert(Map<String, Object> claims) {
		Assert.notNull(claims, "claims cannot be null");

		Map<String, Object> mappedClaims = new HashMap<>(claims);

		for (Map.Entry<String, Converter<Object, ?>> entry : this.claimConverters.entrySet()) {
			String claimName = entry.getKey();
			Converter<Object, ?> converter = entry.getValue();
			if (converter != null) {
				Object claim = claims.get(claimName);
				Object mappedClaim = converter.convert(claim);
				mappedClaims.compute(claimName, (key, value) -> mappedClaim);
			}
		}

		Instant issuedAt = (Instant) mappedClaims.get(JwtClaimNames.IAT);
		Instant expiresAt = (Instant) mappedClaims.get(JwtClaimNames.EXP);
		if (issuedAt == null && expiresAt != null) {
			mappedClaims.put(JwtClaimNames.IAT, expiresAt.minusSeconds(1));
		}

		return mappedClaims;
	}

	/**
	 * Coerces an <a target="_blank" href="https://tools.ietf.org/html/rfc7519#section-4.1.3">Audience</a> claim
	 * into a {@link Collection<String>}, ignoring null values, and throwing an error if its coercion efforts fail.
	 */
	private static class AudienceConverter implements Converter<Object, Collection<String>> {

		@Override
		public Collection<String> convert(Object source) {
			if (source == null) {
				return null;
			}

			if (source instanceof Collection) {
				return ((Collection<?>) source).stream()
						.filter(Objects::nonNull)
						.map(Objects::toString)
						.collect(Collectors.toList());
			}

			return Arrays.asList(source.toString());
		}
	}

	/**
	 * Coerces an <a target="_blank" href="https://tools.ietf.org/html/rfc7519#section-4.1.1">Issuer</a> claim
	 * into a {@link URL}, ignoring null values, and throwing an error if its coercion efforts fail.
	 */
	private static class IssuerConverter implements Converter<Object, String> {

		@Override
		public String convert(Object source) {
			if (source == null) {
				return null;
			}

			if (source instanceof URL) {
				return ((URL) source).toExternalForm();
			}

			if (source instanceof String && ((String) source).contains(":")) {
				try {
					return URI.create((String) source).toString();
				} catch (Exception e) {
					throw new IllegalStateException("Could not coerce " + source + " into a URI String", e);
				}
			}

			return source.toString();
		}
	}

	/**
	 * Coerces a claim into an {@link Instant}, ignoring null values, and throwing an error
	 * if its coercion efforts fail.
	 */
	private static class InstantConverter implements Converter<Object, Instant> {
		@Override
		public Instant convert(Object source) {
			if (source == null) {
				return null;
			}

			if (source instanceof Instant) {
				return (Instant) source;
			}

			if (source instanceof Date) {
				return ((Date) source).toInstant();
			}

			if (source instanceof Number) {
				return Instant.ofEpochSecond(((Number) source).longValue());
			}

			try {
				return Instant.ofEpochSecond(Long.parseLong(source.toString()));
			} catch (Exception e) {
				throw new IllegalStateException("Could not coerce " + source + " into an Instant", e);
			}
		}
	}

	/**
	 * Coerces a claim into a {@link String}, ignoring null values, and throwing an error if its
	 * coercion efforts fail.
	 */
	private static class StringConverter implements Converter<Object, String> {
		@Override
		public String convert(Object source) {
			if (source == null) {
				return null;
			}

			return source.toString();
		}
	}
}
