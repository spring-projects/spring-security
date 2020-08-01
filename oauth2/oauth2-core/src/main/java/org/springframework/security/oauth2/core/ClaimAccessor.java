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

package org.springframework.security.oauth2.core;

import java.net.URL;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import org.springframework.core.convert.TypeDescriptor;
import org.springframework.security.oauth2.core.converter.ClaimConversionService;
import org.springframework.util.Assert;

/**
 * An &quot;accessor&quot; for a set of claims that may be used for assertions.
 *
 * @author Joe Grandja
 * @since 5.0
 */
public interface ClaimAccessor {

	/**
	 * Returns a set of claims that may be used for assertions.
	 * @return a {@code Map} of claims
	 */
	Map<String, Object> getClaims();

	/**
	 * Returns the claim value as a {@code T} type. The claim value is expected to be of
	 * type {@code T}.
	 *
	 * @since 5.2
	 * @param claim the name of the claim
	 * @param <T> the type of the claim value
	 * @return the claim value
	 */
	@SuppressWarnings("unchecked")
	default <T> T getClaim(String claim) {
		return !containsClaim(claim) ? null : (T) getClaims().get(claim);
	}

	/**
	 * Returns {@code true} if the claim exists in {@link #getClaims()}, otherwise
	 * {@code false}.
	 * @param claim the name of the claim
	 * @return {@code true} if the claim exists, otherwise {@code false}
	 */
	default Boolean containsClaim(String claim) {
		Assert.notNull(claim, "claim cannot be null");
		return getClaims().containsKey(claim);
	}

	/**
	 * Returns the claim value as a {@code String} or {@code null} if it does not exist or
	 * is equal to {@code null}.
	 * @param claim the name of the claim
	 * @return the claim value or {@code null} if it does not exist or is equal to
	 * {@code null}
	 */
	default String getClaimAsString(String claim) {
		return !containsClaim(claim) ? null
				: ClaimConversionService.getSharedInstance().convert(getClaims().get(claim), String.class);
	}

	/**
	 * Returns the claim value as a {@code Boolean} or {@code null} if it does not exist.
	 * @param claim the name of the claim
	 * @return the claim value or {@code null} if it does not exist
	 */
	default Boolean getClaimAsBoolean(String claim) {
		return !containsClaim(claim) ? null
				: ClaimConversionService.getSharedInstance().convert(getClaims().get(claim), Boolean.class);
	}

	/**
	 * Returns the claim value as an {@code Instant} or {@code null} if it does not exist.
	 * @param claim the name of the claim
	 * @return the claim value or {@code null} if it does not exist
	 */
	default Instant getClaimAsInstant(String claim) {
		if (!containsClaim(claim)) {
			return null;
		}
		Object claimValue = getClaims().get(claim);
		Instant convertedValue = ClaimConversionService.getSharedInstance().convert(claimValue, Instant.class);
		Assert.isTrue(convertedValue != null,
				() -> "Unable to convert claim '" + claim + "' of type '" + claimValue.getClass() + "' to Instant.");
		return convertedValue;
	}

	/**
	 * Returns the claim value as an {@code URL} or {@code null} if it does not exist.
	 * @param claim the name of the claim
	 * @return the claim value or {@code null} if it does not exist
	 */
	default URL getClaimAsURL(String claim) {
		if (!containsClaim(claim)) {
			return null;
		}
		Object claimValue = getClaims().get(claim);
		URL convertedValue = ClaimConversionService.getSharedInstance().convert(claimValue, URL.class);
		Assert.isTrue(convertedValue != null,
				() -> "Unable to convert claim '" + claim + "' of type '" + claimValue.getClass() + "' to URL.");
		return convertedValue;
	}

	/**
	 * Returns the claim value as a {@code Map<String, Object>} or {@code null} if it does
	 * not exist or cannot be assigned to a {@code Map}.
	 * @param claim the name of the claim
	 * @return the claim value or {@code null} if it does not exist or cannot be assigned
	 * to a {@code Map}
	 */
	@SuppressWarnings("unchecked")
	default Map<String, Object> getClaimAsMap(String claim) {
		if (!containsClaim(claim)) {
			return null;
		}
		final TypeDescriptor sourceDescriptor = TypeDescriptor.valueOf(Object.class);
		final TypeDescriptor targetDescriptor = TypeDescriptor.map(Map.class, TypeDescriptor.valueOf(String.class),
				TypeDescriptor.valueOf(Object.class));
		Object claimValue = getClaims().get(claim);
		Map<String, Object> convertedValue = (Map<String, Object>) ClaimConversionService.getSharedInstance()
				.convert(claimValue, sourceDescriptor, targetDescriptor);
		Assert.isTrue(convertedValue != null,
				() -> "Unable to convert claim '" + claim + "' of type '" + claimValue.getClass() + "' to Map.");
		return convertedValue;
	}

	/**
	 * Returns the claim value as a {@code List<String>} or {@code null} if it does not
	 * exist or cannot be assigned to a {@code List}.
	 * @param claim the name of the claim
	 * @return the claim value or {@code null} if it does not exist or cannot be assigned
	 * to a {@code List}
	 */
	@SuppressWarnings("unchecked")
	default List<String> getClaimAsStringList(String claim) {
		if (!containsClaim(claim)) {
			return null;
		}
		final TypeDescriptor sourceDescriptor = TypeDescriptor.valueOf(Object.class);
		final TypeDescriptor targetDescriptor = TypeDescriptor.collection(List.class,
				TypeDescriptor.valueOf(String.class));
		Object claimValue = getClaims().get(claim);
		List<String> convertedValue = (List<String>) ClaimConversionService.getSharedInstance().convert(claimValue,
				sourceDescriptor, targetDescriptor);
		Assert.isTrue(convertedValue != null,
				() -> "Unable to convert claim '" + claim + "' of type '" + claimValue.getClass() + "' to List.");
		return convertedValue;
	}

}
