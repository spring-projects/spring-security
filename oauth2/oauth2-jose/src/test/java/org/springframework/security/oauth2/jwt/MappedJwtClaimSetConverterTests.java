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
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.junit.Test;

import org.springframework.core.convert.converter.Converter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

/**
 * Tests for {@link MappedJwtClaimSetConverter}
 *
 * @author Josh Cummings
 */
public class MappedJwtClaimSetConverterTests {

	@Test
	public void convertWhenUsingCustomExpiresAtConverterThenIssuedAtConverterStillConsultsIt() {
		Instant at = Instant.ofEpochMilli(1000000000000L);
		Converter<Object, Instant> expiresAtConverter = mock(Converter.class);
		given(expiresAtConverter.convert(any())).willReturn(at);
		MappedJwtClaimSetConverter converter = MappedJwtClaimSetConverter
				.withDefaults(Collections.singletonMap(JwtClaimNames.EXP, expiresAtConverter));
		Map<String, Object> source = new HashMap<>();
		Map<String, Object> target = converter.convert(source);
		assertThat(target.get(JwtClaimNames.IAT)).isEqualTo(Instant.ofEpochMilli(at.toEpochMilli()).minusSeconds(1));
	}

	@Test
	public void convertWhenUsingDefaultsThenBasesIssuedAtOffOfExpiration() {
		MappedJwtClaimSetConverter converter = MappedJwtClaimSetConverter.withDefaults(Collections.emptyMap());
		Map<String, Object> source = Collections.singletonMap(JwtClaimNames.EXP, 1000000000L);
		Map<String, Object> target = converter.convert(source);
		assertThat(target.get(JwtClaimNames.EXP)).isEqualTo(Instant.ofEpochSecond(1000000000L));
		assertThat(target.get(JwtClaimNames.IAT)).isEqualTo(Instant.ofEpochSecond(1000000000L).minusSeconds(1));
	}

	@Test
	public void convertWhenUsingDefaultsThenCoercesAudienceAccordingToJwtSpec() {
		MappedJwtClaimSetConverter converter = MappedJwtClaimSetConverter.withDefaults(Collections.emptyMap());
		Map<String, Object> source = Collections.singletonMap(JwtClaimNames.AUD, "audience");
		Map<String, Object> target = converter.convert(source);
		assertThat(target.get(JwtClaimNames.AUD)).isInstanceOf(Collection.class);
		assertThat(target.get(JwtClaimNames.AUD)).isEqualTo(Arrays.asList("audience"));
		source = Collections.singletonMap(JwtClaimNames.AUD, Arrays.asList("one", "two"));
		target = converter.convert(source);
		assertThat(target.get(JwtClaimNames.AUD)).isInstanceOf(Collection.class);
		assertThat(target.get(JwtClaimNames.AUD)).isEqualTo(Arrays.asList("one", "two"));
	}

	@Test
	public void convertWhenUsingDefaultsThenCoercesAllAttributesInJwtSpec() {
		MappedJwtClaimSetConverter converter = MappedJwtClaimSetConverter.withDefaults(Collections.emptyMap());
		Map<String, Object> source = new HashMap<>();
		source.put(JwtClaimNames.JTI, 1);
		source.put(JwtClaimNames.AUD, "audience");
		source.put(JwtClaimNames.EXP, 2000000000L);
		source.put(JwtClaimNames.IAT, new Date(1000000000000L));
		source.put(JwtClaimNames.ISS, "https://any.url");
		source.put(JwtClaimNames.NBF, 1000000000);
		source.put(JwtClaimNames.SUB, 1234);
		Map<String, Object> target = converter.convert(source);
		assertThat(target.get(JwtClaimNames.JTI)).isEqualTo("1");
		assertThat(target.get(JwtClaimNames.AUD)).isEqualTo(Arrays.asList("audience"));
		assertThat(target.get(JwtClaimNames.EXP)).isEqualTo(Instant.ofEpochSecond(2000000000L));
		assertThat(target.get(JwtClaimNames.IAT)).isEqualTo(Instant.ofEpochSecond(1000000000L));
		assertThat(target.get(JwtClaimNames.ISS)).isEqualTo("https://any.url");
		assertThat(target.get(JwtClaimNames.NBF)).isEqualTo(Instant.ofEpochSecond(1000000000L));
		assertThat(target.get(JwtClaimNames.SUB)).isEqualTo("1234");
	}

	@Test
	public void convertWhenUsingCustomConverterThenAllOtherDefaultsAreStillUsed() {
		Converter<Object, String> claimConverter = mock(Converter.class);
		MappedJwtClaimSetConverter converter = MappedJwtClaimSetConverter
				.withDefaults(Collections.singletonMap(JwtClaimNames.SUB, claimConverter));
		given(claimConverter.convert(any(Object.class))).willReturn("1234");
		Map<String, Object> source = new HashMap<>();
		source.put(JwtClaimNames.JTI, 1);
		source.put(JwtClaimNames.AUD, "audience");
		source.put(JwtClaimNames.EXP, Instant.ofEpochSecond(2000000000L));
		source.put(JwtClaimNames.IAT, new Date(1000000000000L));
		source.put(JwtClaimNames.ISS, URI.create("https://any.url"));
		source.put(JwtClaimNames.NBF, "1000000000");
		source.put(JwtClaimNames.SUB, 2345);
		Map<String, Object> target = converter.convert(source);
		assertThat(target.get(JwtClaimNames.JTI)).isEqualTo("1");
		assertThat(target.get(JwtClaimNames.AUD)).isEqualTo(Arrays.asList("audience"));
		assertThat(target.get(JwtClaimNames.EXP)).isEqualTo(Instant.ofEpochSecond(2000000000L));
		assertThat(target.get(JwtClaimNames.IAT)).isEqualTo(Instant.ofEpochSecond(1000000000L));
		assertThat(target.get(JwtClaimNames.ISS)).isEqualTo("https://any.url");
		assertThat(target.get(JwtClaimNames.NBF)).isEqualTo(Instant.ofEpochSecond(1000000000L));
		assertThat(target.get(JwtClaimNames.SUB)).isEqualTo("1234");
	}

	@Test
	public void convertWhenConverterReturnsNullThenClaimIsRemoved() {
		MappedJwtClaimSetConverter converter = MappedJwtClaimSetConverter.withDefaults(Collections.emptyMap());
		Map<String, Object> source = Collections.singletonMap(JwtClaimNames.ISS, null);
		Map<String, Object> target = converter.convert(source);
		assertThat(target).doesNotContainKey(JwtClaimNames.ISS);
	}

	@Test
	public void convertWhenConverterReturnsValueWhenEntryIsMissingThenEntryIsAdded() {
		Converter<Object, String> claimConverter = mock(Converter.class);
		MappedJwtClaimSetConverter converter = MappedJwtClaimSetConverter
				.withDefaults(Collections.singletonMap("custom-claim", claimConverter));
		given(claimConverter.convert(any())).willReturn("custom-value");
		Map<String, Object> source = new HashMap<>();
		Map<String, Object> target = converter.convert(source);
		assertThat(target.get("custom-claim")).isEqualTo("custom-value");
	}

	@Test
	public void convertWhenUsingConstructorThenOnlyConvertersInThatMapAreUsedForConversion() {
		Converter<Object, String> claimConverter = mock(Converter.class);
		MappedJwtClaimSetConverter converter = new MappedJwtClaimSetConverter(
				Collections.singletonMap(JwtClaimNames.SUB, claimConverter));
		given(claimConverter.convert(any(Object.class))).willReturn("1234");
		Map<String, Object> source = new HashMap<>();
		source.put(JwtClaimNames.JTI, new Object());
		source.put(JwtClaimNames.AUD, new Object());
		source.put(JwtClaimNames.EXP, Instant.ofEpochSecond(1L));
		source.put(JwtClaimNames.IAT, Instant.ofEpochSecond(1L));
		source.put(JwtClaimNames.ISS, new Object());
		source.put(JwtClaimNames.NBF, new Object());
		source.put(JwtClaimNames.SUB, new Object());
		Map<String, Object> target = converter.convert(source);
		assertThat(target.get(JwtClaimNames.JTI)).isEqualTo(source.get(JwtClaimNames.JTI));
		assertThat(target.get(JwtClaimNames.AUD)).isEqualTo(source.get(JwtClaimNames.AUD));
		assertThat(target.get(JwtClaimNames.EXP)).isEqualTo(source.get(JwtClaimNames.EXP));
		assertThat(target.get(JwtClaimNames.IAT)).isEqualTo(source.get(JwtClaimNames.IAT));
		assertThat(target.get(JwtClaimNames.ISS)).isEqualTo(source.get(JwtClaimNames.ISS));
		assertThat(target.get(JwtClaimNames.NBF)).isEqualTo(source.get(JwtClaimNames.NBF));
		assertThat(target.get(JwtClaimNames.SUB)).isEqualTo("1234");
	}

	@Test
	public void convertWhenUsingDefaultsThenFailedConversionThrowsIllegalStateException() {
		MappedJwtClaimSetConverter converter = MappedJwtClaimSetConverter.withDefaults(Collections.emptyMap());
		Map<String, Object> badIssuer = Collections.singletonMap(JwtClaimNames.ISS, "https://badly formed iss");
		assertThatCode(() -> converter.convert(badIssuer)).isInstanceOf(IllegalStateException.class);
		Map<String, Object> badIssuedAt = Collections.singletonMap(JwtClaimNames.IAT, "badly-formed-iat");
		assertThatCode(() -> converter.convert(badIssuedAt)).isInstanceOf(IllegalStateException.class);
		Map<String, Object> badExpiresAt = Collections.singletonMap(JwtClaimNames.EXP, "badly-formed-exp");
		assertThatCode(() -> converter.convert(badExpiresAt)).isInstanceOf(IllegalStateException.class);
		Map<String, Object> badNotBefore = Collections.singletonMap(JwtClaimNames.NBF, "badly-formed-nbf");
		assertThatCode(() -> converter.convert(badNotBefore)).isInstanceOf(IllegalStateException.class);
	}

	// gh-6073
	@Test
	public void convertWhenIssuerIsNotAUriThenConvertsToString() {
		MappedJwtClaimSetConverter converter = MappedJwtClaimSetConverter.withDefaults(Collections.emptyMap());
		Map<String, Object> nonUriIssuer = Collections.singletonMap(JwtClaimNames.ISS, "issuer");
		Map<String, Object> target = converter.convert(nonUriIssuer);
		assertThat(target.get(JwtClaimNames.ISS)).isEqualTo("issuer");
	}

	// gh-6073
	@Test
	public void convertWhenIssuerIsOfTypeURLThenConvertsToString() throws Exception {
		MappedJwtClaimSetConverter converter = MappedJwtClaimSetConverter.withDefaults(Collections.emptyMap());
		Map<String, Object> issuer = Collections.singletonMap(JwtClaimNames.ISS, new URL("https://issuer"));
		Map<String, Object> target = converter.convert(issuer);
		assertThat(target.get(JwtClaimNames.ISS)).isEqualTo("https://issuer");
	}

	@Test
	public void constructWhenAnyParameterIsNullThenIllegalArgumentException() {
		assertThatCode(() -> new MappedJwtClaimSetConverter(null)).isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void withDefaultsWhenAnyParameterIsNullThenIllegalArgumentException() {
		assertThatCode(() -> MappedJwtClaimSetConverter.withDefaults(null))
				.isInstanceOf(IllegalArgumentException.class);
	}

}
