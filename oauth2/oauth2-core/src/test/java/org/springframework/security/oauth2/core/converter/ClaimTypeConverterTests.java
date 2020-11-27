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

import java.net.URL;
import java.time.Instant;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.nimbusds.jose.shaded.json.JSONArray;
import com.nimbusds.jose.shaded.json.JSONObject;
import org.assertj.core.util.Lists;
import org.assertj.core.util.Maps;
import org.junit.Before;
import org.junit.Test;

import org.springframework.core.convert.TypeDescriptor;
import org.springframework.core.convert.converter.Converter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link ClaimTypeConverter}.
 *
 * @author Joe Grandja
 * @since 5.2
 */
public class ClaimTypeConverterTests {

	private static final String STRING_CLAIM = "string-claim";

	private static final String BOOLEAN_CLAIM = "boolean-claim";

	private static final String INSTANT_CLAIM = "instant-claim";

	private static final String URL_CLAIM = "url-claim";

	private static final String COLLECTION_STRING_CLAIM = "collection-string-claim";

	private static final String LIST_STRING_CLAIM = "list-string-claim";

	private static final String MAP_STRING_OBJECT_CLAIM = "map-string-object-claim";

	private static final String JSON_ARRAY_CLAIM = "json-array-claim";

	private static final String JSON_OBJECT_CLAIM = "json-object-claim";

	private ClaimTypeConverter claimTypeConverter;

	@Before
	@SuppressWarnings("unchecked")
	public void setup() {
		Converter<Object, ?> stringConverter = getConverter(TypeDescriptor.valueOf(String.class));
		Converter<Object, ?> booleanConverter = getConverter(TypeDescriptor.valueOf(Boolean.class));
		Converter<Object, ?> instantConverter = getConverter(TypeDescriptor.valueOf(Instant.class));
		Converter<Object, ?> urlConverter = getConverter(TypeDescriptor.valueOf(URL.class));
		Converter<Object, ?> collectionStringConverter = getConverter(
				TypeDescriptor.collection(Collection.class, TypeDescriptor.valueOf(String.class)));
		Converter<Object, ?> listStringConverter = getConverter(
				TypeDescriptor.collection(List.class, TypeDescriptor.valueOf(String.class)));
		Converter<Object, ?> mapStringObjectConverter = getConverter(TypeDescriptor.map(Map.class,
				TypeDescriptor.valueOf(String.class), TypeDescriptor.valueOf(Object.class)));
		Map<String, Converter<Object, ?>> claimTypeConverters = new HashMap<>();
		claimTypeConverters.put(STRING_CLAIM, stringConverter);
		claimTypeConverters.put(BOOLEAN_CLAIM, booleanConverter);
		claimTypeConverters.put(INSTANT_CLAIM, instantConverter);
		claimTypeConverters.put(URL_CLAIM, urlConverter);
		claimTypeConverters.put(COLLECTION_STRING_CLAIM, collectionStringConverter);
		claimTypeConverters.put(LIST_STRING_CLAIM, listStringConverter);
		claimTypeConverters.put(MAP_STRING_OBJECT_CLAIM, mapStringObjectConverter);
		this.claimTypeConverter = new ClaimTypeConverter(claimTypeConverters);
	}

	private static Converter<Object, ?> getConverter(TypeDescriptor targetDescriptor) {
		final TypeDescriptor sourceDescriptor = TypeDescriptor.valueOf(Object.class);
		return (source) -> ClaimConversionService.getSharedInstance().convert(source, sourceDescriptor,
				targetDescriptor);
	}

	@Test
	public void constructorWhenConvertersNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> new ClaimTypeConverter(null));
	}

	@Test
	public void constructorWhenConvertersHasNullConverterThenThrowIllegalArgumentException() {
		Map<String, Converter<Object, ?>> claimTypeConverters = new HashMap<>();
		claimTypeConverters.put("claim1", null);
		assertThatIllegalArgumentException().isThrownBy(() -> new ClaimTypeConverter(claimTypeConverters));
	}

	@Test
	public void convertWhenClaimsEmptyThenReturnSame() {
		Map<String, Object> claims = new HashMap<>();
		assertThat(this.claimTypeConverter.convert(claims)).isSameAs(claims);
	}

	@Test
	public void convertWhenAllClaimsRequireConversionThenConvertAll() throws Exception {
		Instant instant = Instant.now();
		URL url = new URL("https://localhost");
		List<Number> listNumber = Lists.list(1, 2, 3, 4);
		List<String> listString = Lists.list("1", "2", "3", "4");
		Map<Integer, Object> mapIntegerObject = new HashMap<>();
		mapIntegerObject.put(1, "value1");
		Map<String, Object> mapStringObject = new HashMap<>();
		mapStringObject.put("1", "value1");
		JSONArray jsonArray = new JSONArray();
		jsonArray.add("1");
		List<String> jsonArrayListString = Lists.list("1");
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("1", "value1");
		Map<String, Object> jsonObjectMap = Maps.newHashMap("1", "value1");
		Map<String, Object> claims = new HashMap<>();
		claims.put(STRING_CLAIM, Boolean.TRUE);
		claims.put(BOOLEAN_CLAIM, "true");
		claims.put(INSTANT_CLAIM, instant.toString());
		claims.put(URL_CLAIM, url.toExternalForm());
		claims.put(COLLECTION_STRING_CLAIM, listNumber);
		claims.put(LIST_STRING_CLAIM, listNumber);
		claims.put(MAP_STRING_OBJECT_CLAIM, mapIntegerObject);
		claims.put(JSON_ARRAY_CLAIM, jsonArray);
		claims.put(JSON_OBJECT_CLAIM, jsonObject);
		claims = this.claimTypeConverter.convert(claims);
		assertThat(claims.get(STRING_CLAIM)).isEqualTo("true");
		assertThat(claims.get(BOOLEAN_CLAIM)).isEqualTo(Boolean.TRUE);
		assertThat(claims.get(INSTANT_CLAIM)).isEqualTo(instant);
		assertThat(claims.get(URL_CLAIM)).isEqualTo(url);
		assertThat(claims.get(COLLECTION_STRING_CLAIM)).isEqualTo(listString);
		assertThat(claims.get(LIST_STRING_CLAIM)).isEqualTo(listString);
		assertThat(claims.get(MAP_STRING_OBJECT_CLAIM)).isEqualTo(mapStringObject);
		assertThat(claims.get(JSON_ARRAY_CLAIM)).isEqualTo(jsonArrayListString);
		assertThat(claims.get(JSON_OBJECT_CLAIM)).isEqualTo(jsonObjectMap);
	}

	@Test
	public void convertWhenNoClaimsRequireConversionThenConvertNone() throws Exception {
		String string = "value";
		Boolean bool = Boolean.TRUE;
		Instant instant = Instant.now();
		URL url = new URL("https://localhost");
		List<String> listString = Lists.list("1", "2", "3", "4");
		Map<String, Object> mapStringObject = new HashMap<>();
		mapStringObject.put("1", "value1");
		Map<String, Object> claims = new HashMap<>();
		claims.put(STRING_CLAIM, string);
		claims.put(BOOLEAN_CLAIM, bool);
		claims.put(INSTANT_CLAIM, instant);
		claims.put(URL_CLAIM, url);
		claims.put(COLLECTION_STRING_CLAIM, listString);
		claims.put(LIST_STRING_CLAIM, listString);
		claims.put(MAP_STRING_OBJECT_CLAIM, mapStringObject);
		claims = this.claimTypeConverter.convert(claims);
		assertThat(claims.get(STRING_CLAIM)).isSameAs(string);
		assertThat(claims.get(BOOLEAN_CLAIM)).isSameAs(bool);
		assertThat(claims.get(INSTANT_CLAIM)).isSameAs(instant);
		assertThat(claims.get(URL_CLAIM)).isSameAs(url);
		assertThat(claims.get(COLLECTION_STRING_CLAIM)).isNotSameAs(listString).isEqualTo(listString);
		assertThat(claims.get(LIST_STRING_CLAIM)).isNotSameAs(listString).isEqualTo(listString);
		assertThat(claims.get(MAP_STRING_OBJECT_CLAIM)).isNotSameAs(mapStringObject).isEqualTo(mapStringObject);
	}

	@Test
	public void convertWhenConverterNotAvailableThenDoesNotConvert() {
		Map<String, Object> claims = new HashMap<>();
		claims.put("claim1", "value1");
		claims = this.claimTypeConverter.convert(claims);
		assertThat(claims.get("claim1")).isSameAs("value1");
	}

}
