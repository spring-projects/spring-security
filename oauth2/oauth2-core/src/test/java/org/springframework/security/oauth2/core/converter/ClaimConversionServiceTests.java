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

import org.assertj.core.util.Lists;
import org.junit.Test;
import org.springframework.core.convert.ConversionService;

import java.net.URL;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link ClaimConversionService}.
 *
 * @author Joe Grandja
 * @since 5.2
 */
public class ClaimConversionServiceTests {
	private final ConversionService conversionService = ClaimConversionService.getSharedInstance();

	@Test
	public void convertStringWhenNullThenReturnNull() {
		assertThat(this.conversionService.convert(null, String.class)).isNull();
	}

	@Test
	public void convertStringWhenStringThenReturnSame() {
		assertThat(this.conversionService.convert("string", String.class)).isSameAs("string");
	}

	@Test
	public void convertStringWhenNumberThenConverts() {
		assertThat(this.conversionService.convert(1234, String.class)).isEqualTo("1234");
	}

	@Test
	public void convertBooleanWhenNullThenReturnNull() {
		assertThat(this.conversionService.convert(null, Boolean.class)).isNull();
	}

	@Test
	public void convertBooleanWhenBooleanThenReturnSame() {
		assertThat(this.conversionService.convert(Boolean.TRUE, Boolean.class)).isSameAs(Boolean.TRUE);
	}

	@Test
	public void convertBooleanWhenStringTrueThenConverts() {
		assertThat(this.conversionService.convert("true", Boolean.class)).isEqualTo(Boolean.TRUE);
	}

	@Test
	public void convertBooleanWhenNotConvertibleThenReturnBooleanFalse() {
		assertThat(this.conversionService.convert("not-convertible-boolean", Boolean.class)).isEqualTo(Boolean.FALSE);
	}

	@Test
	public void convertInstantWhenNullThenReturnNull() {
		assertThat(this.conversionService.convert(null, Instant.class)).isNull();
	}

	@Test
	public void convertInstantWhenInstantThenReturnSame() {
		Instant instant = Instant.now();
		assertThat(this.conversionService.convert(instant, Instant.class)).isSameAs(instant);
	}

	@Test
	public void convertInstantWhenDateThenConverts() {
		Instant instant = Instant.now();
		assertThat(this.conversionService.convert(Date.from(instant), Instant.class)).isEqualTo(instant);
	}

	@Test
	public void convertInstantWhenNumberThenConverts() {
		Instant instant = Instant.now();
		assertThat(this.conversionService.convert(instant.getEpochSecond(), Instant.class))
				.isEqualTo(instant.truncatedTo(ChronoUnit.SECONDS));
	}

	@Test
	public void convertInstantWhenStringThenConverts() {
		Instant instant = Instant.now();
		assertThat(this.conversionService.convert(String.valueOf(instant.getEpochSecond()), Instant.class))
				.isEqualTo(instant.truncatedTo(ChronoUnit.SECONDS));
		assertThat(this.conversionService.convert(String.valueOf(instant.toString()), Instant.class)).isEqualTo(instant);
	}

	@Test
	public void convertInstantWhenNotConvertibleThenReturnNull() {
		assertThat(this.conversionService.convert("not-convertible-instant", Instant.class)).isNull();
	}

	@Test
	public void convertUrlWhenNullThenReturnNull() {
		assertThat(this.conversionService.convert(null, URL.class)).isNull();
	}

	@Test
	public void convertUrlWhenUrlThenReturnSame() throws Exception {
		URL url = new URL("https://localhost");
		assertThat(this.conversionService.convert(url, URL.class)).isSameAs(url);
	}

	@Test
	public void convertUrlWhenStringThenConverts() throws Exception {
		String urlString = "https://localhost";
		URL url = new URL(urlString);
		assertThat(this.conversionService.convert(urlString, URL.class)).isEqualTo(url);
	}

	@Test
	public void convertUrlWhenNotConvertibleThenReturnNull() {
		assertThat(this.conversionService.convert("not-convertible-url", URL.class)).isNull();
	}

	@Test
	public void convertCollectionStringWhenNullThenReturnNull() {
		assertThat(this.conversionService.convert(null, Collection.class)).isNull();
	}

	@Test
	public void convertCollectionStringWhenListStringThenReturnSame() {
		List<String> list = Lists.list("1", "2", "3", "4");
		assertThat(this.conversionService.convert(list, Collection.class)).isSameAs(list);
	}

	@Test
	public void convertCollectionStringWhenListNumberThenConverts() {
		assertThat(this.conversionService.convert(Lists.list(1, 2, 3, 4), Collection.class))
				.isEqualTo(Lists.list("1", "2", "3", "4"));
	}

	@Test
	public void convertCollectionStringWhenNotConvertibleThenReturnSingletonList() {
		String string = "not-convertible-collection";
		assertThat(this.conversionService.convert(string, Collection.class))
				.isEqualTo(Collections.singletonList(string));
	}

	@Test
	public void convertListStringWhenNullThenReturnNull() {
		assertThat(this.conversionService.convert(null, List.class)).isNull();
	}

	@Test
	public void convertListStringWhenListStringThenReturnSame() {
		List<String> list = Lists.list("1", "2", "3", "4");
		assertThat(this.conversionService.convert(list, List.class)).isSameAs(list);
	}

	@Test
	public void convertListStringWhenListNumberThenConverts() {
		assertThat(this.conversionService.convert(Lists.list(1, 2, 3, 4), List.class))
				.isEqualTo(Lists.list("1", "2", "3", "4"));
	}

	@Test
	public void convertListStringWhenNotConvertibleThenReturnSingletonList() {
		String string = "not-convertible-list";
		assertThat(this.conversionService.convert(string, List.class))
				.isEqualTo(Collections.singletonList(string));
	}

	@Test
	public void convertMapStringObjectWhenNullThenReturnNull() {
		assertThat(this.conversionService.convert(null, Map.class)).isNull();
	}

	@Test
	public void convertMapStringObjectWhenMapStringObjectThenReturnSame() {
		Map<String, Object> mapStringObject = new HashMap<String, Object>() {
			{
				put("key1", "value1");
				put("key2", "value2");
				put("key3", "value3");
			}
		};
		assertThat(this.conversionService.convert(mapStringObject, Map.class)).isSameAs(mapStringObject);
	}

	@Test
	public void convertMapStringObjectWhenMapIntegerObjectThenConverts() {
		Map<String, Object> mapStringObject = new HashMap<String, Object>() {
			{
				put("1", "value1");
				put("2", "value2");
				put("3", "value3");
			}
		};
		Map<Integer, Object> mapIntegerObject = new HashMap<Integer, Object>() {
			{
				put(1, "value1");
				put(2, "value2");
				put(3, "value3");
			}
		};
		assertThat(this.conversionService.convert(mapIntegerObject, Map.class)).isEqualTo(mapStringObject);
	}

	@Test
	public void convertMapStringObjectWhenNotConvertibleThenReturnNull() {
		List<String> notConvertibleList = Lists.list("1", "2", "3", "4");
		assertThat(this.conversionService.convert(notConvertibleList, Map.class)).isNull();
	}
}
