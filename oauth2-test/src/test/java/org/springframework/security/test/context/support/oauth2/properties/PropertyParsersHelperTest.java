/*
 * Copyright 2002-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.test.context.support.oauth2.properties;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.net.URL;
import java.time.Instant;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.Test;

public class PropertyParsersHelperTest {

	@Test
	public void helperWithDefaultParsers() {
		final PropertyParsersHelper actual = PropertyParsersHelper.withDefaultParsers(
				"org.springframework.security.test.context.support.oauth2.properties.PropertyParsersHelperTest$SomeTypePropertyParser",
				"org.springframework.security.test.context.support.oauth2.properties.PropertyParsersHelperTest$OtherTypePropertyParser");

		assertThat(actual.getParser(NoOpPropertyParser.class.getName()))
				.isInstanceOf(NoOpPropertyParser.class);
		assertThat(actual.getParser(BooleanPropertyParser.class.getName()))
				.isInstanceOf(BooleanPropertyParser.class);
		assertThat(actual.getParser(DoublePropertyParser.class.getName()))
				.isInstanceOf(DoublePropertyParser.class);
		assertThat(actual.getParser(InstantPropertyParser.class.getName()))
				.isInstanceOf(InstantPropertyParser.class);
		assertThat(actual.getParser(IntegerPropertyParser.class.getName()))
				.isInstanceOf(IntegerPropertyParser.class);
		assertThat(actual.getParser(LongPropertyParser.class.getName()))
				.isInstanceOf(LongPropertyParser.class);
		assertThat(actual.getParser(StringListPropertyParser.class.getName()))
				.isInstanceOf(StringListPropertyParser.class);
		assertThat(actual.getParser(StringSetPropertyParser.class.getName()))
				.isInstanceOf(StringSetPropertyParser.class);
		assertThat(actual.getParser(UrlPropertyParser.class.getName()))
				.isInstanceOf(UrlPropertyParser.class);
		assertThat(actual.getParser(SomeTypePropertyParser.class.getName()))
				.isInstanceOf(SomeTypePropertyParser.class);
		assertThat(actual.getParser(OtherTypePropertyParser.class.getName()))
				.isInstanceOf(OtherTypePropertyParser.class);
	}

	@Test
	public void helperWithoutDefaultParsers() {
		final PropertyParsersHelper actual = PropertyParsersHelper.withoutDefaultParsers(
				"org.springframework.security.test.context.support.oauth2.properties.PropertyParsersHelperTest$SomeTypePropertyParser",
				"org.springframework.security.test.context.support.oauth2.properties.PropertyParsersHelperTest$OtherTypePropertyParser");
		assertThat(actual.getParser(String.class.getName())).isNull();
		assertThat(actual.getParser(Boolean.class.getName())).isNull();
		assertThat(actual.getParser(Double.class.getName())).isNull();
		assertThat(actual.getParser(Instant.class.getName())).isNull();
		assertThat(actual.getParser(Integer.class.getName())).isNull();
		assertThat(actual.getParser(Long.class.getName())).isNull();
		assertThat(actual.getParser(List.class.getName())).isNull();
		assertThat(actual.getParser(Set.class.getName())).isNull();
		assertThat(actual.getParser(URL.class.getName())).isNull();
		assertThat(actual.getParser(SomeTypePropertyParser.class.getName()))
				.isInstanceOf(SomeTypePropertyParser.class);
		assertThat(actual.getParser(OtherTypePropertyParser.class.getName()))
				.isInstanceOf(OtherTypePropertyParser.class);
	}

	@Test
	public void parsePropertiesWithDistinctNames() {
		final PropertyParsersHelper helper = PropertyParsersHelper.withoutDefaultParsers(
				"org.springframework.security.test.context.support.oauth2.properties.PropertyParsersHelperTest$SomeTypePropertyParser");

		final Property propertyAnnotationA = mock(Property.class);
		when(propertyAnnotationA.name()).thenReturn("a");
		when(propertyAnnotationA.value()).thenReturn("bidule");
		when(propertyAnnotationA.parser())
				.thenReturn(SomeTypePropertyParser.class.getName());

		final Property propertyAnnotationB = mock(Property.class);
		when(propertyAnnotationB.name()).thenReturn("b");
		when(propertyAnnotationB.value()).thenReturn("chose");
		when(propertyAnnotationB.parser())
				.thenReturn(SomeTypePropertyParser.class.getName());

		final Map<String, Object> actual = helper.parse(propertyAnnotationA,
				propertyAnnotationB);
		assertThat(actual).hasSize(2);
		assertThat(actual.get("a")).isInstanceOf(String.class);
		assertThat(actual.get("b")).isInstanceOf(String.class);

	}

	@SuppressWarnings("unchecked")
	@Test
	public void parsePropertiesWithSameNameAccumulatesValues() {
		final PropertyParsersHelper helper = PropertyParsersHelper.withDefaultParsers();

		final Property propertyAnnotationA = mock(Property.class);
		when(propertyAnnotationA.name()).thenReturn("a");
		when(propertyAnnotationA.value()).thenReturn("bidule");
		when(propertyAnnotationA.parser())
				.thenReturn(StringListPropertyParser.class.getName());

		final Property propertyAnnotationB = mock(Property.class);
		when(propertyAnnotationB.name()).thenReturn("a");
		when(propertyAnnotationB.value()).thenReturn("chose");
		when(propertyAnnotationB.parser())
				.thenReturn(StringListPropertyParser.class.getName());

		final Map<String, Object> actual = helper.parse(propertyAnnotationA,
				propertyAnnotationB);
		assertThat(actual).hasSize(1);
		assertThat(actual.get("a")).isInstanceOf(List.class);
		assertThat((List<String>) actual.get("a")).hasSize(2);
		assertThat((List<String>) actual.get("a")).contains("bidule", "chose");

	}

	static final class SomeTypePropertyParser implements PropertyParser<String> {
		@Override
		public String parse(final String value) {
			return value;
		}
	}

	static final class OtherTypePropertyParser
			implements PropertyParser<Collection<String>> {
		@Override
		public Collection<String> parse(final String value) {
			return Collections.singletonList(value);
		}
	}
}
