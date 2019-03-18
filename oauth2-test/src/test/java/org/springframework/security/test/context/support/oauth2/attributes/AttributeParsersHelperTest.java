/*
 * Copyright 2002-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.springframework.security.test.context.support.oauth2.attributes;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.junit.Test;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.security.test.context.support.oauth2.attributes.Attribute;
import org.springframework.security.test.context.support.oauth2.attributes.AttributeParsersHelper;
import org.springframework.security.test.context.support.oauth2.attributes.BooleanStringParser;
import org.springframework.security.test.context.support.oauth2.attributes.DoubleStringParser;
import org.springframework.security.test.context.support.oauth2.attributes.IntegerStringParser;
import org.springframework.security.test.context.support.oauth2.attributes.LongStringParser;
import org.springframework.security.test.context.support.oauth2.attributes.NoOpStringParser;
import org.springframework.security.test.context.support.oauth2.attributes.Parser;
import org.springframework.security.test.context.support.oauth2.attributes.StringListStringParser;
import org.springframework.security.test.context.support.oauth2.attributes.StringSetStringParser;
import org.springframework.security.test.context.support.oauth2.attributes.UrlStringParser;

public class AttributeParsersHelperTest {

	@Test
	public void helperWithDefaultParsers() {
		final AttributeParsersHelper actual = AttributeParsersHelper.withDefaultParsers(
				"org.springframework.security.test.context.support.oauth2.attributes.AttributeParsersHelperTest$SomeTypeParser",
				"org.springframework.security.test.context.support.oauth2.attributes.AttributeParsersHelperTest$OtherTypeParser");

		assertThat(actual.getParser(NoOpStringParser.class.getName())).isInstanceOf(NoOpStringParser.class);
		assertThat(actual.getParser("NoOpStringParser")).isInstanceOf(NoOpStringParser.class);
		assertThat(actual.getParser(BooleanStringParser.class.getName())).isInstanceOf(BooleanStringParser.class);
		assertThat(actual.getParser("BooleanStringParser")).isInstanceOf(BooleanStringParser.class);
		assertThat(actual.getParser(DoubleStringParser.class.getName())).isInstanceOf(DoubleStringParser.class);
		assertThat(actual.getParser("DoubleStringParser")).isInstanceOf(DoubleStringParser.class);
		assertThat(
				actual.getParser(
						org.springframework.security.test.context.support.oauth2.attributes.InstantStringParser.class
								.getName())).isInstanceOf(
										org.springframework.security.test.context.support.oauth2.attributes.InstantStringParser.class);
		assertThat(actual.getParser("InstantStringParser")).isInstanceOf(
				org.springframework.security.test.context.support.oauth2.attributes.InstantStringParser.class);
		assertThat(actual.getParser(IntegerStringParser.class.getName())).isInstanceOf(IntegerStringParser.class);
		assertThat(actual.getParser("IntegerStringParser")).isInstanceOf(IntegerStringParser.class);
		assertThat(actual.getParser(LongStringParser.class.getName())).isInstanceOf(LongStringParser.class);
		assertThat(actual.getParser("LongStringParser")).isInstanceOf(LongStringParser.class);
		assertThat(actual.getParser(StringListStringParser.class.getName())).isInstanceOf(StringListStringParser.class);
		assertThat(actual.getParser("StringListStringParser")).isInstanceOf(StringListStringParser.class);
		assertThat(actual.getParser(StringSetStringParser.class.getName())).isInstanceOf(StringSetStringParser.class);
		assertThat(actual.getParser("StringSetStringParser")).isInstanceOf(StringSetStringParser.class);
		assertThat(actual.getParser(UrlStringParser.class.getName())).isInstanceOf(UrlStringParser.class);
		assertThat(actual.getParser("UrlStringParser")).isInstanceOf(UrlStringParser.class);
		assertThat(actual.getParser(SomeTypeParser.class.getName())).isInstanceOf(SomeTypeParser.class);
		assertThat(actual.getParser("SomeTypeParser")).isInstanceOf(SomeTypeParser.class);
		assertThat(actual.getParser(OtherTypeParser.class.getName())).isInstanceOf(OtherTypeParser.class);
		assertThat(actual.getParser("OtherTypeParser")).isInstanceOf(OtherTypeParser.class);
	}

	@Test
	public void helperWithoutDefaultParsers() {
		final AttributeParsersHelper actual = AttributeParsersHelper.withoutDefaultParsers(
				"org.springframework.security.test.context.support.oauth2.attributes.AttributeParsersHelperTest$SomeTypeParser",
				"org.springframework.security.test.context.support.oauth2.attributes.AttributeParsersHelperTest$OtherTypeParser");
		assertThat(actual.getParser(NoOpStringParser.class.getName())).isNull();
		assertThat(actual.getParser("NoOpStringParser")).isNull();
		assertThat(actual.getParser(BooleanStringParser.class.getName())).isNull();
		assertThat(actual.getParser("BooleanStringParser")).isNull();
		assertThat(actual.getParser(DoubleStringParser.class.getName())).isNull();
		assertThat(actual.getParser("DoubleStringParser")).isNull();
		assertThat(actual.getParser(InstantStringParser.class.getName())).isNull();
		assertThat(actual.getParser("InstantStringParser")).isNull();
		assertThat(actual.getParser(IntegerStringParser.class.getName())).isNull();
		assertThat(actual.getParser("IntegerStringParser")).isNull();
		assertThat(actual.getParser(LongStringParser.class.getName())).isNull();
		assertThat(actual.getParser("LongStringParser")).isNull();
		assertThat(actual.getParser(StringListStringParser.class.getName())).isNull();
		assertThat(actual.getParser("StringListStringParser")).isNull();
		assertThat(actual.getParser(StringSetStringParser.class.getName())).isNull();
		assertThat(actual.getParser("StringSetStringParser")).isNull();
		assertThat(actual.getParser(UrlStringParser.class.getName())).isNull();
		assertThat(actual.getParser("UrlStringParser")).isNull();
		assertThat(actual.getParser(SomeTypeParser.class.getName())).isInstanceOf(SomeTypeParser.class);
		assertThat(actual.getParser("SomeTypeParser")).isInstanceOf(SomeTypeParser.class);
		assertThat(actual.getParser(OtherTypeParser.class.getName())).isInstanceOf(OtherTypeParser.class);
		assertThat(actual.getParser("OtherTypeParser")).isInstanceOf(OtherTypeParser.class);
	}

	@Attribute(name = "a", value = "bidule", parser = "SomeTypeParser")
	private static final class AProperty {
	}

	@Attribute(
			name = "b",
			value = "chose",
			parser = "org.springframework.security.test.context.support.oauth2.attributes.AttributeParsersHelperTest$SomeTypeParser")
	private static final class BProperty {
	}

	@Test
	public void parsePropertiesWithDistinctNames() {
		final AttributeParsersHelper helper = AttributeParsersHelper.withoutDefaultParsers(
				"org.springframework.security.test.context.support.oauth2.attributes.AttributeParsersHelperTest$SomeTypeParser");
		final Attribute propertyAnnotationA = AnnotationUtils.findAnnotation(AProperty.class, Attribute.class);
		final Attribute propertyAnnotationB = AnnotationUtils.findAnnotation(BProperty.class, Attribute.class);

		final Map<String, Object> actual = helper.parse(propertyAnnotationA, propertyAnnotationB);
		assertThat(actual).hasSize(2);
		assertThat(actual.get("a")).isInstanceOf(String.class);
		assertThat(actual.get("b")).isInstanceOf(String.class);

	}

	@Attribute(name = "a", value = "bidule", parser = "StringListStringParser")
	private static final class CProperty {
	}

	@Attribute(name = "a", value = "chose", parser = "StringListStringParser")
	private static final class DProperty {
	}

	@SuppressWarnings("unchecked")
	@Test
	public void parsePropertiesWithSameNameAccumulatesValues() {
		final AttributeParsersHelper helper = AttributeParsersHelper.withDefaultParsers();
		final Attribute propertyAnnotationC = AnnotationUtils.findAnnotation(CProperty.class, Attribute.class);
		final Attribute propertyAnnotationD = AnnotationUtils.findAnnotation(DProperty.class, Attribute.class);

		final Map<String, Object> actual = helper.parse(propertyAnnotationC, propertyAnnotationD);
		assertThat(actual).hasSize(1);
		assertThat(actual.get("a")).isInstanceOf(List.class);
		assertThat((List<String>) actual.get("a")).hasSize(2);
		assertThat((List<String>) actual.get("a")).contains("bidule", "chose");

	}

	@Attribute(name = "instant-millis", value = "12345678", parser = "InstantStringParser")
	private static final class EProperty {
	}

	@Test
	public void parsePropertiesUsesParseroverrides() {
		final AttributeParsersHelper helper = AttributeParsersHelper.withDefaultParsers(
				"org.springframework.security.test.context.support.oauth2.attributes.AttributeParsersHelperTest$InstantStringParser");

		final Attribute propertyAnnotation = AnnotationUtils.findAnnotation(EProperty.class, Attribute.class);

		final Map<String, Object> actual = helper.parse(propertyAnnotation);
		assertThat(actual).hasSize(1);
		assertThat(actual.get("instant-millis")).isInstanceOf(Instant.class);
		assertThat((Instant) actual.get("instant-millis")).isEqualTo(Instant.ofEpochMilli(12345678L));

	}

	public static final class SomeTypeParser implements Parser<String, String> {
		@Override
		public String parse(final String value) {
			return value;
		}
	}

	public static final class OtherTypeParser implements Parser<String, Collection<String>> {
		@Override
		public Collection<String> parse(final String value) {
			return Collections.singletonList(value);
		}
	}

	/**
	 * custom Instant mapper designed to override default one
	 */
	public static final class InstantStringParser implements Parser<String, Instant> {
		@Override
		public Instant parse(final String value) {
			return Instant.ofEpochMilli(Long.valueOf(value));
		}
	}
}
