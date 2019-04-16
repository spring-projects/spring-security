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
package org.springframework.security.test.context.support;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.junit.Test;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.security.test.context.support.StringAttribute.StringListParser;

/**
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 * @since 5.2
 */
public class StringAttributeParserSupportTests {

	@StringAttribute(name = "a", value = "bidule", parser = SomeTypeParser.class)
	private static final class AProperty {
	}

	@StringAttribute(name = "b", value = "chose", parser = SomeTypeParser.class)
	private static final class BProperty {
	}

	@Test
	public void parsePropertiesWithDistinctNames() {
		final StringAttributeParserSupport helper = new StringAttributeParserSupport();
		final StringAttribute propertyAnnotationA =
				AnnotationUtils.findAnnotation(AProperty.class, StringAttribute.class);
		final StringAttribute propertyAnnotationB =
				AnnotationUtils.findAnnotation(BProperty.class, StringAttribute.class);

		final Map<String, Object> actual = helper.parse(propertyAnnotationA, propertyAnnotationB);
		assertThat(actual).hasSize(2);
		assertThat(actual.get("a")).isInstanceOf(String.class);
		assertThat(actual.get("b")).isInstanceOf(String.class);

	}

	@StringAttribute(name = "a", value = "bidule", parser = StringListParser.class)
	private static final class CProperty {
	}

	@StringAttribute(name = "a", value = "chose", parser = StringListParser.class)
	private static final class DProperty {
	}

	@SuppressWarnings("unchecked")
	@Test
	public void parsePropertiesWithSameNameAccumulatesValues() {
		final StringAttributeParserSupport helper = new StringAttributeParserSupport();
		final StringAttribute propertyAnnotationC =
				AnnotationUtils.findAnnotation(CProperty.class, StringAttribute.class);
		final StringAttribute propertyAnnotationD =
				AnnotationUtils.findAnnotation(DProperty.class, StringAttribute.class);

		final Map<String, Object> actual = helper.parse(propertyAnnotationC, propertyAnnotationD);
		assertThat(actual).hasSize(1);
		assertThat(actual.get("a")).isInstanceOf(List.class);
		assertThat((List<String>) actual.get("a")).hasSize(2);
		assertThat((List<String>) actual.get("a")).contains("bidule", "chose");

	}

	@StringAttribute(name = "instant-millis", value = "12345678", parser = InstantParser.class)
	private static final class EProperty {
	}

	@Test
	public void parsePropertiesUsesParseroverrides() {
		final StringAttributeParserSupport helper = new StringAttributeParserSupport();

		final StringAttribute propertyAnnotation =
				AnnotationUtils.findAnnotation(EProperty.class, StringAttribute.class);

		final Map<String, Object> actual = helper.parse(propertyAnnotation);
		assertThat(actual).hasSize(1);
		assertThat(actual.get("instant-millis")).isInstanceOf(Instant.class);
		assertThat((Instant) actual.get("instant-millis")).isEqualTo(Instant.ofEpochMilli(12345678L));

	}

	public static final class SomeTypeParser implements AttributeValueParser<String, String> {
		@Override
		public String parse(final String value) {
			return value;
		}
	}

	public static final class OtherTypeParser implements AttributeValueParser<String, Collection<String>> {
		@Override
		public Collection<String> parse(final String value) {
			return Collections.singletonList(value);
		}
	}

	/**
	 * custom Instant mapper designed to override default one
	 */
	public static final class InstantParser implements AttributeValueParser<String, Instant> {
		@Override
		public Instant parse(final String value) {
			return Instant.ofEpochMilli(Long.valueOf(value));
		}
	}
}
