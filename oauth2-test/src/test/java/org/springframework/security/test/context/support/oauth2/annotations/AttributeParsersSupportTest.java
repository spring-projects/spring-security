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
package org.springframework.security.test.context.support.oauth2.annotations;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.junit.Test;
import org.springframework.core.annotation.AnnotationUtils;

/**
 *
 * @author Jérôme Wacongne &lt;ch4mp@c4-soft.com&gt;
 * @since 5.2.0
 *
 */
public class AttributeParsersSupportTest {

	@Attribute(name = "a", value = "bidule", parserOverride = "SomeTypeParser")
	private static final class AProperty {
	}

	@Attribute(
			name = "b",
			value = "chose",
			parserOverride = "org.springframework.security.test.context.support.oauth2.annotations.AttributeParsersSupportTest$SomeTypeParser")
	private static final class BProperty {
	}

	@Test
	public void parsePropertiesWithDistinctNames() {
		final AttributeParsersSupport helper = AttributeParsersSupport.withoutDefaultParsers(
				"org.springframework.security.test.context.support.oauth2.annotations.AttributeParsersSupportTest$SomeTypeParser");
		final Attribute propertyAnnotationA = AnnotationUtils.findAnnotation(AProperty.class, Attribute.class);
		final Attribute propertyAnnotationB = AnnotationUtils.findAnnotation(BProperty.class, Attribute.class);

		final Map<String, Object> actual = helper.parse(propertyAnnotationA, propertyAnnotationB);
		assertThat(actual).hasSize(2);
		assertThat(actual.get("a")).isInstanceOf(String.class);
		assertThat(actual.get("b")).isInstanceOf(String.class);

	}

	@Attribute(name = "a", value = "bidule", parseTo = TargetType.STRING_LIST)
	private static final class CProperty {
	}

	@Attribute(name = "a", value = "chose", parseTo = TargetType.STRING_LIST)
	private static final class DProperty {
	}

	@SuppressWarnings("unchecked")
	@Test
	public void parsePropertiesWithSameNameAccumulatesValues() {
		final AttributeParsersSupport helper = AttributeParsersSupport.withDefaultParsers();
		final Attribute propertyAnnotationC = AnnotationUtils.findAnnotation(CProperty.class, Attribute.class);
		final Attribute propertyAnnotationD = AnnotationUtils.findAnnotation(DProperty.class, Attribute.class);

		final Map<String, Object> actual = helper.parse(propertyAnnotationC, propertyAnnotationD);
		assertThat(actual).hasSize(1);
		assertThat(actual.get("a")).isInstanceOf(List.class);
		assertThat((List<String>) actual.get("a")).hasSize(2);
		assertThat((List<String>) actual.get("a")).contains("bidule", "chose");

	}

	@Attribute(name = "instant-millis", value = "12345678", parserOverride = "InstantParser")
	private static final class EProperty {
	}

	@Test
	public void parsePropertiesUsesParseroverrides() {
		final AttributeParsersSupport helper = AttributeParsersSupport.withDefaultParsers(
				"org.springframework.security.test.context.support.oauth2.annotations.AttributeParsersSupportTest$InstantParser");

		final Attribute propertyAnnotation = AnnotationUtils.findAnnotation(EProperty.class, Attribute.class);

		final Map<String, Object> actual = helper.parse(propertyAnnotation);
		assertThat(actual).hasSize(1);
		assertThat(actual.get("instant-millis")).isInstanceOf(Instant.class);
		assertThat((Instant) actual.get("instant-millis")).isEqualTo(Instant.ofEpochMilli(12345678L));

	}

	public static final class SomeTypeParser implements AttributeValueParser<String> {
		@Override
		public String parse(final String value) {
			return value;
		}
	}

	public static final class OtherTypeParser implements AttributeValueParser<Collection<String>> {
		@Override
		public Collection<String> parse(final String value) {
			return Collections.singletonList(value);
		}
	}

	/**
	 * custom Instant mapper designed to override default one
	 */
	public static final class InstantParser implements AttributeValueParser<Instant> {
		@Override
		public Instant parse(final String value) {
			return Instant.ofEpochMilli(Long.valueOf(value));
		}
	}
}
