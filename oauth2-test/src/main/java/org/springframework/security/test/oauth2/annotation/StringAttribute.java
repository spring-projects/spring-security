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
package org.springframework.security.test.oauth2.annotation;

import static org.springframework.util.StringUtils.isEmpty;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.net.MalformedURLException;
import java.net.URL;
import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.util.StringUtils;

/**
 * <p>
 * Annotation to create an entry in a {@link java.util.Map Map&lt;String, Object&gt;} such
 * as {@link org.springframework.security.oauth2.jwt.Jwt JWT} headers or claims.
 * </p>
 * You might implement your own, bust most frequently used {@link AttributeValueParser}
 * are provided out of the box:
 * <ul>
 * <li>{@link BooleanParser}</li>
 * <li>{@link DoubleParser}</li>
 * <li>{@link FloatParser}</li>
 * <li>{@link InstantParser}</li>
 * <li>{@link IntegerParser}</li>
 * <li>{@link LongParser}</li>
 * <li>{@link NoOpParser}</li>
 * <li>{@link SpacedSeparatedStringsParser}</li>
 * <li>{@link StringListParser}</li>
 * <li>{@link StringSetParser}</li>
 * <li>{@link UrlParser}</li>
 * </ul>
 *
 * Sample usage:<br>
 *
 * <pre>
 * &#64;WithMockJwt(
 *   claims = {
 *     &#64;StringAttribute(name = JwtClaimNames.AUD, value = "first audience", parser = StringListParser.class),
 *     &#64;StringAttribute(name = JwtClaimNames.AUD, value = "second audience", parser = StringListParser.class),
 *     &#64;StringAttribute(name = JwtClaimNames.ISS, value = "https://test-issuer.org", parseTo = UrlParser.class),
 *     &#64;StringAttribute(name = "machin", value = "chose"),
 *     &#64;StringAttribute(name = "truc", value = "bidule", parser = YourFancyParserImpl.class)})
 * </pre>
 *
 * This would create
 * <ul>
 * <li>an {@code audience} claim with a value being a {@code List<String>} with two
 * entries</li>
 * <li>an {@code issuer} claim with a value being a {@code java.net.URL} instance</li>
 * <li>a {@code machin} claim with {@code chose} String as value (default parser is
 * {@code NoOpParser})</li>
 * <li>a {@code truc} claim whith an instance of what {@code YourFancyParserImpl} is
 * designed to build from {@code bidule} string</li>
 * </ul>
 *
 * @author Jérôme Wacongne &lt;ch4mp@c4-soft.com&gt;
 * @since 5.2.0
 *
 */
@Target({ ElementType.METHOD, ElementType.TYPE })
@Retention(RetentionPolicy.RUNTIME)
public @interface StringAttribute {

	/**
	 * @return the key in the {@link java.util.Map Map&lt;String, Object&gt;}
	 */
	String name();

	/**
	 * @return a value to be transformed using "parser" before being put as value in
	 * {@link java.util.Map Map&lt;String, Object&gt;}
	 */
	String value();

	/**
	 * @return an {@link AttributeValueParser} instance to deserialize {@link #value()}
	 * (turn it into an Object)
	 */
	Class<? extends AttributeValueParser<String, ?>> parser() default NoOpParser.class;

	public class BooleanParser implements AttributeValueParser<String, Boolean> {
		@Override
		public Boolean parse(final String value) {
			return Boolean.valueOf(value);
		}
	}

	public class DoubleParser implements AttributeValueParser<String, Double> {
		@Override
		public Double parse(final String value) {
			return isEmpty(value) ? null : Double.valueOf(value);
		}
	}

	public class FloatParser implements AttributeValueParser<String, Float> {
		@Override
		public Float parse(final String value) {
			return isEmpty(value) ? null : Float.valueOf(value);
		}
	}

	public class InstantParser implements AttributeValueParser<String, Instant> {
		@Override
		public Instant parse(final String value) {
			return isEmpty(value) ? null : Instant.parse(value);
		}
	}

	public class IntegerParser implements AttributeValueParser<String, Integer> {
		@Override
		public Integer parse(final String value) {
			return isEmpty(value) ? null : Integer.valueOf(value);
		}
	}

	public class LongParser implements AttributeValueParser<String, Long> {
		@Override
		public Long parse(final String value) {
			return isEmpty(value) ? null : Long.valueOf(value);
		}

	}

	public class NoOpParser implements AttributeValueParser<String, String> {
		@Override
		public String parse(final String value) {
			return StringUtils.isEmpty(value) ? null : value;
		}
	}

	public class SpacedSeparatedStringsParser implements AttributeValueParser<String, Set<String>> {
		@Override
		public Set<String> parse(final String value) {
			return StringUtils.isEmpty(value) ? null : Stream.of(value.split(" ")).collect(Collectors.toSet());
		}
	}

	public class StringListParser implements AttributeValueParser<String, List<String>> {
		@Override
		public List<String> parse(final String value) {
			return StringUtils.isEmpty(value) ? null : Collections.singletonList(value);
		}
	}

	public class StringSetParser implements AttributeValueParser<String, Set<String>> {
		@Override
		public Set<String> parse(final String value) {
			return StringUtils.isEmpty(value) ? null : Collections.singleton(value);
		}
	}

	public class UrlParser implements AttributeValueParser<String, URL> {
		@Override
		public URL parse(final String value) {
			try {
				return StringUtils.isEmpty(value) ? null : new URL(value);
			} catch (final MalformedURLException e) {
				throw new RuntimeException(e);
			}
		}
	}

}
